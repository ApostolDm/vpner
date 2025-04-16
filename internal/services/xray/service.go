package xrayservice

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/network"
)

type Service struct {
	mu      sync.Mutex
	manager *network.XrayManager
	process map[string]context.CancelFunc
}

func New(x *network.XrayManager) *Service {
	return &Service{
		manager: x,
		process: make(map[string]context.CancelFunc),
	}
}

func (x *Service) StartAll() error {
	return x.startChains(x.manager.ListXray)
}

func (x *Service) StartAuto() error {
	return x.startChains(x.manager.ListAutoRun)
}

func (x *Service) startChains(listFn func() ([]string, error)) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	list, err := listFn()
	if err != nil {
		return err
	}

	var errs []error
	for _, chain := range list {
		if x.checkRunning(chain) {
			continue
		}
		if err := x.startLocked(chain); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", chain, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (x *Service) StartOne(chainName string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.checkRunning(chainName) {
		return fmt.Errorf("xray: chain %s already started", chainName)
	}
	return x.startLocked(chainName)
}

func (x *Service) StopOne(chainName string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	cancel, ok := x.process[chainName]
	if !ok {
		return fmt.Errorf("%s not running", chainName)
	}
	cancel()
	delete(x.process, chainName)
	logging.Infof("Xray stopped: %s", chainName)
	return nil
}

func (x *Service) StopAll() {
	x.mu.Lock()
	defer x.mu.Unlock()

	for name, cancel := range x.process {
		cancel()
		logging.Infof("Xray stopped: %s", name)
	}
	x.process = make(map[string]context.CancelFunc)
}

func (x *Service) startLocked(name string) error {
	ctx, cancel := context.WithCancel(context.Background())

	x.process[name] = cancel
	errCh := make(chan error, 1)

	go func() {
		errCh <- x.manager.StartXray(ctx, name)
		x.mu.Lock()
		delete(x.process, name)
		x.mu.Unlock()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("xray exited (%s): %w", name, err)
		}
		logging.Infof("Xray (%s) exited normally", name)
	case <-time.After(3 * time.Second):
		logging.Infof("Xray (%s) started successfully", name)
	}
	return nil
}

func (x *Service) IsRunning(name string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.checkRunning(name)
}

func (x *Service) checkRunning(name string) bool {
	_, ok := x.process[name]
	return ok
}
