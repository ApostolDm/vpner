package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/network"
)

type XrayService struct {
	mu      sync.Mutex
	manager *network.XrayManager
	process map[string]context.CancelFunc
}

func NewXrayService(x *network.XrayManager) *XrayService {
	return &XrayService{
		manager: x,
		process: make(map[string]context.CancelFunc),
	}
}

func (x *XrayService) StartAll() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	list, err := x.manager.ListXray()
	if err != nil {
		return err
	}
	for _, chain_name := range list {
		if x.checkRunning(chain_name){
			continue
		}
		if err := x.start(chain_name); err != nil {
			log.Printf("xray: failed to start %s: %v", chain_name, err)
		}
	}
	return nil
}

func (x *XrayService) StartOne(chain_name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.checkRunning(chain_name){
		return fmt.Errorf("xray: chain %s already started", chain_name)
	}
	if err := x.start(chain_name); err != nil {
		log.Printf("xray: failed to start %s: %v", chain_name, err)
	}
	return nil
}

func (x *XrayService) StopOne(chain_name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	cancel, ok := x.process[chain_name]
	if ok {
		cancel()
		delete(x.process, chain_name)
		log.Printf("stopped: %s", chain_name)

	} else {
		return fmt.Errorf("%s not running", chain_name)
	}
	return nil
}

func (x *XrayService) StopAll() {
	x.mu.Lock()
	defer x.mu.Unlock()

	for name, cancel := range x.process {
		cancel()
		log.Printf("stopped: %s", name)
	}
	x.process = make(map[string]context.CancelFunc)
}

func (x *XrayService) start(name string) error {
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
			return fmt.Errorf("xray exited (%s): %v", name, err)
		} else {
			log.Printf("xray (%s) exited normally", name)
		}
	case <-time.After(3 * time.Second):
		log.Printf("xray (%s) started successfully", name)
	}
	return nil
}

func (x *XrayService) IsRunning(name string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.checkRunning(name)
}

func (x *XrayService) checkRunning(name string) bool {
	_, ok := x.process[name]
	return ok
}