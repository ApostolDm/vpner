package proxysvc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
	proxy "github.com/ApostolDmitry/vpner/internal/proxy"
)

type procEntry struct {
	cancel    context.CancelFunc
	startedAt time.Time
	restarts  int
	lastExit  string
}

type Service struct {
	mu      sync.Mutex
	manager *proxy.Manager
	process map[string]*procEntry

	start func(context.Context, string) error

	startGrace  time.Duration
	baseBackoff time.Duration
	maxBackoff  time.Duration
	healthyRun  time.Duration
}

func New(x *proxy.Manager) *Service {
	return &Service{
		manager:     x,
		process:     make(map[string]*procEntry),
		start:       x.Start,
		startGrace:  3 * time.Second,
		baseBackoff: 1 * time.Second,
		maxBackoff:  60 * time.Second,
		healthyRun:  30 * time.Second,
	}
}

func (x *Service) StartAuto() error {
	return x.startChains(x.manager.ListAuto)
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
	entry, ok := x.process[chainName]
	if !ok {
		return fmt.Errorf("%s not running", chainName)
	}
	entry.cancel()
	delete(x.process, chainName)
	logx.Infof("Xray stopped: %s", chainName)
	return nil
}

func (x *Service) StopAll() {
	x.mu.Lock()
	defer x.mu.Unlock()

	for name, entry := range x.process {
		entry.cancel()
		logx.Infof("Xray stopped: %s", name)
	}
	x.process = make(map[string]*procEntry)
}

func (x *Service) startLocked(name string) error {
	ctx, cancel := context.WithCancel(context.Background())
	entry := &procEntry{cancel: cancel, startedAt: time.Now()}
	x.process[name] = entry
	errCh := make(chan error, 1)

	go x.supervise(ctx, name, entry, errCh)

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("xray exited (%s): %w", name, err)
		}
		logx.Infof("Xray (%s) exited normally", name)
	case <-time.After(x.startGrace):
		logx.Infof("Xray (%s) started successfully", name)
	}
	return nil
}

func (x *Service) supervise(ctx context.Context, name string, entry *procEntry, errCh chan error) {
	backoff := x.baseBackoff
	first := true
	for {
		runStart := time.Now()
		err := x.start(ctx, name)
		ran := time.Since(runStart)

		if first {
			first = false
			select {
			case errCh <- err:
			default:
			}
			if err != nil && ran < x.startGrace {
				x.forget(name, entry)
				return
			}
		}
		if ctx.Err() != nil {
			return
		}

		x.mu.Lock()
		entry.restarts++
		entry.lastExit = exitText(err)
		if ran >= x.healthyRun {
			backoff = x.baseBackoff
		}
		restarts := entry.restarts
		x.mu.Unlock()

		logx.Warnf("Xray (%s) exited after %s (%v); restart #%d in %s",
			name, ran.Round(time.Second), err, restarts, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		x.mu.Lock()
		entry.startedAt = time.Now()
		x.mu.Unlock()
		if backoff *= 2; backoff > x.maxBackoff {
			backoff = x.maxBackoff
		}
	}
}

func (x *Service) forget(name string, entry *procEntry) {
	x.mu.Lock()
	if x.process[name] == entry {
		delete(x.process, name)
	}
	x.mu.Unlock()
}

func exitText(err error) string {
	if err == nil {
		return "exited cleanly"
	}
	return err.Error()
}

func (x *Service) IsRunning(name string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.checkRunning(name)
}

type ChainRuntime struct {
	Running  bool
	Restarts int
	LastExit string
	Uptime   time.Duration
}

func (x *Service) Runtimes() map[string]ChainRuntime {
	x.mu.Lock()
	defer x.mu.Unlock()
	now := time.Now()
	out := make(map[string]ChainRuntime, len(x.process))
	for name, e := range x.process {
		out[name] = ChainRuntime{
			Running:  true,
			Restarts: e.restarts,
			LastExit: e.lastExit,
			Uptime:   now.Sub(e.startedAt),
		}
	}
	return out
}

func (x *Service) ListInfo() (map[string]proxy.ChainInfo, error) {
	return x.manager.Infos()
}

func (x *Service) GetInfo(name string) (proxy.ChainInfo, error) {
	return x.manager.Get(name)
}

func (x *Service) Create(link string, autoRun bool) (string, error) {
	return x.manager.Create(link, autoRun)
}

func (x *Service) Update(name, link string) error {
	return x.manager.Update(name, link)
}

func (x *Service) Delete(name string) error {
	return x.manager.Delete(name)
}

func (x *Service) SetAutorun(name string, autoRun bool) error {
	return x.manager.SetAutoRun(name, autoRun)
}

func (x *Service) IsChain(name string) bool {
	return x.manager.IsChain(name)
}

func (x *Service) Test(name string) (string, error) {
	return x.manager.Test(name)
}

func (x *Service) checkRunning(name string) bool {
	_, ok := x.process[name]
	return ok
}
