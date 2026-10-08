package resolver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/ApostolDmitry/vpner/internal/logx"
)

type Service struct {
	mu       sync.Mutex
	cfg      conf.ServerConfig
	syncer   IPSyncer
	upstream *Upstream
	server   *Server
	cancel   context.CancelFunc
	done     chan struct{}
	running  bool
}

func NewService(cfg conf.ServerConfig, syncer IPSyncer, upstream *Upstream) *Service {
	return &Service{cfg: cfg, syncer: syncer, upstream: upstream}
}

func (d *Service) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.done = make(chan struct{})
	d.server = NewServer(d.cfg, d.syncer, d.upstream)

	started := make(chan struct{})
	errCh := make(chan error, 1)
	d.server.SetNotifyStartedFunc(func() {
		select {
		case <-started:
		default:
			close(started)
		}
	})

	go func() {
		defer close(d.done)
		if err := d.server.Run(ctx); err != nil {
			logx.Errorf("DNS server exited: %v", err)
			select {
			case errCh <- err:
			default:
			}
		}
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	select {
	case err := <-errCh:
		cancel()
		d.cancel = nil
		return fmt.Errorf("dns server failed to start: %w", err)
	case <-started:
		d.running = true
		logx.Infof("DNS server listening on :%d", d.cfg.Port)
	case <-time.After(2 * time.Second):
		d.running = true
		logx.Warnf("DNS server start confirmation timeout; assuming running on :%d", d.cfg.Port)
	}
	return nil
}

func (d *Service) Stop() {
	d.mu.Lock()
	done := d.done
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
		logx.Infof("DNS server shutdown requested")
	}
	d.running = false
	d.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logx.Warnf("DNS server shutdown timed out after 5s")
		}
	}
}

func (d *Service) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func (d *Service) UpstreamStats() []ServerStat {
	if d.upstream == nil {
		return nil
	}
	return d.upstream.ServerStats()
}

func (d *Service) QueryStats() QueryStats {
	d.mu.Lock()
	srv := d.server
	d.mu.Unlock()
	if srv == nil {
		return QueryStats{}
	}
	return srv.Stats()
}
