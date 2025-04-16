package dnsservice

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/network"
)

type Service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	mu      sync.Mutex

	server   *dnsserver.DNSServer
	cfg      dnsserver.ServerConfig
	unblock  *network.UnblockManager
	resolver *dohclient.Resolver
}

func New(cfg dnsserver.ServerConfig, um *network.UnblockManager, resolver *dohclient.Resolver) *Service {
	return &Service{
		cfg:      cfg,
		unblock:  um,
		resolver: resolver,
	}
}

func (d *Service) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		logging.Debugf("DNS service already running")
		return nil
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.server = dnsserver.NewDNSServer(d.cfg, d.unblock, d.resolver)
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
		if err := d.server.Run(d.ctx); err != nil {
			logging.Errorf("DNS server exited: %v", err)
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
		d.cancel()
		d.cancel = nil
		return fmt.Errorf("dns server failed to start: %w", err)
	case <-started:
		d.running = true
		logging.Infof("DNS server listening on :%d", d.cfg.Port)
	case <-time.After(2 * time.Second):
		d.running = true
		logging.Warnf("DNS server start confirmation timeout; assuming running on :%d", d.cfg.Port)
	}

	return nil
}

func (d *Service) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
		logging.Infof("DNS server shutdown requested")
	}
	d.running = false
}

func (d *Service) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}
