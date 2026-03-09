package dnsservice

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/dns"
	"github.com/ApostolDmitry/vpner/internal/doh"
	"github.com/ApostolDmitry/vpner/internal/logging"
	"github.com/ApostolDmitry/vpner/internal/network"
	unblockservice "github.com/ApostolDmitry/vpner/internal/service/unblockservice"
)

type Service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	done    chan struct{} // closed when server goroutine exits
	mu      sync.Mutex

	server    *dns.DNSServer
	cfg       dns.ServerConfig
	ipManager *network.IpRuleManager
	resolver  *doh.Resolver
}

func New(cfg dns.ServerConfig, unblock *unblockservice.Service, resolver *doh.Resolver, registry *network.IPSetRegistry) *Service {
	var ipManager *network.IpRuleManager
	if unblock != nil {
		ipManager = network.NewIpRuleManager(unblock, unblock.RuntimeOptions(), resolver, registry)
	}

	return &Service{
		cfg:       cfg,
		ipManager: ipManager,
		resolver:  resolver,
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
	d.done = make(chan struct{})
	d.server = dns.NewDNSServer(d.cfg, d.ipManager, d.resolver)
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
	done := d.done
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
		logging.Infof("DNS server shutdown requested")
	}
	d.running = false
	d.mu.Unlock()

	// Wait for the server goroutine to fully exit so the port is released.
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logging.Warnf("DNS server shutdown timed out after 5s")
		}
	}
}

func (d *Service) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}
