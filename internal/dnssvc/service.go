package dnssvc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	unblock "github.com/ApostolDmitry/vpner/internal/unblock"
)

type Service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	done    chan struct{}
	mu      sync.Mutex

	server    *resolver.Server
	cfg       resolver.ServerConfig
	ipManager *firewall.IpRuleManager
	resolver  *resolver.Upstream
}

func New(cfg resolver.ServerConfig, unblock *unblock.Service, resolver *resolver.Upstream, registry *firewall.IPSetRegistry) *Service {
	var ipManager *firewall.IpRuleManager
	if unblock != nil {
		ipManager = firewall.NewIpRuleManager(unblock, unblock.RuntimeOptions(), resolver, registry)
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
		logx.Debugf("DNS service already running")
		return nil
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.done = make(chan struct{})
	d.server = resolver.NewServer(d.cfg, d.ipManager, d.resolver)
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
		d.cancel()
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

func (d *Service) UpstreamStats() []resolver.ServerStat {
	if d.resolver == nil {
		return nil
	}
	return d.resolver.ServerStats()
}
