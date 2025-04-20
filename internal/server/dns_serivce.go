package server

import (
	"context"
	"log"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/network"
)

type DNSService struct {
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	mu      sync.Mutex

	server   *dnsserver.DNSServer
	cfg      dnsserver.ServerConfig
	unblock  *network.UnblockManager
	resolver *dohclient.Resolver
}

func NewDNSService(cfg dnsserver.ServerConfig, um *network.UnblockManager, resolver *dohclient.Resolver) *DNSService {
	return &DNSService{
		cfg:      cfg,
		unblock:  um,
		resolver: resolver,
	}
}

func (d *DNSService) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.server = dnsserver.NewDNSServer(d.cfg, d.unblock, d.resolver)
	d.running = true

	go func() {
		if err := d.server.Run(d.ctx); err != nil {
			log.Printf("DNS server exited: %v", err)
		}
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	return nil
}

func (d *DNSService) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	d.running = false
}

func (d *DNSService) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}
