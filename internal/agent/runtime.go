package agent

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/logx"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	rpc "github.com/ApostolDmitry/vpner/internal/rpc"
	"golang.org/x/sync/errgroup"
)

const (
	defaultReconcileInterval = 45 * time.Second
	watchdogBaseThreshold    = 2
	watchdogMaxThreshold     = 32
)

type Runtime struct {
	cfg conf.FullConfig

	dnsService *resolver.Service
	xraySvc    *proxysvc.Service
	serverImpl *rpc.VpnerServer
	upstream   *resolver.Upstream
	keepalive  *firewall.KeepaliveSweeper

	grpcServers []*grpcInstance
	shutdown    sync.Once
}

func New(cfg conf.FullConfig) (*Runtime, error) {
	graph, err := buildRuntimeGraph(cfg)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		cfg:        cfg,
		dnsService: graph.dnsService,
		xraySvc:    graph.xraySvc,
		serverImpl: graph.grpcServer,
		upstream:   graph.upstream,
		keepalive:  graph.keepalive,
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if r.cfg.DNSServer.Running {
		logx.Infof("Auto-starting DNS server")
		if err := r.dnsService.Start(); err != nil {
			return fmt.Errorf("failed to start DNS server: %w", err)
		}
	}

	if err := r.xraySvc.StartAuto(); err != nil {
		logx.Errorf("Failed to autostart xray chains: %v", err)
	}
	r.serverImpl.RestoreMarkRouting("")
	r.serverImpl.RestoreXrayRouting(true, true, "")

	servers, err := r.buildGRPCServers()
	if err != nil {
		r.shutdownRuntime()
		return err
	}
	r.grpcServers = servers

	grp, _ := errgroup.WithContext(ctx)
	for _, inst := range r.grpcServers {
		grp.Go(inst.Serve)
	}

	go r.runWatchdog(ctx)
	if r.keepalive != nil {
		go r.runKeepalive(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- grp.Wait()
	}()

	select {
	case <-ctx.Done():
		logx.Warnf("Context cancelled, shutting down runtime")
		r.shutdownRuntime()
		if err := <-errCh; err != nil {
			logx.Debugf("gRPC listeners stopped with: %v", err)
		}
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			logx.Errorf("gRPC listener exited: %v", err)
		}
		r.shutdownRuntime()
		return err
	}
}

type backoff struct {
	misses    int
	threshold int
}

func newBackoff() *backoff {
	return &backoff{threshold: watchdogBaseThreshold}
}

func (b *backoff) reset() {
	b.misses, b.threshold = 0, watchdogBaseThreshold
}

func (b *backoff) due() bool {
	b.misses++
	if b.misses < b.threshold {
		return false
	}
	b.misses = 0
	if b.threshold < watchdogMaxThreshold {
		b.threshold *= 2
	}
	return true
}

func (r *Runtime) runWatchdog(ctx context.Context) {
	defer logx.Recover("routing watchdog")
	interval := defaultReconcileInterval
	switch n := r.cfg.Network.ReconcileInterval; {
	case n < 0:
		logx.Infof("routing watchdog disabled by config")
		return
	case n > 0:
		interval = time.Duration(n) * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	mark, xray := newBackoff(), newBackoff()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.serverImpl.MarkRoutingHealthy() {
				mark.reset()
			} else if mark.due() {
				logx.Warnf("routing watchdog: interface VPN routing incomplete; restoring")
				r.serverImpl.RestoreMarkRouting("")
			}

			if r.serverImpl.RoutingHealthy() {
				xray.reset()
			} else if xray.due() {
				logx.Warnf("routing watchdog: managed routing missing from kernel; reconciling")
				r.serverImpl.ReconcileRouting()
			}
		}
	}
}

func (r *Runtime) runKeepalive(ctx context.Context) {
	defer logx.Recover("ipset keepalive")
	ticker := time.NewTicker(r.keepalive.Interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !r.keepalive.SweepOnce() {
				return
			}
			debug.FreeOSMemory()
		}
	}
}

func (r *Runtime) buildGRPCServers() ([]*grpcInstance, error) {
	listeners, err := newGRPCListenerBuilder(r.cfg.GRPC, r.serverImpl).Build()
	if err != nil {
		return nil, err
	}
	for _, inst := range listeners {
		logx.Infof("gRPC listening on %s (%s)", inst.address, inst.network)
	}
	return listeners, nil
}

func (r *Runtime) shutdownRuntime() {
	r.shutdown.Do(func() {
		for _, inst := range r.grpcServers {
			inst.Stop()
		}
		r.grpcServers = nil

		logx.Infof("Stopping DNS service")
		r.dnsService.Stop()

		r.serverImpl.DisableAllXrayRouting()
		logx.Infof("Stopping all Xray chains")
		r.xraySvc.StopAll()

		r.upstream.Close()
	})
}
