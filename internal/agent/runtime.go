package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	dnssvc "github.com/ApostolDmitry/vpner/internal/dnssvc"
	"github.com/ApostolDmitry/vpner/internal/logx"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	rpc "github.com/ApostolDmitry/vpner/internal/rpc"
	"golang.org/x/sync/errgroup"
)

const defaultReconcileInterval = 45 * time.Second

type Runtime struct {
	cfg conf.FullConfig

	dnsService *dnssvc.Service
	xraySvc    *proxysvc.Service
	serverImpl *rpc.VpnerServer
	resolver   *resolver.Upstream

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
		resolver:   graph.resolver,
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
	r.serverImpl.RestoreXrayRouting(true, true, "")

	servers, err := r.buildGRPCServers()
	if err != nil {
		r.shutdownRuntime()
		return err
	}
	r.grpcServers = servers

	grp, _ := errgroup.WithContext(ctx)
	for _, inst := range r.grpcServers {
		inst := inst
		grp.Go(func() error {
			return inst.Serve()
		})
	}

	go r.runWatchdog(ctx)

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

func (r *Runtime) runWatchdog(ctx context.Context) {
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

	const baseThreshold, maxThreshold = 2, 32
	misses, threshold := 0, baseThreshold
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.serverImpl.RoutingHealthy() {
				misses, threshold = 0, baseThreshold
				continue
			}
			if misses++; misses >= threshold {
				logx.Warnf("routing watchdog: Xray routing missing from kernel; reconciling")
				r.serverImpl.ReconcileRouting()
				misses = 0

				if threshold < maxThreshold {
					threshold *= 2
				}
			}
		}
	}
}

func (r *Runtime) buildGRPCServers() ([]*grpcInstance, error) {
	builder := newGRPCListenerBuilder(r.cfg.GRPC, r.serverImpl)
	listeners, err := builder.Build()
	if err != nil {
		return nil, err
	}
	for _, inst := range listeners {
		switch inst.network {
		case "tcp":
			logx.Infof("gRPC listening on %s (tcp)", inst.address)
		case "unix":
			logx.Infof("gRPC listening on %s (unix)", inst.address)
		}
	}
	return listeners, nil
}

func (r *Runtime) shutdownRuntime() {
	r.shutdown.Do(func() {
		for _, inst := range r.grpcServers {
			inst.Stop()
		}
		r.grpcServers = nil

		if r.dnsService != nil {
			logx.Infof("Stopping DNS service")
			r.dnsService.Stop()
		}
		if r.xraySvc != nil {
			if r.serverImpl != nil {
				r.serverImpl.DisableAllXrayRouting()
			}
			logx.Infof("Stopping all Xray chains")
			r.xraySvc.StopAll()
		}
		if r.resolver != nil {
			r.resolver.Close()
		}
	})
}
