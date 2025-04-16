package runtime

import (
	"context"
	"fmt"
	"sync"

	"github.com/ApostolDmitry/vpner/config"
	"github.com/ApostolDmitry/vpner/internal/common/logging"
	grpcserver "github.com/ApostolDmitry/vpner/internal/server"
	dnsservice "github.com/ApostolDmitry/vpner/internal/services/dns"
	xrayservice "github.com/ApostolDmitry/vpner/internal/services/xray"
	"golang.org/x/sync/errgroup"
)

// Runtime wires core services together and manages their lifecycle.
// It replaces the previous implicit wiring done in main() and internal/app.
type Runtime struct {
	cfg config.FullConfig

	dnsService *dnsservice.Service
	xraySvc    *xrayservice.Service
	serverImpl *grpcserver.VpnerServer

	grpcServers []*grpcInstance
	shutdown    sync.Once
}

func New(cfg config.FullConfig) (*Runtime, error) {
	graph, err := buildRuntimeGraph(cfg)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		cfg:        cfg,
		dnsService: graph.dnsService,
		xraySvc:    graph.xraySvc,
		serverImpl: graph.grpcServer,
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if r.cfg.DNSServer.Running {
		logging.Infof("Auto-starting DNS server")
		if err := r.dnsService.Start(); err != nil {
			return fmt.Errorf("failed to start DNS server: %w", err)
		}
	}

	if err := r.xraySvc.StartAuto(); err != nil {
		logging.Errorf("Failed to autostart xray chains: %v", err)
	}
	r.serverImpl.RestoreXrayRouting()

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

	errCh := make(chan error, 1)
	go func() {
		errCh <- grp.Wait()
	}()

	select {
	case <-ctx.Done():
		logging.Warnf("Context cancelled, shutting down runtime")
		r.shutdownRuntime()
		if err := <-errCh; err != nil {
			logging.Debugf("gRPC listeners stopped with: %v", err)
		}
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			logging.Errorf("gRPC listener exited: %v", err)
		}
		r.shutdownRuntime()
		return err
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
			logging.Infof("gRPC listening on %s (tcp)", inst.address)
		case "unix":
			logging.Infof("gRPC listening on %s (unix)", inst.address)
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
			logging.Infof("Stopping DNS service")
			r.dnsService.Stop()
		}
		if r.xraySvc != nil {
			if r.serverImpl != nil {
				r.serverImpl.DisableAllXrayRouting()
			}
			logging.Infof("Stopping all Xray chains")
			r.xraySvc.StopAll()
		}
	})
}
