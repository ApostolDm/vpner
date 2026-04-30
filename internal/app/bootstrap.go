package app

import (
	"fmt"
	"log"

	"github.com/ApostolDmitry/vpner/internal/config"
	"github.com/ApostolDmitry/vpner/internal/doh"
	grpcserver "github.com/ApostolDmitry/vpner/internal/grpcserver"
	"github.com/ApostolDmitry/vpner/internal/network"
	dnsservice "github.com/ApostolDmitry/vpner/internal/service/dnsservice"
	interfaces "github.com/ApostolDmitry/vpner/internal/service/interfaces"
	routingservice "github.com/ApostolDmitry/vpner/internal/service/routingservice"
	unblockservice "github.com/ApostolDmitry/vpner/internal/service/unblockservice"
	xrayservice "github.com/ApostolDmitry/vpner/internal/service/xrayservice"
	xraypkg "github.com/ApostolDmitry/vpner/internal/xray"
)

type runtimeGraph struct {
	dnsService *dnsservice.Service
	xraySvc    *xrayservice.Service
	grpcServer *grpcserver.VpnerServer
	resolver   *doh.Resolver
}

func buildRuntimeGraph(cfg config.FullConfig) (*runtimeGraph, error) {
	resolver := doh.NewResolver(cfg.DoH)
	ipsetRegistry := network.NewIPSetRegistry()

	tproxyEnabled := cfg.Network.EnableTProxy
	if tproxyEnabled {
		if err := network.EnsureTProxySupport(cfg.Network.EnableIPv6); err != nil {
			log.Printf("WARNING: TPROXY disabled, falling back to REDIRECT: %v", err)
			tproxyEnabled = false
		}
	}

	xrayMgr, err := xraypkg.NewXrayManager(tproxyEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to init xray manager: %w", err)
	}

	iptables := network.NewIptablesManager(cfg.Network.EnableIPv6, tproxyEnabled)
	iptables.CleanupStaleState()
	xrayRouter := routingservice.NewXrayRouter(iptables, cfg.Network.LANInterfaces)

	ifManager := interfaces.NewInterfaceManager("")
	xraySvc := xrayservice.New(xrayMgr)

	unblockManager := network.NewUnblockManager(
		cfg.UnblockRulesPath,
		cfg.Network.EnableIPv6,
		cfg.Network.IPSetDebug,
		cfg.Network.IPSetStaleQueries,
		ipsetRegistry,
	)
	unblockSvc := unblockservice.New(unblockManager, ifManager, xraySvc)
	if err := unblockSvc.Init(); err != nil {
		return nil, fmt.Errorf("failed to init unblock manager: %w", err)
	}

	dnsSvc := dnsservice.New(cfg.DNSServer, unblockSvc, resolver, ipsetRegistry)

	deps := grpcserver.Dependencies{
		DNS:              dnsSvc,
		Unblock:          unblockSvc,
		InterfaceManager: ifManager,
		XrayService:      xraySvc,
		XrayRouter:       xrayRouter,
	}

	srv := grpcserver.NewVpnerServer(deps)

	return &runtimeGraph{
		dnsService: dnsSvc,
		xraySvc:    xraySvc,
		grpcServer: srv,
		resolver:   resolver,
	}, nil
}
