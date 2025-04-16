package runtime

import (
	"fmt"

	"github.com/ApostolDmitry/vpner/config"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	interface_manager "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/routing"
	grpcserver "github.com/ApostolDmitry/vpner/internal/server"
	dnsservice "github.com/ApostolDmitry/vpner/internal/services/dns"
	xrayservice "github.com/ApostolDmitry/vpner/internal/services/xray"
)

type runtimeGraph struct {
	dnsService *dnsservice.Service
	xraySvc    *xrayservice.Service
	grpcServer *grpcserver.VpnerServer
}

func buildRuntimeGraph(cfg config.FullConfig) (*runtimeGraph, error) {
	resolver := dohclient.NewResolver(cfg.DoH)

	unblock := network.NewUnblockManager(cfg.UnblockRulesPath)
	if err := unblock.Init(); err != nil {
		return nil, fmt.Errorf("failed to init unblock manager: %w", err)
	}

	xrayMgr, err := network.NewXrayManager()
	if err != nil {
		return nil, fmt.Errorf("failed to init xray manager: %w", err)
	}

	iptables := network.NewIptablesManager()
	xrayRouter := routing.NewXrayRouter(iptables, cfg.Network.LANInterface)

	dnsSvc := dnsservice.New(cfg.DNSServer, unblock, resolver)
	xraySvc := xrayservice.New(xrayMgr)
	ifManager := interface_manager.NewInterfaceManager("")

	deps := grpcserver.Dependencies{
		DNS:              dnsSvc,
		Unblock:          unblock,
		InterfaceManager: ifManager,
		XrayManager:      xrayMgr,
		XrayService:      xraySvc,
		XrayRouter:       xrayRouter,
	}

	srv := grpcserver.NewVpnerServer(deps)

	return &runtimeGraph{
		dnsService: dnsSvc,
		xraySvc:    xraySvc,
		grpcServer: srv,
	}, nil
}
