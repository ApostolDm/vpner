package agent

import (
	"fmt"
	"log"
	"time"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/conf"
	dnssvc "github.com/ApostolDmitry/vpner/internal/dnssvc"
	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	proxy "github.com/ApostolDmitry/vpner/internal/proxy"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	routing "github.com/ApostolDmitry/vpner/internal/routing"
	rpc "github.com/ApostolDmitry/vpner/internal/rpc"
	unblock "github.com/ApostolDmitry/vpner/internal/unblock"
)

type runtimeGraph struct {
	dnsService *dnssvc.Service
	xraySvc    *proxysvc.Service
	grpcServer *rpc.VpnerServer
	resolver   *resolver.Upstream
}

func buildRuntimeGraph(cfg conf.FullConfig) (*runtimeGraph, error) {
	resolver := resolver.NewUpstream(cfg.DoH)
	ipsetRegistry := firewall.NewIPSetRegistry()

	tproxyEnabled := cfg.Network.EnableTProxy
	if tproxyEnabled {
		if err := firewall.EnsureTProxySupport(cfg.Network.EnableIPv6); err != nil {
			log.Printf("WARNING: TPROXY disabled, falling back to REDIRECT: %v", err)
			tproxyEnabled = false
		}
	}

	xrayMgr, err := proxy.New(tproxyEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to init xray manager: %w", err)
	}

	iptables := firewall.NewIptablesManager(cfg.Network.EnableIPv6, tproxyEnabled)
	iptables.CleanupStaleState()
	xrayRouter := routing.NewXrayRouter(iptables, cfg.Network.LANInterfaces)

	ifManager := netif.NewInterfaceManager("")
	xraySvc := proxysvc.New(xrayMgr)

	unblockManager := firewall.NewUnblockManager(
		cfg.UnblockRulesPath,
		cfg.Network.EnableIPv6,
		cfg.Network.IPSetDebug,
		cfg.Network.IPSetStaleQueries,
		ipsetRegistry,
	)
	unblockSvc := unblock.New(unblockManager, ifManager, xraySvc)
	if err := unblockSvc.Init(); err != nil {
		return nil, fmt.Errorf("failed to init unblock manager: %w", err)
	}

	dnsSvc := dnssvc.New(cfg.DNSServer, unblockSvc, resolver, ipsetRegistry)

	deps := rpc.Dependencies{
		DNS:              dnsSvc,
		Unblock:          unblockSvc,
		InterfaceManager: ifManager,
		XrayService:      xraySvc,
		XrayRouter:       xrayRouter,
		Info: rpc.StatusInfo{
			Version:       buildinfo.String(),
			StartedAt:     time.Now(),
			DNSPort:       cfg.DNSServer.Port,
			TProxyEnabled: tproxyEnabled,
		},
	}

	srv := rpc.NewVpnerServer(deps)

	return &runtimeGraph{
		dnsService: dnsSvc,
		xraySvc:    xraySvc,
		grpcServer: srv,
		resolver:   resolver,
	}, nil
}
