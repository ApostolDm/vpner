package agent

import (
	"fmt"
	"log"
	"time"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/conf"
	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/logx"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	proxy "github.com/ApostolDmitry/vpner/internal/proxy"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	rpc "github.com/ApostolDmitry/vpner/internal/rpc"
)

type runtimeGraph struct {
	dnsService *resolver.Service
	xraySvc    *proxysvc.Service
	grpcServer *rpc.VpnerServer
	upstream   *resolver.Upstream
	keepalive  *firewall.KeepaliveSweeper
}

func buildRuntimeGraph(cfg conf.FullConfig) (*runtimeGraph, error) {
	upstream := resolver.NewUpstream(cfg.DoH)
	ipsetRegistry := firewall.NewIPSetRegistry()

	tproxyEnabled := cfg.Network.EnableTProxy
	if tproxyEnabled {
		if err := firewall.EnsureTProxySupport(cfg.Network.EnableIPv6); err != nil {
			log.Printf("WARNING: TPROXY disabled, falling back to REDIRECT (TCP only: UDP traffic will NOT be proxied): %v", err)
			tproxyEnabled = false
		}
	}

	keepalive := firewall.NewKeepaliveSweeper(ipsetRegistry, firewall.KeepaliveOptions{
		EntryTimeout: cfg.Network.IPSetEntryTimeout,
		Interval:     cfg.Network.IPSetKeepaliveInterval,
		Enabled:      cfg.Network.IPSetKeepalive == nil || *cfg.Network.IPSetKeepalive,
		Debug:        cfg.Network.IPSetDebug,
	})
	if keepalive != nil {
		logx.Infof("ipset keepalive: interval=%s refresh-below=%ds", keepalive.Interval(), keepalive.Threshold())
	}

	xrayMgr, err := proxy.New(tproxyEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to init xray manager: %w", err)
	}

	iptables := firewall.NewIptablesManager(cfg.Network.EnableIPv6, tproxyEnabled, cfg.Network.IPSetEntryTimeout, cfg.Network.LocalExceptions, cfg.Network.LANInterfaces)
	iptables.CleanupStaleState()

	ifManager := netif.NewInterfaceManager("")
	xraySvc := proxysvc.New(xrayMgr)

	unblockManager := firewall.NewUnblockManager(
		cfg.UnblockRulesPath,
		cfg.Network.EnableIPv6,
		cfg.Network.IPSetDebug,
		cfg.Network.IPSetStaleQueries,
		cfg.Network.IPSetEntryTimeout,
		cfg.Network.ClampDNSTTL,
		ipsetRegistry,
	)
	if err := unblockManager.Init(); err != nil {
		return nil, fmt.Errorf("failed to init unblock manager: %w", err)
	}

	ipRules := firewall.NewIpRuleManager(unblockManager, unblockManager.RuntimeOptions(), ipsetRegistry)
	dnsSvc := resolver.NewService(cfg.DNSServer, ipRules, upstream)

	srv := rpc.NewVpnerServer(rpc.Dependencies{
		DNS:        dnsSvc,
		Upstream:   upstream,
		IPRules:    ipRules,
		Unblock:    unblockManager,
		Interfaces: ifManager,
		Xray:       xraySvc,
		Iptables:   iptables,
		Info: rpc.StatusInfo{
			Version:       buildinfo.String(),
			StartedAt:     time.Now(),
			DNSPort:       cfg.DNSServer.Port,
			TProxyEnabled: tproxyEnabled,
		},
		IPSetCounts: firewall.ManagedIpsetCounts,
	})

	return &runtimeGraph{
		dnsService: dnsSvc,
		xraySvc:    xraySvc,
		grpcServer: srv,
		upstream:   upstream,
		keepalive:  keepalive,
	}, nil
}
