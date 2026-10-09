package rpc

import (
	"sync"
	"time"

	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
)

type StatusInfo struct {
	Version       string
	StartedAt     time.Time
	DNSPort       int
	TProxyEnabled bool
}

type Dependencies struct {
	DNS              *resolver.Service
	Upstream         *resolver.Upstream
	IPRules          *firewall.IpRuleManager
	Unblock          *firewall.UnblockManager
	Interfaces       *netif.Manager
	Xray             *proxysvc.Service
	Iptables         *firewall.IptablesManager
	Info             StatusInfo
	IPSetCounts      func() (v4, v6 int64)
	DefaultRouteFile string
}

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns         *resolver.Service
	upstream    *resolver.Upstream
	ipRules     *firewall.IpRuleManager
	unblock     *firewall.UnblockManager
	ifManager   *netif.Manager
	xrayService *proxysvc.Service
	iptables    *firewall.IptablesManager
	markMu      sync.Mutex
	xrayMu      sync.Mutex
	routeMu     sync.Mutex
	routeOpMu   sync.Mutex
	route       defaultRoute
	routeFile   string
	info        StatusInfo
	ipsetCounts func() (v4, v6 int64)
}

func NewVpnerServer(deps Dependencies) *VpnerServer {
	return &VpnerServer{
		dns:         deps.DNS,
		upstream:    deps.Upstream,
		ipRules:     deps.IPRules,
		unblock:     deps.Unblock,
		ifManager:   deps.Interfaces,
		xrayService: deps.Xray,
		iptables:    deps.Iptables,
		routeFile:   deps.DefaultRouteFile,
		info:        deps.Info,
		ipsetCounts: deps.IPSetCounts,
	}
}
