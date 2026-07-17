package rpc

import (
	"context"
	"time"

	dnssvc "github.com/ApostolDmitry/vpner/internal/dnssvc"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	proxy "github.com/ApostolDmitry/vpner/internal/proxy"
	proxysvc "github.com/ApostolDmitry/vpner/internal/proxysvc"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	routing "github.com/ApostolDmitry/vpner/internal/routing"
	unblock "github.com/ApostolDmitry/vpner/internal/unblock"
)

type DNSController interface {
	Start() error
	Stop()
	IsRunning() bool
	UpstreamStats() []resolver.ServerStat
	QueryStats() resolver.QueryStats
	ResyncRules(ctx context.Context) (dnssvc.SyncReport, error)
}

type InterfaceController interface {
	LoadInterfacesFromFile() (*netif.VPNInterfaces, error)
	FetchInterfaces() (map[string]netif.Interface, error)
	AddInterface(id string) error
	DeleteInterface(id string) error
	LookupTracked(name string) (netif.Interface, bool)
	SystemNameResolver() func(id string) (string, error)
}

type XrayController interface {
	StartAuto() error
	StartOne(string) error
	StopOne(string) error
	IsRunning(string) bool
	ListInfo() (map[string]proxy.ChainInfo, error)
	GetInfo(string) (proxy.ChainInfo, error)
	Create(link string, autoRun bool) (string, error)
	Update(name, link string) error
	Delete(name string) error
	SetAutorun(name string, autoRun bool) error
	IsChain(name string) bool
	Runtimes() map[string]proxysvc.ChainRuntime
	Test(name string) (string, error)
}

type UnblockController interface {
	List() ([]unblock.RuleGroup, error)
	AddRule(chainName, pattern string) (string, error)
	DeleteRule(pattern string) (string, string, error)
	DeleteChain(vpnType, chainName string) error
	RuleCount(vpnType, chainName string) int
}

type RoutingController interface {
	Apply(chain string, info proxy.ChainInfo) error
	Remove(chain string) error
	Restore(info map[string]proxy.ChainInfo, isRunning func(string) bool, restoreV4, restoreV6 bool, table string)
	Shutdown()
	ClearAppliedState(table string, clearV4, clearV6 bool)
	ResetStateFamily(resetV4, resetV6 bool)
	RoutingIntact() bool
}

type MarkRoutingController interface {
	Apply(vpnType, chain string, resolveIface func() (string, error)) error
	Sync(vpnType, chain string, resolveIface func() (string, error)) error
	Remove(vpnType, chain string) error
	Intact(vpnType, chain string) bool
}

type StatusInfo struct {
	Version       string
	StartedAt     time.Time
	DNSPort       int
	TProxyEnabled bool
}

type Dependencies struct {
	DNS              DNSController
	Unblock          UnblockController
	InterfaceManager InterfaceController
	XrayService      XrayController
	XrayRouter       RoutingController
	MarkRouter       MarkRoutingController
	Info             StatusInfo
	IPSetCounts      func() (v4, v6 int64)
}

func NewVpnerServer(deps Dependencies) *VpnerServer {
	return &VpnerServer{
		dns:         deps.DNS,
		unblock:     deps.Unblock,
		ifManager:   deps.InterfaceManager,
		xrayService: deps.XrayService,
		xrayRouter:  deps.XrayRouter,
		markRouter:  deps.MarkRouter,
		info:        deps.Info,
		ipsetCounts: deps.IPSetCounts,
	}
}

var _ XrayController = (*proxysvc.Service)(nil)
var _ UnblockController = (*unblock.Service)(nil)
var _ InterfaceController = (*netif.Manager)(nil)
var _ RoutingController = (*routing.XrayRouter)(nil)
var _ MarkRoutingController = (*routing.MarkRouter)(nil)
