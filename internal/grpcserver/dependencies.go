package grpcserver

import (
	interfaces "github.com/ApostolDmitry/vpner/internal/service/interfaces"
	routingservice "github.com/ApostolDmitry/vpner/internal/service/routingservice"
	unblockservice "github.com/ApostolDmitry/vpner/internal/service/unblockservice"
	xrayservice "github.com/ApostolDmitry/vpner/internal/service/xrayservice"
	xraypkg "github.com/ApostolDmitry/vpner/internal/xray"
)

type DNSController interface {
	Start() error
	Stop()
	IsRunning() bool
}

type InterfaceController interface {
	LoadInterfacesFromFile() (*interfaces.VPNInterfaces, error)
	FetchInterfaces() (map[string]interfaces.Interface, error)
	AddInterface(id string) error
	DeleteInterface(id string) error
	LookupTrackedType(name string) (string, bool)
	LookupRouterType(name string) (string, bool)
}

type XrayController interface {
	StartAuto() error
	StartOne(string) error
	StopOne(string) error
	StopAll()
	IsRunning(string) bool
	ListInfo() (map[string]xraypkg.XrayInfoDetails, error)
	GetInfo(string) (xraypkg.XrayInfoDetails, error)
	Create(link string, autoRun bool) (string, error)
	Delete(name string) error
	SetAutorun(name string, autoRun bool) error
	IsChain(name string) bool
}

type UnblockController interface {
	List() ([]unblockservice.RuleGroup, error)
	AddRule(chainName, pattern string) error
	DeleteRule(pattern string) error
	DeleteChain(vpnType, chainName string) error
	MatchDomain(domain string) (vpnType string, chainName string, rule string, ok bool)
}

type RoutingController interface {
	Apply(chain string, info xraypkg.XrayInfoDetails) error
	Remove(chain string) error
	Restore(info map[string]xraypkg.XrayInfoDetails, isRunning func(string) bool, restoreV4, restoreV6 bool, table string)
	Shutdown()
	ClearAppliedState(table string, clearV4, clearV6 bool)
	ResetStateFamily(resetV4, resetV6 bool)
}

type Dependencies struct {
	DNS              DNSController
	Unblock          UnblockController
	InterfaceManager InterfaceController
	XrayService      XrayController
	XrayRouter       RoutingController
}

func NewVpnerServer(deps Dependencies) *VpnerServer {
	return &VpnerServer{
		dns:         deps.DNS,
		unblock:     deps.Unblock,
		ifManager:   deps.InterfaceManager,
		xrayService: deps.XrayService,
		xrayRouter:  deps.XrayRouter,
	}
}

var _ XrayController = (*xrayservice.Service)(nil)
var _ UnblockController = (*unblockservice.Service)(nil)
var _ InterfaceController = (*interfaces.Manager)(nil)
var _ RoutingController = (*routingservice.XrayRouter)(nil)
