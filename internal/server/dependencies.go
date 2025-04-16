package grpcserver

import (
	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/routing"
	dnsservice "github.com/ApostolDmitry/vpner/internal/services/dns"
	xrayservice "github.com/ApostolDmitry/vpner/internal/services/xray"
)

type DNSController interface {
	Start() error
	Stop()
	IsRunning() bool
}

type XrayController interface {
	StartAuto() error
	StartOne(string) error
	StopOne(string) error
	StopAll()
	IsRunning(string) bool
}

type Dependencies struct {
	DNS              DNSController
	Unblock          *network.UnblockManager
	InterfaceManager *manager_interface.Manager
	XrayManager      *network.XrayManager
	XrayService      XrayController
	XrayRouter       *routing.XrayRouter
}

func NewVpnerServer(deps Dependencies) *VpnerServer {
	return &VpnerServer{
		dns:         deps.DNS,
		unblock:     deps.Unblock,
		ifManager:   deps.InterfaceManager,
		xrayManager: deps.XrayManager,
		xrayService: deps.XrayService,
		xrayRouter:  deps.XrayRouter,
	}
}

var _ DNSController = (*dnsservice.Service)(nil)
var _ XrayController = (*xrayservice.Service)(nil)
