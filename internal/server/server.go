package grpcserver

import (
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	interface_manager "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/routing"
)

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns         DNSController
	unblock     *network.UnblockManager
	ifManager   *interface_manager.Manager
	xrayManager *network.XrayManager
	xrayService XrayController
	xrayRouter  *routing.XrayRouter
}
