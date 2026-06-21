package rpc

import (
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns         DNSController
	unblock     UnblockController
	ifManager   InterfaceController
	xrayService XrayController
	xrayRouter  RoutingController
	info        StatusInfo
}
