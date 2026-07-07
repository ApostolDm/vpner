package rpc

import (
	"sync"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns         DNSController
	unblock     UnblockController
	ifManager   InterfaceController
	xrayService XrayController
	xrayRouter  RoutingController
	markRouter  MarkRoutingController
	markMu      sync.Mutex
	info        StatusInfo
	ipsetCounts func() (v4, v6 int64)
}
