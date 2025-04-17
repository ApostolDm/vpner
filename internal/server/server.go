package server

import (
	"context"

	"github.com/ApostolDmitry/vpner/internal/dohclient"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns      *DNSService
	unblock  *network.UnblockManager
	resolver *dohclient.Resolver
}

func (s *VpnerServer) DnsManage(ctx context.Context, req *grpcpb.DnsManageResponse) (*grpcpb.DnsManageRequest, error) {
	switch req.GetAct() {
	case grpcpb.DnsManageResponse_START:
		if err := s.dns.Start(); err != nil {
			return &grpcpb.DnsManageRequest{
				Result: &grpcpb.DnsManageRequest_Error{Error: &grpcpb.Error{Message: err.Error()}},
			}, nil
		}
		return &grpcpb.DnsManageRequest{
			Result: &grpcpb.DnsManageRequest_Success{Success: &grpcpb.Success{Message: "Server started"}},
		}, nil

	case grpcpb.DnsManageResponse_STOP:
		s.dns.Stop()
		return &grpcpb.DnsManageRequest{
			Result: &grpcpb.DnsManageRequest_Success{Success: &grpcpb.Success{Message: "Server stopped"}},
		}, nil

	case grpcpb.DnsManageResponse_STATUS:
		running := s.dns.IsRunning()
		status := "DOWN"
		if running {
			status = "RUNNING"
		}
		return &grpcpb.DnsManageRequest{
			Result: &grpcpb.DnsManageRequest_Success{Success: &grpcpb.Success{Message: status}},
		}, nil

	case grpcpb.DnsManageResponse_RESTART:
		s.dns.Stop()
		err := s.dns.Start()
		if err != nil {
			return &grpcpb.DnsManageRequest{
				Result: &grpcpb.DnsManageRequest_Error{Error: &grpcpb.Error{Message: err.Error()}},
			}, nil
		}
		return &grpcpb.DnsManageRequest{
			Result: &grpcpb.DnsManageRequest_Success{Success: &grpcpb.Success{Message: "DNS Server restated."}},
		}, nil

	default:
		return &grpcpb.DnsManageRequest{
			Result: &grpcpb.DnsManageRequest_Error{Error: &grpcpb.Error{Message: "unknown action"}},
		}, nil
	}
}

func (s *VpnerServer) UnblockList(ctx context.Context, _ *grpcpb.UnblockListResponse) (*grpcpb.UnblockListRequest, error) {
	conf, err := s.unblock.GetAllRules()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get rules: %v", err)
	}

	var result []*grpcpb.UnblockInfo
	for vpnType, set := range conf.RuleMap() {
		for chain, patterns := range *set {
			result = append(result, &grpcpb.UnblockInfo{
				TypeName:  vpnType,
				ChainName: chain,
				Rules:     patterns,
			})
		}
	}

	return &grpcpb.UnblockListRequest{Rules: result}, nil
}
