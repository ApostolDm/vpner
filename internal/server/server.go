package server

import (
	"context"
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/dohclient"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	interface_manager "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VpnerServer struct {
	grpcpb.UnimplementedVpnerManagerServer
	dns       *DNSService
	unblock   *network.UnblockManager
	resolver  *dohclient.Resolver
	ifManager *interface_manager.Manager
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

func (s *VpnerServer) UnblockAdd(ctx context.Context, req *grpcpb.UnblockAddResponse) (*grpcpb.UnblockAddRequest, error) {
	if err := utils.ValidatePattern(req.ChainName); err != nil {
		return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: err.Error()}}}, nil
	}
	if req.ChainName == "" {
		return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: "chainName is not set"}}}, nil
	}
	vpnType, exists := s.ifManager.PrintInterfaceTypeByName(req.ChainName)
	if !exists {
		return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: "there is no such ChainName"}}}, nil
	}

	allRules, err := s.unblock.GetAllRules()
	if err != nil {
		return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: "cant`t read rules"}}}, nil
	}
	for typ, setPtr := range allRules.RuleMap() {
		if setPtr == nil {
			continue
		}
		for chain, rules := range *setPtr {
			for _, existing := range rules {
				if utils.PatternsOverlap(existing, req.Domain) {
					return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: fmt.Sprintf("the new %s' rule intersects with the existing %s' rule in [%s/%s]\n", req.Domain, existing, typ, chain)}}}, nil
				}
			}
		}
	}

	if err := s.unblock.AddRule(vpnType, req.ChainName, req.Domain); err != nil {
		return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Error{Error: &grpcpb.Error{Message: "cant`t add rule"}}}, nil
	}
	return &grpcpb.UnblockAddRequest{Result: &grpcpb.UnblockAddRequest_Success{Success: &grpcpb.Success{Message: "Rule added"}}}, nil
}

func (s *VpnerServer) UnblockDel(ctx context.Context, req *grpcpb.UnblockDelResponse) (*grpcpb.UnblockDelRequest, error) {
	if err := utils.ValidatePattern(req.Domain); err != nil {
		return &grpcpb.UnblockDelRequest{Result: &grpcpb.UnblockDelRequest_Error{Error: &grpcpb.Error{Message: err.Error()}}}, nil
	}

	vpnType, chainName, exists := s.unblock.MatchDomain(req.Domain)
	if !exists {
		return &grpcpb.UnblockDelRequest{Result: &grpcpb.UnblockDelRequest_Error{Error: &grpcpb.Error{Message: "This rule is not have"}}}, nil
	}
	if err := s.unblock.DelRule(vpnType, chainName, req.Domain); err != nil {
		return &grpcpb.UnblockDelRequest{Result: &grpcpb.UnblockDelRequest_Error{Error: &grpcpb.Error{Message: "cant`t delete rule"}}}, nil
	}
	return &grpcpb.UnblockDelRequest{Result: &grpcpb.UnblockDelRequest_Success{Success: &grpcpb.Success{Message: "Rule deleted"}}}, nil
}
