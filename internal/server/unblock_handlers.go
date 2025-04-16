package grpcserver

import (
	"context"
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/common/patterns"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *VpnerServer) UnblockList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.UnblockListResponse, error) {
	conf, err := s.unblock.GetAllRules()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve unblock rules: %v", err)
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
	return &grpcpb.UnblockListResponse{Rules: result}, nil
}

func (s *VpnerServer) UnblockAdd(ctx context.Context, req *grpcpb.UnblockAddRequest) (*grpcpb.GenericResponse, error) {
	if req.ChainName == "" {
		return errorGeneric("Chain name is required"), nil
	}
	if err := patterns.Validate(req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Invalid pattern: %v", err)), nil
	}
	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromVpner(req.ChainName)
	isXray := s.xrayManager.IsXrayChain(req.ChainName)
	if isXray {
		vpnType = "Xray"
	}
	if !exists && !isXray {
		return errorGeneric(fmt.Sprintf("Chain name '%s' does not exist", req.ChainName)), nil
	}
	allRules, err := s.unblock.GetAllRules()
	if err != nil {
		return errorGeneric("Failed to load existing rules"), nil
	}
	for typ, setPtr := range allRules.RuleMap() {
		for chain, rules := range *setPtr {
			for _, existing := range rules {
				if patterns.Overlap(existing, req.Domain) {
					return errorGeneric(fmt.Sprintf(
						"New rule '%s' overlaps with existing rule '%s' in [%s/%s]",
						req.Domain, existing, typ, chain,
					)), nil
				}
			}
		}
	}
	if err := s.unblock.AddRule(vpnType, req.ChainName, req.Domain); err != nil {
		return errorGeneric("Failed to add rule"), nil
	}
	return successGeneric("Rule added successfully"), nil
}

func (s *VpnerServer) UnblockDel(ctx context.Context, req *grpcpb.UnblockDelRequest) (*grpcpb.GenericResponse, error) {
	if err := patterns.Validate(req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Invalid pattern: %v", err)), nil
	}
	vpnType, chainName, exists := s.unblock.MatchDomain(req.Domain)
	if !exists {
		return errorGeneric("Rule does not exist"), nil
	}
	if err := s.unblock.DelRule(vpnType, chainName, req.Domain); err != nil {
		return errorGeneric("Failed to delete rule"), nil
	}
	return successGeneric("Rule deleted successfully"), nil
}
