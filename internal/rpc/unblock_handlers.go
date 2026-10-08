package rpc

import (
	"context"
	"fmt"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (s *VpnerServer) resolveChainType(chainName string) (string, bool) {
	if s.xrayService.IsChain(chainName) {
		return vpnkind.Xray.String(), true
	}
	return s.ifManager.LookupTrackedType(chainName)
}

func (s *VpnerServer) UnblockList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.UnblockListResponse, error) {
	var result []*grpcpb.UnblockInfo
	for _, rule := range s.unblock.Groups() {
		result = append(result, &grpcpb.UnblockInfo{
			TypeName:  rule.TypeName,
			ChainName: rule.ChainName,
			Rules:     rule.Rules,
		})
	}
	return &grpcpb.UnblockListResponse{Rules: result}, nil
}

func (s *VpnerServer) UnblockAdd(ctx context.Context, req *grpcpb.UnblockAddRequest) (*grpcpb.GenericResponse, error) {
	vpnType, ok := s.resolveChainType(req.ChainName)
	if !ok {
		return errorGeneric(fmt.Sprintf("Failed to add rule: chain name %q does not exist", req.ChainName)), nil
	}
	if err := s.unblock.AddRule(vpnType, req.ChainName, req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to add rule: %v", err)), nil
	}
	if err := s.applyMarkRouting(vpnType, req.ChainName); err != nil {
		if _, _, delErr := s.unblock.DeleteRuleByPattern(req.Domain); delErr != nil {
			return errorGeneric(fmt.Sprintf("Rule added, but failed to configure routing: %v (rollback failed: %v)", err, delErr)), nil
		}
		return errorGeneric(fmt.Sprintf("Failed to configure routing: %v", err)), nil
	}
	return successGeneric("Rule added successfully"), nil
}

func (s *VpnerServer) UnblockDel(ctx context.Context, req *grpcpb.UnblockDelRequest) (*grpcpb.GenericResponse, error) {
	vpnType, chainName, err := s.unblock.DeleteRuleByPattern(req.Domain)
	if err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete rule: %v", err)), nil
	}
	if err := s.dropMarkRoutingIfUnused(vpnType, chainName); err != nil {
		return errorGeneric(fmt.Sprintf("Rule deleted, but failed to remove routing: %v", err)), nil
	}
	return successGeneric("Rule deleted successfully"), nil
}
