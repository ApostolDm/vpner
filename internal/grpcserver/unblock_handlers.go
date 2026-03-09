package grpcserver

import (
	"context"
	"fmt"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *VpnerServer) UnblockList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.UnblockListResponse, error) {
	rules, err := s.unblock.List()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve unblock rules: %v", err)
	}

	var result []*grpcpb.UnblockInfo
	for _, rule := range rules {
		result = append(result, &grpcpb.UnblockInfo{
			TypeName:  rule.TypeName,
			ChainName: rule.ChainName,
			Rules:     rule.Rules,
		})
	}
	return &grpcpb.UnblockListResponse{Rules: result}, nil
}

func (s *VpnerServer) UnblockAdd(ctx context.Context, req *grpcpb.UnblockAddRequest) (*grpcpb.GenericResponse, error) {
	if err := s.unblock.AddRule(req.ChainName, req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to add rule: %v", err)), nil
	}
	return successGeneric("Rule added successfully"), nil
}

func (s *VpnerServer) UnblockDel(ctx context.Context, req *grpcpb.UnblockDelRequest) (*grpcpb.GenericResponse, error) {
	if err := s.unblock.DeleteRule(req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete rule: %v", err)), nil
	}
	return successGeneric("Rule deleted successfully"), nil
}
