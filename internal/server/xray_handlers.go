package grpcserver

import (
	"context"
	"fmt"
	"sort"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *VpnerServer) XrayList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.XrayListResponse, error) {
	xrayList, err := s.xrayManager.ListXrayInfo()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve Xray list: %v", err)
	}
	if len(xrayList) == 0 {
		return nil, status.Errorf(codes.Internal, "no Xray configurations found")
	}
	var xrayConfigs []*grpcpb.XrayInfo
	for name, config := range xrayList {
		isRunning := s.xrayService.IsRunning(name)
		xrayConfigs = append(xrayConfigs, &grpcpb.XrayInfo{
			ChainName: name,
			Host:      config.Host,
			Port:      int32(config.Port),
			AutoRun:   config.AutoRun,
			Status:    isRunning,
			Type:      config.Type,
		})
	}
	sort.Slice(xrayConfigs, func(i, j int) bool {
		return xrayConfigs[i].ChainName < xrayConfigs[j].ChainName
	})
	return &grpcpb.XrayListResponse{List: xrayConfigs}, nil
}

func (s *VpnerServer) XrayManage(ctx context.Context, req *grpcpb.XrayManageRequest) (*grpcpb.GenericResponse, error) {
	switch req.Act {
	case grpcpb.ManageAction_START:
		if err := s.xrayService.StartOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to start Xray: %v", err)), nil
		}
		if err := s.applyXrayRouting(req.ChainName); err != nil {
			_ = s.xrayService.StopOne(req.ChainName)
			return errorGeneric(fmt.Sprintf("Failed to configure routing: %v", err)), nil
		}
		return successGeneric(fmt.Sprintf("Xray started successfully: %s", req.ChainName)), nil
	case grpcpb.ManageAction_STOP:
		if err := s.xrayService.StopOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to stop Xray: %v", err)), nil
		}
		if err := s.removeXrayRouting(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to cleanup routing: %v", err)), nil
		}
		return successGeneric(fmt.Sprintf("Xray stopped successfully: %s", req.ChainName)), nil
	case grpcpb.ManageAction_STATUS:
		if s.xrayService.IsRunning(req.ChainName) {
			return successGeneric(fmt.Sprintf("Xray is running: %s", req.ChainName)), nil
		}
		return errorGeneric(fmt.Sprintf("Xray is not running: %s", req.ChainName)), nil
	default:
		return errorGeneric("Unknown Xray management action"), nil
	}
}

func (s *VpnerServer) XraySetAutorun(ctx context.Context, req *grpcpb.XrayAutoRunRequest) (*grpcpb.GenericResponse, error) {
	if req.ChainName == "" {
		return errorGeneric("Chain name is required"), nil
	}
	if err := s.xrayManager.UpdateAutoRun(req.ChainName, req.AutoRun); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to update autorun: %v", err)), nil
	}
	state := "disabled"
	if req.AutoRun {
		state = "enabled"
	}
	return successGeneric(fmt.Sprintf("Xray autorun %s: %s", state, req.ChainName)), nil
}

func (s *VpnerServer) HookRestore(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.GenericResponse, error) {
	if s.xrayRouter != nil {
		s.xrayRouter.ResetState()
	}
	s.RestoreXrayRouting()
	return successGeneric("Routing restore triggered"), nil
}

func (s *VpnerServer) XrayCreate(ctx context.Context, req *grpcpb.XrayCreateRequest) (*grpcpb.GenericResponse, error) {
	name, err := s.xrayManager.CreateXray(req.Link, req.AutoRun)
	if err != nil {
		return errorGeneric(fmt.Sprintf("Failed to create Xray: %v", err)), nil
	}
	if req.AutoRun {
		if err := s.xrayService.StartOne(name); err != nil {
			return errorGeneric(fmt.Sprintf("Xray created as %s but failed to start: %v", name, err)), nil
		}
		if err := s.applyXrayRouting(name); err != nil {
			_ = s.xrayService.StopOne(name)
			return errorGeneric(fmt.Sprintf("Failed to configure routing: %v", err)), nil
		}
	}
	return successGeneric(fmt.Sprintf("Xray created successfully: %s", name)), nil
}

func (s *VpnerServer) XrayDelete(ctx context.Context, req *grpcpb.XrayRequest) (*grpcpb.GenericResponse, error) {
	if s.xrayService.IsRunning(req.ChainName) {
		if err := s.xrayService.StopOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to stop Xray: %v", err)), nil
		}
		if err := s.removeXrayRouting(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to cleanup routing: %v", err)), nil
		}
	}
	if err := s.xrayManager.DeleteXray(req.ChainName); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete Xray: %v", err)), nil
	}
	if err := s.unblock.DelChain("Xray", req.ChainName); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete unblock chain: %v", err)), nil
	}
	return successGeneric(fmt.Sprintf("Xray deleted successfully: %s", req.ChainName)), nil
}
