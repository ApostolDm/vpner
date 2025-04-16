package grpcserver

import (
	"context"
	"fmt"
	"sort"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *VpnerServer) InterfaceList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.InterfaceListResponse, error) {
	interfaces, err := s.ifManager.LoadInterfacesFromFile()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load interfaces: %v", err)
	}
	if len(interfaces.Interfaces) == 0 {
		return nil, status.Errorf(codes.Internal, "interfaces do not exist")
	}
	var result []*grpcpb.InterfaceInfo
	for id, iface := range interfaces.Interfaces {
		result = append(result, &grpcpb.InterfaceInfo{
			Id:          id,
			Type:        iface.Type,
			Description: iface.Description,
			Status:      returnIfStatus(iface.State),
		})
	}
	return &grpcpb.InterfaceListResponse{Interfaces: result}, nil
}

func (s *VpnerServer) InterfaceScan(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.InterfaceListResponse, error) {
	interfaceMan, err := s.ifManager.FetchInterfaces()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to scan interfaces: %v", err)
	}
	if len(interfaceMan) == 0 {
		return nil, status.Errorf(codes.Internal, "no interfaces found")
	}
	interfacesFile, err := s.ifManager.LoadInterfacesFromFile()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load saved interfaces: %v", err)
	}
	added := make(map[string]bool)
	for id := range interfacesFile.Interfaces {
		added[id] = true
	}
	var interfaces []*grpcpb.InterfaceInfo
	for id, iface := range interfaceMan {
		interfaces = append(interfaces, &grpcpb.InterfaceInfo{
			Id:          id,
			Type:        iface.Type,
			Description: iface.Description,
			Status:      returnIfStatus(iface.State),
			Added:       added[id],
		})
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Id < interfaces[j].Id
	})
	return &grpcpb.InterfaceListResponse{Interfaces: interfaces}, nil
}

func (s *VpnerServer) InterfaceAdd(ctx context.Context, req *grpcpb.InterfaceActionRequest) (*grpcpb.GenericResponse, error) {
	if req.Id == "" {
		return errorGeneric("interface id is required"), nil
	}
	if err := s.ifManager.AddInterface(req.Id); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to add interface: %v", err)), nil
	}
	return successGeneric(fmt.Sprintf("Interface added successfully: %s", req.Id)), nil
}

func (s *VpnerServer) InterfaceDel(ctx context.Context, req *grpcpb.InterfaceActionRequest) (*grpcpb.GenericResponse, error) {
	if req.Id == "" {
		return errorGeneric("interface id is required"), nil
	}
	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromRouter(req.Id)
	if exists {
		if err := s.unblock.DelChain(vpnType, req.Id); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to delete unblock chain: %v", err)), nil
		}
	}
	if err := s.ifManager.DeleteInterface(req.Id); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete interface: %v", err)), nil
	}
	return successGeneric(fmt.Sprintf("Interface deleted successfully: %s", req.Id)), nil
}
