package server

import (
	"context"
	"fmt"
	"sort"

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
			return errorResponse(fmt.Sprintf("Failed to start DNS server: %v", err)), nil
		}
		return successResponse("DNS server started successfully"), nil

	case grpcpb.DnsManageResponse_STOP:
		s.dns.Stop()
		return successResponse("DNS server stopped successfully"), nil

	case grpcpb.DnsManageResponse_STATUS:
		status := "DOWN"
		if s.dns.IsRunning() {
			status = "RUNNING"
		}
		return successResponse(fmt.Sprintf("DNS server status: %s", status)), nil

	case grpcpb.DnsManageResponse_RESTART:
		s.dns.Stop()
		if err := s.dns.Start(); err != nil {
			return errorResponse(fmt.Sprintf("Failed to restart DNS server: %v", err)), nil
		}
		return successResponse("DNS server restarted successfully"), nil

	default:
		return errorResponse("Unknown DNS management action"), nil
	}
}

func (s *VpnerServer) UnblockList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.UnblockListRequest, error) {
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

	return &grpcpb.UnblockListRequest{Rules: result}, nil
}

func (s *VpnerServer) UnblockAdd(ctx context.Context, req *grpcpb.UnblockAddResponse) (*grpcpb.UnblockAddRequest, error) {
	if req.ChainName == "" {
		return errorAddResponse("Chain name is required"), nil
	}
	if err := utils.ValidatePattern(req.Domain); err != nil {
		return errorAddResponse(fmt.Sprintf("Invalid pattern: %v", err)), nil
	}

	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromVpner(req.ChainName)
	if !exists {
		return errorAddResponse(fmt.Sprintf("Chain name '%s' does not exist", req.ChainName)), nil
	}

	allRules, err := s.unblock.GetAllRules()
	if err != nil {
		return errorAddResponse("Failed to load existing rules"), nil
	}

	for typ, setPtr := range allRules.RuleMap() {
		for chain, rules := range *setPtr {
			for _, existing := range rules {
				if utils.PatternsOverlap(existing, req.Domain) {
					return errorAddResponse(fmt.Sprintf(
						"New rule '%s' overlaps with existing rule '%s' in [%s/%s]",
						req.Domain, existing, typ, chain,
					)), nil
				}
			}
		}
	}

	if err := s.unblock.AddRule(vpnType, req.ChainName, req.Domain); err != nil {
		return errorAddResponse("Failed to add rule"), nil
	}

	return successAddResponse("Rule added successfully"), nil
}

func (s *VpnerServer) UnblockDel(ctx context.Context, req *grpcpb.UnblockDelResponse) (*grpcpb.UnblockDelRequest, error) {
	if err := utils.ValidatePattern(req.Domain); err != nil {
		return errorDelResponse(fmt.Sprintf("Invalid pattern: %v", err)), nil
	}

	vpnType, chainName, exists := s.unblock.MatchDomain(req.Domain)
	if !exists {
		return errorDelResponse("Rule does not exist"), nil
	}

	if err := s.unblock.DelRule(vpnType, chainName, req.Domain); err != nil {
		return errorDelResponse("Failed to delete rule"), nil
	}

	return successDelResponse("Rule deleted successfully"), nil
}

func (s *VpnerServer) InterfaceList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.InterfaceMap, error) {
	interfaces, err := s.ifManager.LoadInterfacesFromFile()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed read load Interfaces: %v", err)
	}
	if len(interfaces.Interfaces) == 0 {
		return nil, status.Errorf(codes.Internal, "interfaces does not exits: %v", err)
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
	return &grpcpb.InterfaceMap{Interfaces: result}, nil
}

func (s *VpnerServer) InterfaceScan(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.InterfaceMap, error) {
	interfaceMan, err := s.ifManager.FetchInterfaces()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed read load Interfaces: %v", err)
	}
	if len(interfaceMan) == 0 {
		return nil, status.Errorf(codes.Internal, "interfaces does not exits: %v", err)
	}
	interfacesFile, err := s.ifManager.LoadInterfacesFromFile()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed read load Interfaces: %v", err)
	}
	added := make(map[string]bool)
	for id := range interfacesFile.Interfaces {
		added[id] = true
	}
	var interfaces []*grpcpb.InterfaceInfo
	for id, iface := range interfaceMan {
		_, isAdded := added[id]
		interfaces = append(interfaces, &grpcpb.InterfaceInfo{
			Id:          id,
			Type:        iface.Type,
			Description: iface.Description,
			Status:      returnIfStatus(iface.State),
			Added:       isAdded,
		})
	}
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Id < interfaces[j].Id
	})

	return &grpcpb.InterfaceMap{Interfaces: interfaces}, nil
}

func (s *VpnerServer) InterfaceAdd(ctx context.Context, req *grpcpb.InterfaceResponse) (*grpcpb.InterfaceRequest, error) {
	err := s.ifManager.AddInterface(req.Id)
	if err != nil {
		return errorInterfaceResponse(fmt.Sprintf("Failed to add interface: %v", err)), nil
	}
	return &grpcpb.InterfaceRequest{
		Result: &grpcpb.InterfaceRequest_Success{
			Success: &grpcpb.Success{Message: fmt.Sprintf("Interface added successfully: %s", req.Id)},
		},
	}, nil
}

func (s *VpnerServer) InterfaceDel(ctx context.Context, req *grpcpb.InterfaceResponse) (*grpcpb.InterfaceRequest, error) {
	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromRouter(req.Id)
	if exists {
		s.unblock.DelChain(vpnType, req.Id)
	}
	return &grpcpb.InterfaceRequest{
		Result: &grpcpb.InterfaceRequest_Success{
			Success: &grpcpb.Success{Message: fmt.Sprintf("Interface deleted successfully: %s", req.Id)},
		},
	}, nil
}

func returnIfStatus(status string) grpcpb.InterfaceInfoState {
	switch status {
	case "up":
		return grpcpb.InterfaceInfo_UP
	case "down":
		return grpcpb.InterfaceInfo_DOWN
	default:
		return grpcpb.InterfaceInfo_UNKNOWN
	}
}
func successResponse(msg string) *grpcpb.DnsManageRequest {
	return &grpcpb.DnsManageRequest{
		Result: &grpcpb.DnsManageRequest_Success{
			Success: &grpcpb.Success{Message: msg},
		},
	}
}

func errorResponse(msg string) *grpcpb.DnsManageRequest {
	return &grpcpb.DnsManageRequest{
		Result: &grpcpb.DnsManageRequest_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}

func successAddResponse(msg string) *grpcpb.UnblockAddRequest {
	return &grpcpb.UnblockAddRequest{
		Result: &grpcpb.UnblockAddRequest_Success{
			Success: &grpcpb.Success{Message: msg},
		},
	}
}

func errorAddResponse(msg string) *grpcpb.UnblockAddRequest {
	return &grpcpb.UnblockAddRequest{
		Result: &grpcpb.UnblockAddRequest_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}

func successDelResponse(msg string) *grpcpb.UnblockDelRequest {
	return &grpcpb.UnblockDelRequest{
		Result: &grpcpb.UnblockDelRequest_Success{
			Success: &grpcpb.Success{Message: msg},
		},
	}
}

func errorDelResponse(msg string) *grpcpb.UnblockDelRequest {
	return &grpcpb.UnblockDelRequest{
		Result: &grpcpb.UnblockDelRequest_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}

func errorInterfaceResponse(msg string) *grpcpb.InterfaceRequest {
	return &grpcpb.InterfaceRequest{
		Result: &grpcpb.InterfaceRequest_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}
