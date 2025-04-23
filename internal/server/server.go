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
	ss        *SSService
	unblock   *network.UnblockManager
	resolver  *dohclient.Resolver
	ifManager *interface_manager.Manager
	ssManger  *network.SsManager
}

func (s *VpnerServer) DnsManage(ctx context.Context, req *grpcpb.ManageRequest) (*grpcpb.GenericResponse, error) {
	switch req.Act {
	case grpcpb.ManageAction_START:
		if err := s.dns.Start(); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to start DNS server: %v", err)), nil
		}
		return successGeneric("DNS server started successfully"), nil
	case grpcpb.ManageAction_STOP:
		s.dns.Stop()
		return successGeneric("DNS server stopped successfully"), nil
	case grpcpb.ManageAction_STATUS:
		status := "DOWN"
		if s.dns.IsRunning() {
			status = "RUNNING"
		}
		return successGeneric(fmt.Sprintf("DNS server status: %s", status)), nil
	case grpcpb.ManageAction_RESTART:
		s.dns.Stop()
		if err := s.dns.Start(); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to restart DNS server: %v", err)), nil
		}
		return successGeneric("DNS server restarted successfully"), nil
	default:
		return errorGeneric("Unknown DNS management action"), nil
	}
}

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
	if err := utils.ValidatePattern(req.Domain); err != nil {
		return errorGeneric(fmt.Sprintf("Invalid pattern: %v", err)), nil
	}
	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromVpner(req.ChainName)
	if !exists {
		return errorGeneric(fmt.Sprintf("Chain name '%s' does not exist", req.ChainName)), nil
	}
	allRules, err := s.unblock.GetAllRules()
	if err != nil {
		return errorGeneric("Failed to load existing rules"), nil
	}
	for typ, setPtr := range allRules.RuleMap() {
		for chain, rules := range *setPtr {
			for _, existing := range rules {
				if utils.PatternsOverlap(existing, req.Domain) {
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
	if err := utils.ValidatePattern(req.Domain); err != nil {
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
	return &grpcpb.InterfaceListResponse{Interfaces: interfaces}, nil
}

func (s *VpnerServer) InterfaceAdd(ctx context.Context, req *grpcpb.InterfaceActionRequest) (*grpcpb.GenericResponse, error) {
	if err := s.ifManager.AddInterface(req.Id); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to add interface: %v", err)), nil
	}
	return successGeneric(fmt.Sprintf("Interface added successfully: %s", req.Id)), nil
}

func (s *VpnerServer) InterfaceDel(ctx context.Context, req *grpcpb.InterfaceActionRequest) (*grpcpb.GenericResponse, error) {
	vpnType, exists := s.ifManager.GetInterfaceTypeByNameFromRouter(req.Id)
	if exists {
		s.unblock.DelChain(vpnType, req.Id)
	}
	return successGeneric(fmt.Sprintf("Interface deleted successfully: %s", req.Id)), nil
}

func (s *VpnerServer) SSCreate(ctx context.Context, req *grpcpb.SSInfo) (*grpcpb.GenericResponse, error) {
	if err := s.ssManger.CreateSS(network.SSminConfig{
		Host:       req.Host,
		ServerPort: int(req.Port),
		Mode:       req.Mode,
		Password:   req.Password,
		Method:     req.Method,
		AutoRun:    req.AutoRun,
	}); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to create SS: %v", err)), nil
	}
	return successGeneric(fmt.Sprintf("SS created successfully: %s", req.Host)), nil
}
func (s *VpnerServer) SSDelete(ctx context.Context, req *grpcpb.SSDeleteRequest) (*grpcpb.GenericResponse, error) {
	if err := s.ssManger.DeleteSS(req.ChainName); err != nil {
		return errorGeneric(fmt.Sprintf("Failed to delete SS: %v", err)), nil
	}
	var errors []string
	if err := s.unblock.DelChain("Shadowsocks", req.ChainName); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to delete unblock chain: %v", err))
	}
	if err := s.ifManager.DeleteInterface(req.ChainName); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to delete interface: %v", err))
	}
	if len(errors) > 0 {
		return errorGeneric(fmt.Sprintf("Errors occurred: %v", errors)), nil
	}
	return successGeneric(fmt.Sprintf("SS deleted successfully: %s", req.ChainName)), nil
}

func (s *VpnerServer) SSList(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.SSListResponse, error) {
	ssList := s.ssManger.GetAll()
	if len(ssList) == 0 {
		return nil, status.Errorf(codes.Internal, "no SS configurations found")
	}
	var ssConfigs []*grpcpb.SSCreateWithChainRequest
	for name, config := range ssList {
		ssConfigs = append(ssConfigs, &grpcpb.SSCreateWithChainRequest{
			ChainName: name,
			Ss: &grpcpb.SSInfo{
				Host:     config.Host,
				Port:     int32(config.ServerPort),
				Mode:     config.Mode,
				Password: config.Password,
				Method:   config.Method,
				AutoRun:  config.AutoRun,
			},
		})
	}
	sort.Slice(ssConfigs, func(i, j int) bool {
		return ssConfigs[i].ChainName < ssConfigs[j].ChainName
	})
	return &grpcpb.SSListResponse{List: ssConfigs}, nil
}

func (s *VpnerServer) SSManage(ctx context.Context, req *grpcpb.SSManageRequest) (*grpcpb.GenericResponse, error) {
	switch req.Act {
	case grpcpb.ManageAction_START:
		if err := s.ss.StartOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to start SS: %v", err)), nil
		}
		return successGeneric(fmt.Sprintf("SS started successfully: %s", req.ChainName)), nil
	case grpcpb.ManageAction_STOP:
		if err := s.ss.StopOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to stop SS: %v", err)), nil
		}
		return successGeneric(fmt.Sprintf("SS stopped successfully: %s", req.ChainName)), nil
	case grpcpb.ManageAction_STATUS:
		IsRunning := s.ss.IsRunning(req.ChainName)
		if IsRunning {
			return successGeneric(fmt.Sprintf("SS is running: %s", req.ChainName)), nil
		}
		return errorGeneric(fmt.Sprintf("SS is not running: %s", req.ChainName)), nil
	case grpcpb.ManageAction_RESTART:
		if err := s.ss.RestartOne(req.ChainName); err != nil {
			return errorGeneric(fmt.Sprintf("Failed to restart SS: %v", err)), nil
		}
		return successGeneric(fmt.Sprintf("SS restarted successfully: %s", req.ChainName)), nil
	default:
		return errorGeneric("Unknown SS management action"), nil
	}
}

func returnIfStatus(status string) grpcpb.InterfaceInfo_State {
	switch status {
	case "up":
		return grpcpb.InterfaceInfo_UP
	case "down":
		return grpcpb.InterfaceInfo_DOWN
	default:
		return grpcpb.InterfaceInfo_UNKNOWN
	}
}

func successGeneric(msg string) *grpcpb.GenericResponse {
	return &grpcpb.GenericResponse{
		Result: &grpcpb.GenericResponse_Success{
			Success: &grpcpb.Success{Message: msg},
		},
	}
}

func errorGeneric(msg string) *grpcpb.GenericResponse {
	return &grpcpb.GenericResponse{
		Result: &grpcpb.GenericResponse_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}
