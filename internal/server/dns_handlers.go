package grpcserver

import (
	"context"
	"fmt"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

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
