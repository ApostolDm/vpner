package rpc

import (
	"context"
	"fmt"
	"strings"

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

func (s *VpnerServer) SyncRules(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.GenericResponse, error) {
	report, err := s.dns.ResyncRules(ctx)
	if err != nil {
		return errorGeneric(fmt.Sprintf("Failed to sync rules: %v", err)), nil
	}

	msg := fmt.Sprintf(
		"Synced %d static entries; resolved %d/%d domains, added %d IPs",
		report.StaticEntries, report.DomainsResolved, report.DomainsTotal, report.IPsAdded,
	)
	if report.Failures > 0 {
		msg += fmt.Sprintf(" (%d failures)", report.Failures)
	}
	if len(report.Errors) > 0 {
		limit := len(report.Errors)
		if limit > 5 {
			limit = 5
		}
		msg += ": " + strings.Join(report.Errors[:limit], "; ")
		if len(report.Errors) > limit {
			msg += fmt.Sprintf("; and %d more", len(report.Errors)-limit)
		}
	}
	return successGeneric(msg), nil
}
