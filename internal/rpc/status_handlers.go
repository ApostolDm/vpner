package rpc

import (
	"context"
	"time"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

func (s *VpnerServer) Status(_ context.Context, _ *grpcpb.Empty) (*grpcpb.StatusResponse, error) {
	resp := &grpcpb.StatusResponse{
		Version:       s.info.Version,
		UptimeSeconds: int64(time.Since(s.info.StartedAt).Seconds()),
		DnsRunning:    s.dns.IsRunning(),
		DnsPort:       int32(s.info.DNSPort),
		TproxyEnabled: s.info.TProxyEnabled,
	}

	runtimes := s.xrayService.Runtimes()
	listed := make(map[string]bool)
	if infos, err := s.xrayService.ListInfo(); err == nil {
		for name, info := range infos {
			listed[name] = true
			rt := runtimes[name]
			resp.Chains = append(resp.Chains, &grpcpb.ChainStatus{
				Name:          name,
				Type:          info.Type,
				Host:          info.Host,
				Port:          int32(info.Port),
				InboundPort:   int32(info.InboundPort),
				AutoRun:       info.AutoRun,
				Running:       rt.Running,
				Restarts:      int32(rt.Restarts),
				UptimeSeconds: int64(rt.Uptime.Seconds()),
				LastExit:      rt.LastExit,
			})
		}
	}

	for name, rt := range runtimes {
		if listed[name] {
			continue
		}
		resp.Chains = append(resp.Chains, &grpcpb.ChainStatus{
			Name:          name,
			Running:       rt.Running,
			Restarts:      int32(rt.Restarts),
			UptimeSeconds: int64(rt.Uptime.Seconds()),
			LastExit:      rt.LastExit,
		})
	}

	if groups, err := s.unblock.List(); err == nil {
		for _, g := range groups {
			resp.UnblockRuleCount += int32(len(g.Rules))
		}
	}

	for _, st := range s.dns.UpstreamStats() {
		resp.DohServers = append(resp.DohServers, &grpcpb.DohServerStatus{
			Server:        st.Server,
			Successes:     st.Successes,
			Failures:      st.Failures,
			LastLatencyMs: st.LastLatency.Milliseconds(),
		})
	}

	return resp, nil
}
