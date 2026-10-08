package rpc

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/matcher"
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

type syncReport struct {
	staticEntries   int
	domainsTotal    int
	domainsResolved int
	ipsAdded        int
	failures        int
	errors          []string
}

const syncResolveWorkers = 8

func (s *VpnerServer) SyncRules(ctx context.Context, _ *grpcpb.Empty) (*grpcpb.GenericResponse, error) {
	report := s.resyncRules(ctx)
	debug.FreeOSMemory()

	msg := fmt.Sprintf(
		"Synced %d static entries; resolved %d/%d domains, added %d IPs",
		report.staticEntries, report.domainsResolved, report.domainsTotal, report.ipsAdded,
	)
	if report.failures > 0 {
		msg += fmt.Sprintf(" (%d failures)", report.failures)
	}
	if len(report.errors) > 0 {
		limit := len(report.errors)
		if limit > 5 {
			limit = 5
		}
		msg += ": " + strings.Join(report.errors[:limit], "; ")
		if len(report.errors) > limit {
			msg += fmt.Sprintf("; and %d more", len(report.errors)-limit)
		}
	}
	return successGeneric(msg), nil
}

func (s *VpnerServer) resyncRules(ctx context.Context) syncReport {
	var rep syncReport

	n, err := s.unblock.ResyncStaticEntries()
	rep.staticEntries = n
	if err != nil {
		rep.errors = append(rep.errors, fmt.Sprintf("static entries: %v", err))
	}

	hosts := s.resolvableHosts()
	rep.domainsTotal = len(hosts)
	if len(hosts) == 0 {
		return rep
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		jobs = make(chan string)
	)
	worker := func() {
		defer wg.Done()
		defer logx.Recover("resync worker")
		for host := range jobs {
			ips, err := s.upstream.Resolve(ctx, host)
			if err != nil {
				mu.Lock()
				rep.failures++
				rep.errors = append(rep.errors, fmt.Sprintf("%s: %v", host, err))
				mu.Unlock()
				continue
			}
			if len(ips) == 0 {
				continue
			}
			if err := s.ipRules.ResyncAnswers(host, ips); err != nil {
				mu.Lock()
				rep.failures++
				rep.errors = append(rep.errors, fmt.Sprintf("%s add: %v", host, err))
				mu.Unlock()
				continue
			}
			mu.Lock()
			rep.domainsResolved++
			rep.ipsAdded += len(ips)
			mu.Unlock()
		}
	}

	workers := syncResolveWorkers
	if workers > len(hosts) {
		workers = len(hosts)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

feed:
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- host:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		rep.errors = append(rep.errors, fmt.Sprintf("sync interrupted: %v", err))
	}
	return rep
}

func (s *VpnerServer) resolvableHosts() []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, group := range s.unblock.Groups() {
		for _, pattern := range group.Rules {
			host := resolvableHost(pattern)
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func resolvableHost(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || matcher.IsIP(pattern) || matcher.IsCIDR(pattern) {
		return ""
	}
	if !strings.Contains(pattern, "*") {
		return pattern
	}
	if strings.HasPrefix(pattern, "*.") && strings.Count(pattern, "*") == 1 {
		if host := strings.TrimPrefix(pattern, "*."); host != "" {
			return host
		}
	}
	return ""
}
