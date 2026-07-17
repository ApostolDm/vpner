package dnssvc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/matcher"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	unblock "github.com/ApostolDmitry/vpner/internal/unblock"
	"github.com/miekg/dns"
)

type Service struct {
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	done    chan struct{}
	mu      sync.Mutex

	server    *resolver.Server
	cfg       conf.ServerConfig
	ipManager *firewall.IpRuleManager
	resolver  *resolver.Upstream
	unblock   *unblock.Service
}

func New(cfg conf.ServerConfig, unblock *unblock.Service, resolver *resolver.Upstream, registry *firewall.IPSetRegistry) *Service {
	var ipManager *firewall.IpRuleManager
	if unblock != nil {
		ipManager = firewall.NewIpRuleManager(unblock, unblock.RuntimeOptions(), registry)
	}

	return &Service{
		cfg:       cfg,
		ipManager: ipManager,
		resolver:  resolver,
		unblock:   unblock,
	}
}

func (d *Service) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		logx.Debugf("DNS service already running")
		return nil
	}

	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.done = make(chan struct{})
	var syncer resolver.IPSyncer
	if d.ipManager != nil {
		syncer = d.ipManager
	}
	d.server = resolver.NewServer(d.cfg, syncer, d.resolver)
	started := make(chan struct{})
	errCh := make(chan error, 1)
	d.server.SetNotifyStartedFunc(func() {
		select {
		case <-started:
		default:
			close(started)
		}
	})

	go func() {
		defer close(d.done)
		if err := d.server.Run(d.ctx); err != nil {
			logx.Errorf("DNS server exited: %v", err)
			select {
			case errCh <- err:
			default:
			}
		}
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	select {
	case err := <-errCh:
		d.cancel()
		d.cancel = nil
		return fmt.Errorf("dns server failed to start: %w", err)
	case <-started:
		d.running = true
		logx.Infof("DNS server listening on :%d", d.cfg.Port)
	case <-time.After(2 * time.Second):
		d.running = true
		logx.Warnf("DNS server start confirmation timeout; assuming running on :%d", d.cfg.Port)
	}

	return nil
}

func (d *Service) Stop() {
	d.mu.Lock()
	done := d.done
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
		logx.Infof("DNS server shutdown requested")
	}
	d.running = false
	d.mu.Unlock()

	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			logx.Warnf("DNS server shutdown timed out after 5s")
		}
	}
}

func (d *Service) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

func (d *Service) UpstreamStats() []resolver.ServerStat {
	if d.resolver == nil {
		return nil
	}
	return d.resolver.ServerStats()
}

func (d *Service) QueryStats() resolver.QueryStats {
	d.mu.Lock()
	srv := d.server
	d.mu.Unlock()
	if srv == nil {
		return resolver.QueryStats{}
	}
	return srv.Stats()
}

type SyncReport struct {
	StaticEntries   int
	DomainsTotal    int
	DomainsResolved int
	IPsAdded        int
	Failures        int
	Errors          []string
}

const syncResolveWorkers = 8

func (d *Service) ResyncRules(ctx context.Context) (SyncReport, error) {
	var rep SyncReport
	if d.ipManager == nil {
		return rep, fmt.Errorf("routing is not configured; nothing to sync")
	}

	if d.unblock != nil {
		n, err := d.unblock.ResyncStatic()
		rep.StaticEntries = n
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("static entries: %v", err))
		}
	}

	hosts := d.resolvableHosts()
	rep.DomainsTotal = len(hosts)
	if len(hosts) == 0 || d.resolver == nil {
		return rep, nil
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
			ips, err := d.resolveHostIPs(ctx, host)
			mu.Lock()
			if err != nil {
				rep.Failures++
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", host, err))
				mu.Unlock()
				continue
			}
			mu.Unlock()
			if len(ips) == 0 {
				continue
			}
			if err := d.ipManager.ResyncAnswers(host, ips); err != nil {
				mu.Lock()
				rep.Failures++
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s add: %v", host, err))
				mu.Unlock()
				continue
			}
			mu.Lock()
			rep.DomainsResolved++
			rep.IPsAdded += len(ips)
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
		rep.Errors = append(rep.Errors, fmt.Sprintf("sync interrupted: %v", err))
	}
	return rep, nil
}

func (d *Service) resolvableHosts() []string {
	if d.unblock == nil {
		return nil
	}
	groups, err := d.unblock.List()
	if err != nil {
		logx.Warnf("resync: failed to list rules: %v", err)
		return nil
	}
	seen := make(map[string]struct{})
	var hosts []string
	for _, group := range groups {
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
	if pattern == "" {
		return ""
	}
	if matcher.IsIP(pattern) || matcher.IsCIDR(pattern) {
		return ""
	}
	if !strings.Contains(pattern, "*") {
		return pattern
	}
	if strings.HasPrefix(pattern, "*.") && strings.Count(pattern, "*") == 1 {
		host := strings.TrimPrefix(pattern, "*.")
		if host != "" && !strings.Contains(host, "*") {
			return host
		}
	}
	return ""
}

func (d *Service) resolveHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	var lastErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if err := ctx.Err(); err != nil {
			return ips, err
		}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), qtype)
		msg.RecursionDesired = true
		packed, err := msg.Pack()
		if err != nil {
			lastErr = err
			continue
		}
		respBytes, err := d.resolver.ForwardQuery(packed)
		if err != nil {
			lastErr = err
			continue
		}
		var resp dns.Msg
		if err := resp.Unpack(respBytes); err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, answerIPs(&resp)...)
	}
	if len(ips) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return ips, nil
}

func answerIPs(msg *dns.Msg) []net.IP {
	var ips []net.IP
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if record.A != nil {
				ips = append(ips, record.A)
			}
		case *dns.AAAA:
			if record.AAAA != nil {
				ips = append(ips, record.AAAA)
			}
		}
	}
	return ips
}
