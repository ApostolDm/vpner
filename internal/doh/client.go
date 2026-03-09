package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logging"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type cachedEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
	StaleAt   time.Time
}

type ResolverConfig struct {
	Servers            []string `yaml:"servers"`
	Resolvers          []string `yaml:"resolvers"`
	CacheTTL           int      `yaml:"cache-ttl"`
	Verbose            bool     `yaml:"verbose"`
	InsecureSkipVerify bool     `yaml:"insecure-skip-verify"`

	HTTPTimeout           int  `yaml:"http-timeout"`
	DialTimeout           int  `yaml:"dial-timeout"`
	TLSHandshakeTimeout   int  `yaml:"tls-handshake-timeout"`
	ResponseHeaderTimeout int  `yaml:"response-header-timeout"`
	BootstrapTimeout      int  `yaml:"bootstrap-timeout"`
	MaxCacheEntries       int  `yaml:"max-cache-entries"`
	StaleTTL              int  `yaml:"stale-ttl"`
	CleanupInterval       int  `yaml:"cleanup-interval"`
	MaxConcurrentRequests int  `yaml:"max-concurrent-requests"`
	PreferIPv6            bool `yaml:"prefer-ipv6"`
}

type serverStat struct {
	Server      string
	LastLatency time.Duration
	LastSuccess time.Time
	LastError   time.Time
	Successes   uint64
	Failures    uint64
}

type serverState struct {
	server string

	lastLatency atomic.Int64
	successes   atomic.Uint64
	failures    atomic.Uint64

	mu          sync.RWMutex
	lastSuccess time.Time
	lastError   time.Time
}

type Resolver struct {
	config ResolverConfig

	httpClient *http.Client

	cache   map[string]cachedEntry
	cacheMu sync.RWMutex

	sf singleflight.Group

	servers []*serverState

	reqSem chan struct{}

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewResolver(cfg ResolverConfig) *Resolver {
	cfg = normalizeConfig(cfg)

	r := &Resolver{
		config: cfg,
		cache:  make(map[string]cachedEntry),
		stopCh: make(chan struct{}),
	}

	r.reqSem = make(chan struct{}, cfg.MaxConcurrentRequests)

	r.initServers()

	transport := &http.Transport{
		DialContext:           r.dialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   time.Duration(cfg.TLSHandshakeTimeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.ResponseHeaderTimeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
	}

	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	r.httpClient = &http.Client{
		Timeout:   time.Duration(cfg.HTTPTimeout) * time.Second,
		Transport: transport,
	}

	r.wg.Add(1)
	go r.cleanupLoop()

	return r
}

func (r *Resolver) Close() {
	close(r.stopCh)
	r.wg.Wait()

	if tr, ok := r.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func normalizeConfig(cfg ResolverConfig) ResolverConfig {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 300
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 300
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 8
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		cfg.TLSHandshakeTimeout = 5
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = 5
	}
	if cfg.BootstrapTimeout <= 0 {
		cfg.BootstrapTimeout = 3
	}
	if cfg.MaxCacheEntries <= 0 {
		cfg.MaxCacheEntries = 2048
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 60
	}
	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 256
	}

	cfg.Servers = trimNonEmpty(cfg.Servers)
	cfg.Resolvers = trimNonEmpty(cfg.Resolvers)

	return cfg
}

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))

	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}

func (r *Resolver) initServers() {
	r.servers = make([]*serverState, 0, len(r.config.Servers))
	for _, s := range r.config.Servers {
		r.servers = append(r.servers, &serverState{server: s})
	}
}

func (r *Resolver) cleanupLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(time.Duration(r.config.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupCache()
		case <-r.stopCh:
			return
		}
	}
}

func (r *Resolver) cleanupCache() {
	now := time.Now()

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	for host, entry := range r.cache {
		if now.After(entry.StaleAt) {
			delete(r.cache, host)
		}
	}
}

func (r *Resolver) GetServerStats() []serverStat {
	stats := make([]serverStat, 0, len(r.servers))

	for _, s := range r.servers {
		s.mu.RLock()
		stats = append(stats, serverStat{
			Server:      s.server,
			LastLatency: time.Duration(s.lastLatency.Load()),
			LastSuccess: s.lastSuccess,
			LastError:   s.lastError,
			Successes:   s.successes.Load(),
			Failures:    s.failures.Load(),
		})
		s.mu.RUnlock()
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Successes == stats[j].Successes {
			return stats[i].LastLatency < stats[j].LastLatency
		}
		return stats[i].Successes > stats[j].Successes
	})

	return stats
}

func (r *Resolver) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(r.config.DialTimeout) * time.Second,
	}

	if ip := net.ParseIP(host); ip != nil {
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := r.resolveHost(host)
	if err != nil {
		return nil, err
	}

	ips = r.sortIPsForDial(ips)

	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), port)

		conn, err := dialer.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}

		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("no bootstrap IPs available")
	}

	return nil, fmt.Errorf("all bootstrap IPs failed for %s: %w", host, lastErr)
}

func (r *Resolver) sortIPsForDial(ips []net.IP) []net.IP {
	out := cloneIPs(ips)

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})

	sort.SliceStable(out, func(i, j int) bool {
		i6 := isIPv6(out[i])
		j6 := isIPv6(out[j])

		if r.config.PreferIPv6 {
			if i6 != j6 {
				return i6
			}
			return false
		}

		if i6 != j6 {
			return !i6
		}
		return false
	})

	return out
}

func (r *Resolver) ForwardQuery(query []byte) ([]byte, error) {
	if len(r.servers) == 0 {
		return nil, errors.New("no DoH servers configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.config.HTTPTimeout)*time.Second)
	defer cancel()

	type result struct {
		server *serverState
		resp   []byte
		err    error
	}

	ch := make(chan result, len(r.servers))
	orderedServers := r.orderServers()

	launched := 0
	for _, s := range orderedServers {
		launched++

		go func(s *serverState) {
			start := time.Now()
			resp, err := r.forwardToServer(ctx, s.server, query)
			latency := time.Since(start)

			r.updateServerStat(s, latency, err)

			select {
			case ch <- result{server: s, resp: resp, err: err}:
			case <-ctx.Done():
			}
		}(s)
	}

	var errs []string

	for i := 0; i < launched; i++ {
		select {
		case res := <-ch:
			if res.err == nil {
				logging.Debugf("doh server %s won race in %s", res.server.server, time.Duration(res.server.lastLatency.Load()))
				return res.resp, nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", res.server.server, res.err))
		case <-ctx.Done():
			if len(errs) > 0 {
				return nil, fmt.Errorf("doh timeout: %s", strings.Join(errs, "; "))
			}
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all DoH servers failed: %s", strings.Join(errs, "; "))
}

func (r *Resolver) orderServers() []*serverState {
	out := make([]*serverState, 0, len(r.servers))
	out = append(out, r.servers...)

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})

	sort.SliceStable(out, func(i, j int) bool {
		li := time.Duration(out[i].lastLatency.Load())
		lj := time.Duration(out[j].lastLatency.Load())

		si := out[i].successes.Load()
		sj := out[j].successes.Load()

		fi := out[i].failures.Load()
		fj := out[j].failures.Load()

		if si != sj {
			return si > sj
		}
		if fi != fj {
			return fi < fj
		}
		if li == 0 && lj != 0 {
			return true
		}
		if lj == 0 && li != 0 {
			return false
		}
		return li < lj
	})

	return out
}

func (r *Resolver) updateServerStat(s *serverState, latency time.Duration, err error) {
	s.lastLatency.Store(latency.Nanoseconds())

	s.mu.Lock()
	defer s.mu.Unlock()

	if err == nil {
		s.successes.Add(1)
		s.lastSuccess = time.Now()
		return
	}

	s.failures.Add(1)
	s.lastError = time.Now()
}

func (r *Resolver) forwardToServer(ctx context.Context, serverURL string, query []byte) ([]byte, error) {
	select {
	case r.reqSem <- struct{}{}:
		defer func() { <-r.reqSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH url %q: %w", serverURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "vpner-dohclient/1.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}

	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if contentType != "" && !strings.Contains(contentType, "application/dns-message") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("unexpected content-type %q: %q", contentType, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("empty DoH response")
	}

	var msg dns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("invalid dns message in DoH response: %w", err)
	}

	return body, nil
}

func (r *Resolver) resolveHost(host string) ([]net.IP, error) {
	now := time.Now()

	r.cacheMu.RLock()
	entry, ok := r.cache[host]
	r.cacheMu.RUnlock()

	if ok && now.Before(entry.ExpiresAt) {
		return cloneIPs(entry.IPs), nil
	}

	v, err, _ := r.sf.Do(host, func() (interface{}, error) {
		now := time.Now()

		r.cacheMu.RLock()
		entry, ok := r.cache[host]
		r.cacheMu.RUnlock()

		if ok && now.Before(entry.ExpiresAt) {
			return cloneIPs(entry.IPs), nil
		}

		ips, ttl, err := r.resolveHostUncached(host)
		if err != nil {
			if ok && now.Before(entry.StaleAt) && len(entry.IPs) > 0 {
				logging.Warnf("bootstrap resolve failed for %s, serving stale cache: %v", host, err)
				return cloneIPs(entry.IPs), nil
			}
			return nil, err
		}

		r.storeCache(host, ips, ttl)
		return cloneIPs(ips), nil
	})
	if err != nil {
		return nil, err
	}

	ips, ok := v.([]net.IP)
	if !ok {
		return nil, errors.New("invalid singleflight result")
	}

	return ips, nil
}

func (r *Resolver) resolveHostUncached(host string) ([]net.IP, time.Duration, error) {
	var errs []string
	bestTTL := time.Duration(r.config.CacheTTL) * time.Second

	for _, resolver := range r.config.Resolvers {
		ips, ttl, err := r.queryBootstrap(resolver, host)
		if err == nil && len(ips) > 0 {
			if ttl <= 0 {
				ttl = bestTTL
			}
			return ips, ttl, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", resolver, err))
		}
	}

	if len(errs) == 0 {
		return nil, 0, errors.New("bootstrap resolvers failed")
	}

	return nil, 0, fmt.Errorf("bootstrap resolvers failed: %s", strings.Join(errs, "; "))
}

func (r *Resolver) queryBootstrap(resolver, host string) ([]net.IP, time.Duration, error) {
	type answer struct {
		ips []net.IP
		ttl time.Duration
		err error
	}

	aCh := make(chan answer, 1)
	aaaaCh := make(chan answer, 1)

	go func() {
		ips, ttl, err := r.queryType(resolver, host, dns.TypeA)
		aCh <- answer{ips: ips, ttl: ttl, err: err}
	}()

	go func() {
		ips, ttl, err := r.queryType(resolver, host, dns.TypeAAAA)
		aaaaCh <- answer{ips: ips, ttl: ttl, err: err}
	}()

	aRes := <-aCh
	aaaaRes := <-aaaaCh

	var ips []net.IP
	var ttl time.Duration

	if aRes.err == nil {
		ips = append(ips, aRes.ips...)
		ttl = pickTTL(ttl, aRes.ttl)
	}
	if aaaaRes.err == nil {
		ips = append(ips, aaaaRes.ips...)
		ttl = pickTTL(ttl, aaaaRes.ttl)
	}

	ips = dedupeIPs(ips)
	if len(ips) > 0 {
		if ttl <= 0 {
			ttl = time.Duration(r.config.CacheTTL) * time.Second
		}
		return ips, ttl, nil
	}

	if aRes.err != nil && aaaaRes.err != nil {
		return nil, 0, fmt.Errorf("A failed: %v; AAAA failed: %v", aRes.err, aaaaRes.err)
	}

	return nil, 0, errors.New("no A/AAAA records")
}

func pickTTL(current, next time.Duration) time.Duration {
	if next <= 0 {
		return current
	}
	if current <= 0 {
		return next
	}
	if next < current {
		return next
	}
	return current
}

func (r *Resolver) queryType(resolver, host string, qtype uint16) ([]net.IP, time.Duration, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return nil, 0, errors.New("resolver is empty")
	}

	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	timeout := time.Duration(r.config.BootstrapTimeout) * time.Second

	resp, err := r.exchangeDNS("udp", resolver, msg, timeout)
	if err != nil {
		resp, err = r.exchangeDNS("tcp", resolver, msg, timeout)
		if err != nil {
			return nil, 0, err
		}
	}

	if resp == nil {
		return nil, 0, errors.New("nil dns response")
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var (
		ips    []net.IP
		minTTL uint32
	)

	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, rr.A)
				minTTL = minTTL32(minTTL, rr.Hdr.Ttl)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, rr.AAAA)
				minTTL = minTTL32(minTTL, rr.Hdr.Ttl)
			}
		}
	}

	if len(ips) == 0 {
		return nil, 0, errors.New("no records")
	}

	ttl := normalizeTTL(minTTL, r.config.CacheTTL)
	return dedupeIPs(ips), ttl, nil
}

func (r *Resolver) exchangeDNS(network, resolver string, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func normalizeTTL(ttl uint32, fallbackSeconds int) time.Duration {
	if ttl == 0 {
		return time.Duration(fallbackSeconds) * time.Second
	}

	d := time.Duration(ttl) * time.Second

	minTTL := 30 * time.Second
	maxTTL := time.Duration(fallbackSeconds) * time.Second

	if maxTTL < minTTL {
		maxTTL = minTTL
	}

	if d < minTTL {
		return minTTL
	}
	if d > maxTTL {
		return maxTTL
	}
	return d
}

func minTTL32(current, next uint32) uint32 {
	if next == 0 {
		return current
	}
	if current == 0 || next < current {
		return next
	}
	return current
}

func (r *Resolver) ResolveDomain(domain string, qtype uint16) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	respData, err := r.ForwardQuery(packed)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, rr.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, rr.AAAA)
			}
		}
	}

	ips = dedupeIPs(ips)
	if len(ips) == 0 {
		return nil, errors.New("no records in DoH response")
	}

	return ips, nil
}

func (r *Resolver) ResolveA(domain string) ([]net.IP, error) {
	return r.ResolveDomain(domain, dns.TypeA)
}

func (r *Resolver) ResolveAAAA(domain string) ([]net.IP, error) {
	return r.ResolveDomain(domain, dns.TypeAAAA)
}

func (r *Resolver) storeCache(host string, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Duration(r.config.CacheTTL) * time.Second
	}

	staleTTL := time.Duration(r.config.StaleTTL) * time.Second
	now := time.Now()

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if len(r.cache) >= r.config.MaxCacheEntries {
		r.evictExpiredLocked(now)
	}
	if len(r.cache) >= r.config.MaxCacheEntries {
		r.evictOneLocked()
	}

	r.cache[host] = cachedEntry{
		IPs:       cloneIPs(ips),
		ExpiresAt: now.Add(ttl),
		StaleAt:   now.Add(ttl + staleTTL),
	}
}

func (r *Resolver) evictExpiredLocked(now time.Time) {
	for host, entry := range r.cache {
		if now.After(entry.StaleAt) {
			delete(r.cache, host)
		}
	}
}

func (r *Resolver) evictOneLocked() {
	for host := range r.cache {
		delete(r.cache, host)
		return
	}
}

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		cp := make(net.IP, len(ip))
		copy(cp, ip)
		out = append(out, cp)
	}
	return out
}

func dedupeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}

	return out
}

func isIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}
