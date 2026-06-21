package resolver

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	"golang.org/x/sync/singleflight"
)

type upstreamState struct {
	server string

	lastLatency atomic.Int64
	successes   atomic.Uint64
	failures    atomic.Uint64

	mu          sync.RWMutex
	lastSuccess time.Time
	lastError   time.Time
}

type Upstream struct {
	config     conf.UpstreamConfig
	httpClient *http.Client

	cache   map[string]cachedEntry
	cacheMu sync.RWMutex

	sf      singleflight.Group
	servers []*upstreamState
	reqSem  chan struct{}

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewUpstream(cfg conf.UpstreamConfig) *Upstream {
	cfg = normalizeConfig(cfg)

	r := &Upstream{
		config: cfg,
		cache:  make(map[string]cachedEntry),
		reqSem: make(chan struct{}, cfg.MaxConcurrentRequests),
		stopCh: make(chan struct{}),
	}
	r.initServers()

	transport := &http.Transport{
		DialContext:           r.dialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   secs(cfg.TLSHandshakeTimeout),
		ResponseHeaderTimeout: secs(cfg.ResponseHeaderTimeout),
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
	}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	r.httpClient = &http.Client{
		Timeout:   secs(cfg.HTTPTimeout),
		Transport: transport,
	}

	r.wg.Add(1)
	go r.cleanupLoop()
	return r
}

func (r *Upstream) Close() {
	close(r.stopCh)
	r.wg.Wait()
	if tr, ok := r.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (r *Upstream) initServers() {
	r.servers = make([]*upstreamState, 0, len(r.config.Servers))
	for _, s := range r.config.Servers {
		r.servers = append(r.servers, &upstreamState{server: s})
	}
}

type ServerStat struct {
	Server      string
	Successes   uint64
	Failures    uint64
	LastLatency time.Duration
}

func (r *Upstream) ServerStats() []ServerStat {
	out := make([]ServerStat, 0, len(r.servers))
	for _, s := range r.servers {
		out = append(out, ServerStat{
			Server:      s.server,
			Successes:   s.successes.Load(),
			Failures:    s.failures.Load(),
			LastLatency: time.Duration(s.lastLatency.Load()),
		})
	}
	return out
}

func normalizeConfig(cfg conf.UpstreamConfig) conf.UpstreamConfig {
	setDefault(&cfg.CacheTTL, 300)
	setDefault(&cfg.StaleTTL, 300)
	setDefault(&cfg.HTTPTimeout, 8)
	setDefault(&cfg.DialTimeout, 5)
	setDefault(&cfg.TLSHandshakeTimeout, 5)
	setDefault(&cfg.ResponseHeaderTimeout, 5)
	setDefault(&cfg.BootstrapTimeout, 3)
	setDefault(&cfg.MaxCacheEntries, 2048)
	setDefault(&cfg.CleanupInterval, 60)
	setDefault(&cfg.MaxConcurrentRequests, 256)

	cfg.Servers = trimNonEmpty(cfg.Servers)
	cfg.Resolvers = trimNonEmpty(cfg.Resolvers)
	return cfg
}

func setDefault(v *int, def int) {
	if *v <= 0 {
		*v = def
	}
}

func secs(n int) time.Duration { return time.Duration(n) * time.Second }

func trimNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s == "" {
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
