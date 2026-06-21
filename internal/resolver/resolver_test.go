package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
)

func TestNormalizeConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := normalizeConfig(conf.UpstreamConfig{
		Servers:   []string{" https://a/dns-query ", "https://a/dns-query", ""},
		Resolvers: []string{"1.1.1.1", "1.1.1.1"},
	})
	if cfg.CacheTTL != 300 || cfg.HTTPTimeout != 8 || cfg.MaxConcurrentRequests != 256 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0] != "https://a/dns-query" {
		t.Fatalf("servers not trimmed/deduped: %v", cfg.Servers)
	}
	if len(cfg.Resolvers) != 1 {
		t.Fatalf("resolvers not deduped: %v", cfg.Resolvers)
	}
}

func TestDedupeAndCloneIPs(t *testing.T) {
	t.Parallel()

	in := []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.4"), nil, net.ParseIP("::1")}
	out := dedupeIPs(in)
	if len(out) != 2 {
		t.Fatalf("dedupe: got %d, want 2", len(out))
	}

	clone := cloneIPs(out)
	clone[0][0] = 9
	if out[0][0] == 9 {
		t.Fatal("cloneIPs returned an aliased slice")
	}
}

func TestNormalizeTTL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ttl      uint32
		fallback int
		want     time.Duration
	}{
		{0, 300, 300 * time.Second},
		{5, 300, 30 * time.Second},
		{120, 300, 120 * time.Second},
		{9000, 300, 300 * time.Second},
	}
	for _, c := range cases {
		if got := normalizeTTL(c.ttl, c.fallback); got != c.want {
			t.Errorf("normalizeTTL(%d,%d)=%v want %v", c.ttl, c.fallback, got, c.want)
		}
	}
}

func TestCacheFreshAndStale(t *testing.T) {
	t.Parallel()

	r := &Upstream{
		config: conf.UpstreamConfig{CacheTTL: 300, StaleTTL: 300, MaxCacheEntries: 8},
		cache:  make(map[string]cachedEntry),
	}
	ips := []net.IP{net.ParseIP("203.0.113.7")}

	r.storeCache("host", ips, 50*time.Millisecond)
	if _, ok := r.cachedFresh("host"); !ok {
		t.Fatal("entry should be fresh right after store")
	}

	r.cacheMu.Lock()
	e := r.cache["host"]
	e.ExpiresAt = time.Now().Add(-time.Second)
	r.cache["host"] = e
	r.cacheMu.Unlock()

	if _, ok := r.cachedFresh("host"); ok {
		t.Fatal("entry should no longer be fresh")
	}
	if _, ok := r.cachedStale("host"); !ok {
		t.Fatal("entry should still be served as stale")
	}
}

func TestSortIPsForDialPrefersIPv4ByDefault(t *testing.T) {
	t.Parallel()

	r := &Upstream{config: conf.UpstreamConfig{PreferIPv6: false}}
	in := []net.IP{net.ParseIP("::1"), net.ParseIP("1.2.3.4"), net.ParseIP("::2")}
	out := r.sortIPsForDial(in)
	if isIPv6(out[0]) {
		t.Fatalf("expected an IPv4 address first, got %v", out[0])
	}
}
