package resolver

import (
	"testing"
	"time"
)

func TestOrderServersDemotesFailingPrimary(t *testing.T) {
	t.Parallel()

	now := time.Now()
	primary := &upstreamState{server: "https://a/dns-query"}
	primary.successes.Store(200000)
	primary.mu.Lock()
	primary.lastSuccess = now.Add(-time.Hour)
	primary.lastError = now
	primary.mu.Unlock()

	secondary := &upstreamState{server: "https://b/dns-query"}
	secondary.successes.Store(5)
	secondary.mu.Lock()
	secondary.lastSuccess = now
	secondary.mu.Unlock()

	r := &Upstream{servers: []*upstreamState{primary, secondary}}
	if got := r.orderServers(); got[0] != secondary {
		t.Fatalf("a primary whose last error is newer than its last success must be demoted; got %s first", got[0].server)
	}

	primary.mu.Lock()
	primary.lastSuccess = now.Add(time.Second)
	primary.mu.Unlock()
	if got := r.orderServers(); got[0] != primary {
		t.Fatalf("a recovered primary with more lifetime successes must lead again; got %s first", got[0].server)
	}
}

func TestOrderServersNeverErroredIsHealthy(t *testing.T) {
	t.Parallel()

	fresh := &upstreamState{server: "https://fresh/dns-query"}
	failing := &upstreamState{server: "https://failing/dns-query"}
	failing.successes.Store(10)
	failing.mu.Lock()
	failing.lastError = time.Now()
	failing.mu.Unlock()

	r := &Upstream{servers: []*upstreamState{failing, fresh}}
	if got := r.orderServers(); got[0] != fresh {
		t.Fatalf("a never-errored server must outrank a currently failing one; got %s first", got[0].server)
	}
}
