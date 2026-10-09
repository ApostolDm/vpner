package firewall

import (
	"sync"
	"testing"
)

type stubMatcher struct{ domains map[string]bool }

func (s stubMatcher) MatchDomain(domain string) (string, string, string, bool) {
	if s.domains[domain] {
		return "OpenVPN", "OpenVPN0", domain, true
	}
	return "", "", "", false
}

func TestDropAAAAFollowsDefaultRoute(t *testing.T) {
	t.Parallel()

	m := NewIpRuleManager(stubMatcher{domains: map[string]bool{"matched.example": true}}, RuleRuntimeOptions{IPv6Enabled: false}, NewIPSetRegistry())
	if !m.DropAAAA("matched.example") {
		t.Fatal("matched domain must drop AAAA when ipv6 is disabled")
	}
	if m.DropAAAA("other.example") {
		t.Fatal("unmatched domain must keep AAAA while routing is split")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(on bool) {
			defer wg.Done()
			m.SetDefaultRoute(on)
			_ = m.DropAAAA("other.example")
		}(i%2 == 0)
	}
	wg.Wait()

	m.SetDefaultRoute(true)
	if !m.DropAAAA("other.example") {
		t.Fatal("every domain must drop AAAA while the default route is active")
	}
	m.SetDefaultRoute(false)
	if m.DropAAAA("other.example") {
		t.Fatal("disabling the default route must restore per-rule behaviour")
	}

	v6 := NewIpRuleManager(stubMatcher{}, RuleRuntimeOptions{IPv6Enabled: true}, NewIPSetRegistry())
	v6.SetDefaultRoute(true)
	if v6.DropAAAA("other.example") {
		t.Fatal("AAAA must never be dropped when ipv6 routing is enabled")
	}
}
