package firewall

import (
	"strings"
	"testing"
	"time"
)

func TestBuildBulkAddScriptWithTimeout(t *testing.T) {
	t.Parallel()

	script := buildBulkAddScript(
		"vpnx_test",
		[]string{"203.0.113.10", "203.0.113.11"},
		`vpner|rule=*.example.com|domain=cdn.example.com`,
		3600,
		true,
	)

	lines := strings.Split(strings.TrimSuffix(script, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), script)
	}
	want := `add vpnx_test 203.0.113.10 timeout 3600 comment "vpner|rule=*.example.com|domain=cdn.example.com"`
	if lines[0] != want {
		t.Fatalf("unexpected line:\n got: %s\nwant: %s", lines[0], want)
	}
}

func TestBuildBulkAddScriptWithoutTimeout(t *testing.T) {
	t.Parallel()

	script := buildBulkAddScript("vpnx_test", []string{"198.51.100.1"}, "c", 3600, false)
	if strings.Contains(script, "timeout") {
		t.Fatalf("timeout must be omitted on sets without timeout support: %q", script)
	}
}

func TestBuildBulkAddScriptPermanentEntry(t *testing.T) {
	t.Parallel()

	script := buildBulkAddScript("vpnx_test", []string{"198.51.100.0/24"}, "static", 0, true)
	if !strings.Contains(script, " timeout 0 ") {
		t.Fatalf("permanent entries on timeout sets need explicit timeout 0: %q", script)
	}
}

func TestTimeoutArgs(t *testing.T) {
	t.Parallel()

	timeoutSet := &IPSet{Name: "a", Timeout: 3600}
	if got := strings.Join(timeoutSet.timeoutArgs(0), " "); got != "timeout 0" {
		t.Fatalf("static entry on timeout set: got %q, want explicit timeout 0", got)
	}
	if got := strings.Join(timeoutSet.timeoutArgs(120), " "); got != "timeout 120" {
		t.Fatalf("dns entry on timeout set: got %q", got)
	}

	plainSet := &IPSet{Name: "b"}
	if got := plainSet.timeoutArgs(0); got != nil {
		t.Fatalf("plain set must not emit timeout args: %v", got)
	}
}

func TestRefreshThrottle(t *testing.T) {
	t.Parallel()

	r := NewIPSetRegistry()
	window := 5 * time.Minute

	key := refreshKey("vpnx_test", "comment")
	fp := ipsFingerprint([]string{"2.2.2.2", "1.1.1.1"})
	if fp != "1.1.1.1,2.2.2.2" {
		t.Fatalf("fingerprint must be order independent: %q", fp)
	}

	if r.RecentlyRefreshed(key, fp, window) {
		t.Fatal("fresh key must not be throttled")
	}
	r.MarkRefreshed(key, fp, window)
	if !r.RecentlyRefreshed(key, fp, window) {
		t.Fatal("identical answer within window must be throttled")
	}
	if r.RecentlyRefreshed(key, ipsFingerprint([]string{"3.3.3.3"}), window) {
		t.Fatal("changed answer must bypass the throttle")
	}

	r.refreshMu.Lock()
	r.refreshSeen[key] = refreshRecord{ips: fp, at: time.Now().Add(-time.Hour)}
	r.refreshMu.Unlock()
	if r.RecentlyRefreshed(key, fp, window) {
		t.Fatal("expired record must not throttle")
	}
}

func TestRefreshThrottleInvalidation(t *testing.T) {
	t.Parallel()

	r := NewIPSetRegistry()
	window := 5 * time.Minute
	comment := buildRuleComment("*.example.com", "cdn.example.com")
	key := refreshKey("vpnx_test", comment)
	fp := "1.1.1.1"

	r.MarkRefreshed(key, fp, window)
	r.ClearRefreshKey(key)
	if r.RecentlyRefreshed(key, fp, window) {
		t.Fatal("ClearRefreshKey must drop the record")
	}

	r.MarkRefreshed(key, fp, window)
	other := refreshKey("vpnx_test", buildRuleComment("*.example.com", "img.example.com"))
	r.MarkRefreshed(other, fp, window)
	unrelated := refreshKey("vpnx_test", buildRuleComment("*.other.org", "a.other.org"))
	r.MarkRefreshed(unrelated, fp, window)

	r.ClearRefreshByPrefix(refreshKey("vpnx_test", ruleCommentPrefix("*.example.com")))
	if r.RecentlyRefreshed(key, fp, window) || r.RecentlyRefreshed(other, fp, window) {
		t.Fatal("rule delete must clear all its domain records")
	}
	if !r.RecentlyRefreshed(unrelated, fp, window) {
		t.Fatal("unrelated rule records must survive")
	}
}

func TestRefreshWindowBounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		timeout int
		want    time.Duration
	}{
		{0, legacyModeRefreshWindow},
		{120, refreshIntervalFloor},
		{3600, refreshIntervalCap},
		{600, 150 * time.Second},
		{40, 20 * time.Second},
		{20, 10 * time.Second},
	}
	for _, tc := range cases {
		m := NewIpRuleManager(nil, RuleRuntimeOptions{IPSetEntryTimeout: tc.timeout}, NewIPSetRegistry())
		if got := m.refreshWindow(); got != tc.want {
			t.Fatalf("timeout=%d: got %v, want %v", tc.timeout, got, tc.want)
		}
	}
}

func TestLegacySweptOnlyAfterSuccess(t *testing.T) {
	t.Parallel()

	r := NewIPSetRegistry()
	if r.IsLegacySwept("vpnx_a") {
		t.Fatal("must start unswept")
	}
	r.MarkLegacySwept("vpnx_a")
	if !r.IsLegacySwept("vpnx_a") {
		t.Fatal("must report swept after mark")
	}
	if r.IsLegacySwept("vpnx_b") {
		t.Fatal("different set must be independent")
	}
}

func TestStaticEntryRegistry(t *testing.T) {
	t.Parallel()

	r := NewIPSetRegistry()
	r.RegisterStaticEntry("vpnx_test", "203.0.113.5")
	if !r.IsStaticEntry("vpnx_test", "203.0.113.5") {
		t.Fatal("registered static entry must be reported")
	}
	if r.IsStaticEntry("vpnx_other", "203.0.113.5") {
		t.Fatal("static entries are per set")
	}

	m := NewIpRuleManager(nil, RuleRuntimeOptions{IPSetEntryTimeout: 3600}, r)
	got := m.filterStaticEntries("vpnx_test", []string{"203.0.113.5", "203.0.113.6"})
	if len(got) != 1 || got[0] != "203.0.113.6" {
		t.Fatalf("static entry must be filtered from DNS adds: %v", got)
	}

	r.UnregisterStaticEntry("vpnx_test", "203.0.113.5")
	if r.IsStaticEntry("vpnx_test", "203.0.113.5") {
		t.Fatal("unregistered static entry must be gone")
	}
}

func TestNormalizeStaticEntry(t *testing.T) {
	t.Parallel()

	if got := normalizeStaticEntry("1.2.3.4/32", false); got != "1.2.3.4" {
		t.Fatalf("host CIDR must normalize: %q", got)
	}
	if got := normalizeStaticEntry("10.0.0.0/8", false); got != "10.0.0.0/8" {
		t.Fatalf("real CIDR must stay intact: %q", got)
	}
	if got := normalizeStaticEntry("2001:db8::1/128", true); got != "2001:db8::1" {
		t.Fatalf("v6 host CIDR must normalize: %q", got)
	}
}

func TestTempSetName(t *testing.T) {
	t.Parallel()

	if got := tempSetName("vpnx_short", "-tmp"); got != "vpnx_short-tmp" {
		t.Fatalf("short names keep plain suffix: %q", got)
	}
	long := "vpner-wireguard-verylongchainname"
	got := tempSetName(long, "-temp")
	if len(got) > maxIpsetNameLen {
		t.Fatalf("temp name exceeds kernel limit: %q (%d)", got, len(got))
	}
	if got == tempSetName(long+"x", "-temp") {
		t.Fatal("different bases must not collide")
	}
}
