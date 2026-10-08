package firewall

import (
	"strings"
	"testing"
	"time"
)

func TestKeepaliveIntervalMath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		timeout, override int
		want              time.Duration
	}{
		{3600, 0, 300 * time.Second},
		{60, 0, 30 * time.Second},
		{600, 0, 100 * time.Second},
		{86400, 0, 300 * time.Second},
		{3600, 600, 600 * time.Second},
		{3600, 10, 30 * time.Second},
		{3600, 5000, 1350 * time.Second},
		{60, 600, 30 * time.Second},
	}
	for _, tc := range cases {
		if got := keepaliveInterval(tc.timeout, tc.override); got != tc.want {
			t.Errorf("keepaliveInterval(%d, %d) = %s, want %s", tc.timeout, tc.override, got, tc.want)
		}
	}
}

func TestKeepaliveNoExpiryBetweenSweeps(t *testing.T) {
	t.Parallel()

	for _, timeout := range []int{60, 600, 3600, 86400} {
		for _, override := range []int{0, 60, 600, 5000} {
			interval := keepaliveInterval(timeout, override)
			threshold := refreshThreshold(timeout, interval)
			seconds := int(interval / time.Second)
			if threshold <= seconds {
				t.Errorf("timeout=%d override=%d: threshold %d <= interval %d, entry can expire between sweeps",
					timeout, override, threshold, seconds)
			}
			if threshold > timeout {
				t.Errorf("timeout=%d override=%d: threshold %d exceeds entry timeout", timeout, override, threshold)
			}
		}
	}
}

func TestScanSaveEntries(t *testing.T) {
	t.Parallel()

	data := strings.Join([]string{
		"create vpner-xray-ch1 hash:net family inet hashsize 1024 maxelem 65536 timeout 3600 comment",
		`add vpner-xray-ch1 1.2.3.4 timeout 541 comment "vpner|rule=*.discord.gg|domain=gateway.discord.gg"`,
		"add vpner-xray-ch1 5.6.7.8 timeout 0",
		"add vpner-xray-ch1 10.0.0.0/24 timeout 200 comment \"vpner|rule=10.0.0.0/24|domain=10.0.0.0/24\"",
		"add vpner-other-set 9.9.9.9 timeout 100",
		"add vpner-xray-ch1 2.3.4.5",
		"",
	}, "\n")

	var entries []keepaliveEntry
	if err := scanSaveEntries(strings.NewReader(data), "vpner-xray-ch1", func(e keepaliveEntry) {
		entries = append(entries, e)
	}); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries with timeouts, got %d: %#v", len(entries), entries)
	}
	if entries[0].Entry != "1.2.3.4" || entries[0].Timeout != 541 ||
		entries[0].Comment != "vpner|rule=*.discord.gg|domain=gateway.discord.gg" {
		t.Fatalf("unexpected first entry: %#v", entries[0])
	}
	if entries[1].Entry != "5.6.7.8" || entries[1].Timeout != 0 || entries[1].Comment != "" {
		t.Fatalf("unexpected second entry: %#v", entries[1])
	}
	if entries[2].Entry != "10.0.0.0/24" || entries[2].Timeout != 200 {
		t.Fatalf("unexpected third entry: %#v", entries[2])
	}
}

func TestIsCandidate(t *testing.T) {
	t.Parallel()

	registry := NewIPSetRegistry()
	registry.RegisterStaticEntry("vpner-x", "8.8.8.8")
	sweeper := &KeepaliveSweeper{registry: registry, entryTimeout: 3600, threshold: 600}

	cases := []struct {
		entry   keepaliveEntry
		wantKey string
	}{
		{keepaliveEntry{Entry: "1.2.3.4", Timeout: 500, Comment: "vpner|rule=a|domain=b"}, "1.2.3.4"},
		{keepaliveEntry{Entry: "5.6.7.8", Timeout: 601, Comment: "vpner|rule=a|domain=b"}, ""},
		{keepaliveEntry{Entry: "9.9.9.9", Timeout: 0}, ""},
		{keepaliveEntry{Entry: "10.0.0.0/24", Timeout: 100}, ""},
		{keepaliveEntry{Entry: "8.8.8.8", Timeout: 100}, ""},
		{keepaliveEntry{Entry: "not-an-ip", Timeout: 100}, ""},
		{keepaliveEntry{Entry: "4.4.4.4", Timeout: 100, Comment: `bad"comment`}, ""},
		{keepaliveEntry{Entry: "7.7.7.7", Timeout: 100, Comment: "legacy.example.com"}, ""},
		{keepaliveEntry{Entry: "6.6.6.6", Timeout: 100, Comment: ""}, ""},
		{keepaliveEntry{Entry: "2a00:1450::5e", Timeout: 42, Comment: "vpner|rule=a|domain=b"}, "2a00:1450::5e"},
	}
	for _, tc := range cases {
		key, ok := sweeper.isCandidate("vpner-x", tc.entry)
		if ok != (tc.wantKey != "") || key != tc.wantKey {
			t.Errorf("isCandidate(%#v) = (%q,%v), want key %q", tc.entry, key, ok, tc.wantKey)
		}
	}
}

func TestConntrackActive(t *testing.T) {
	t.Parallel()

	data := strings.Join([]string{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=1.2.3.4 sport=51544 dport=443 src=1.2.3.4 dst=203.0.113.7 sport=443 dport=51544 [ASSURED] mark=0 use=1",
		"ipv4     2 udp      17 175 src=192.168.1.10 dst=66.22.220.1 sport=50001 dport=50002 src=66.22.220.1 dst=203.0.113.7 sport=50002 dport=50001 [ASSURED] mark=200 use=1",
		"ipv6     10 udp     17 40 src=2a02:0000:0000:0000:0000:0000:0000:0001 dst=2a00:1450:4010:0c08:0000:0000:0000:005e sport=5353 dport=443 src=2a00:1450:4010:0c08:0000:0000:0000:005e dst=2a02::1 sport=443 dport=5353 mark=0 use=1",
		"udp      17 170 src=10.0.0.2 dst=8.8.8.8 sport=1024 dport=53 src=8.8.8.8 dst=10.0.0.2 sport=53 dport=1024 [ASSURED]",
		"garbage line without tuples",
		"",
	}, "\n")

	want := map[string]keepaliveEntry{
		"1.2.3.4":                {Entry: "1.2.3.4", Timeout: 100},
		"2a00:1450:4010:c08::5e": {Entry: "2a00:1450:4010:c08::5e", Timeout: 50},
		"203.0.113.7":            {Entry: "203.0.113.7", Timeout: 10},
		"5.5.5.5":                {Entry: "5.5.5.5", Timeout: 10},
	}
	active := conntrackActive(strings.NewReader(data), want)

	got := map[string]bool{}
	for _, e := range active {
		got[e.Entry] = true
	}
	if !got["1.2.3.4"] || !got["2a00:1450:4010:c08::5e"] {
		t.Fatalf("expected first-tuple dst matches, got %#v", got)
	}
	if got["203.0.113.7"] {
		t.Error("reply-direction dst (router WAN) must not be collected from the first tuple lines")
	}
	if got["5.5.5.5"] {
		t.Error("idle candidate must not be marked active")
	}
	if len(active) != 2 {
		t.Fatalf("expected exactly 2 active entries, got %d: %#v", len(active), active)
	}
	if _, still := want["1.2.3.4"]; still {
		t.Error("matched candidates must be consumed from the want map")
	}
}

func TestStillEligibleDropsDeletedAndRefreshedEntries(t *testing.T) {
	t.Parallel()

	active := []keepaliveEntry{
		{Entry: "1.2.3.4", Timeout: 100, Comment: "vpner|rule=a|domain=b"},
		{Entry: "5.6.7.8", Timeout: 120, Comment: "vpner|rule=a|domain=c"},
		{Entry: "9.9.9.9", Timeout: 50, Comment: "vpner|rule=a|domain=d"},
	}
	current := map[string]keepaliveEntry{
		"1.2.3.4": {Entry: "1.2.3.4", Timeout: 90, Comment: "vpner|rule=a|domain=b"},
		"9.9.9.9": {Entry: "9.9.9.9", Timeout: 45, Comment: "vpner|rule=x|domain=d"},
	}

	got := stillEligible(active, current)
	if len(got) != 2 {
		t.Fatalf("expected 2 still-eligible entries, got %d: %#v", len(got), got)
	}
	if got[0].Entry != "1.2.3.4" || got[0].Timeout != 90 {
		t.Fatalf("must use the fresh re-read entry, got %#v", got[0])
	}
	if got[1].Comment != "vpner|rule=x|domain=d" {
		t.Fatalf("must use the fresh comment, got %#v", got[1])
	}
	for _, e := range got {
		if e.Entry == "5.6.7.8" {
			t.Fatal("entry deleted (or refreshed above threshold) between scan and lock must not be re-added")
		}
	}
}

func TestBuildKeepaliveScript(t *testing.T) {
	t.Parallel()

	entries := []keepaliveEntry{
		{Entry: "1.2.3.4", Timeout: 100, Comment: "vpner|rule=*.x|domain=a.x"},
		{Entry: "5.6.7.8", Timeout: 200, Comment: ""},
	}
	got := buildKeepaliveScript("vpner-x", entries, 3600, false)
	want := "add vpner-x 1.2.3.4 timeout 3600 comment \"vpner|rule=*.x|domain=a.x\"\n" +
		"add vpner-x 5.6.7.8 timeout 3600\n"
	if got != want {
		t.Fatalf("unexpected script:\n%q\nwant:\n%q", got, want)
	}

	legacy := buildKeepaliveScript("vpner-x", entries, 3600, true)
	wantLegacy := "del vpner-x 1.2.3.4\n" +
		"add vpner-x 1.2.3.4 timeout 3600 comment \"vpner|rule=*.x|domain=a.x\"\n" +
		"del vpner-x 5.6.7.8\n" +
		"add vpner-x 5.6.7.8 timeout 3600\n"
	if legacy != wantLegacy {
		t.Fatalf("unexpected legacy script:\n%q\nwant:\n%q", legacy, wantLegacy)
	}
}

func TestNewKeepaliveSweeperDisabled(t *testing.T) {
	t.Parallel()

	registry := NewIPSetRegistry()
	if s := NewKeepaliveSweeper(registry, KeepaliveOptions{EntryTimeout: 0, Enabled: true}); s != nil {
		t.Fatal("legacy mode (timeout 0) must disable the sweeper")
	}
	if s := NewKeepaliveSweeper(registry, KeepaliveOptions{EntryTimeout: 3600, Enabled: false}); s != nil {
		t.Fatal("config off must disable the sweeper")
	}
	if s := NewKeepaliveSweeper(nil, KeepaliveOptions{EntryTimeout: 3600, Enabled: true}); s != nil {
		t.Fatal("nil registry must disable the sweeper")
	}
}
