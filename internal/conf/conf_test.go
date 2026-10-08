package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFullConfigAppliesDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vpner.yaml")
	if err := os.WriteFile(path, []byte("dnsServer: {}\ngrpc:\n  tcp:\n    enabled: true\nnetwork: {}\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFullConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.UnblockRulesPath != "/opt/etc/vpner/vpner_unblock.yaml" {
		t.Fatalf("unexpected unblock path: %s", cfg.UnblockRulesPath)
	}
	if cfg.DNSServer.Port != 53 {
		t.Fatalf("unexpected dns port: %d", cfg.DNSServer.Port)
	}
	if cfg.DNSServer.MaxConcurrentConn != 100 {
		t.Fatalf("unexpected max concurrent conn: %d", cfg.DNSServer.MaxConcurrentConn)
	}
	if cfg.GRPC.TCP.Address != ":50051" {
		t.Fatalf("unexpected grpc address: %s", cfg.GRPC.TCP.Address)
	}
	if cfg.DoH.CacheTTL != 300 {
		t.Fatalf("unexpected DoH cache ttl: %d", cfg.DoH.CacheTTL)
	}
	if len(cfg.Network.LANInterfaces) != 1 || cfg.Network.LANInterfaces[0] != "br0" {
		t.Fatalf("unexpected lan interfaces: %#v", cfg.Network.LANInterfaces)
	}
	if cfg.Network.IPSetEntryTimeout != 3600 {
		t.Fatalf("unexpected ipset entry timeout default: %d", cfg.Network.IPSetEntryTimeout)
	}
}

func TestLoadFullConfigIPSetEntryTimeout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	custom, err := LoadFullConfig(write("custom.yaml", "network:\n  ipset-entry-timeout: 600\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if custom.Network.IPSetEntryTimeout != 600 {
		t.Fatalf("custom timeout not preserved: %d", custom.Network.IPSetEntryTimeout)
	}

	disabled, err := LoadFullConfig(write("disabled.yaml", "network:\n  ipset-entry-timeout: -1\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if disabled.Network.IPSetEntryTimeout != 0 {
		t.Fatalf("negative must normalize to 0 (disabled): %d", disabled.Network.IPSetEntryTimeout)
	}

	tiny, err := LoadFullConfig(write("tiny.yaml", "network:\n  ipset-entry-timeout: 20\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if tiny.Network.IPSetEntryTimeout != 60 {
		t.Fatalf("sub-minute timeout must clamp to 60: %d", tiny.Network.IPSetEntryTimeout)
	}
}

func TestLoadFullConfigClampAndKeepaliveDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	defaults, err := LoadFullConfig(write("defaults.yaml", "network: {}\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if defaults.Network.ClampDNSTTL != 3300 {
		t.Fatalf("clamp auto must default to entry timeout minus the refresh window: %d", defaults.Network.ClampDNSTTL)
	}
	if defaults.Network.IPSetKeepalive != nil {
		t.Fatalf("keepalive default must stay nil (enabled): %v", *defaults.Network.IPSetKeepalive)
	}
	if defaults.Network.IPSetKeepaliveInterval != 0 {
		t.Fatalf("keepalive interval default must be 0 (auto): %d", defaults.Network.IPSetKeepaliveInterval)
	}

	off, err := LoadFullConfig(write("off.yaml", "network:\n  clamp-dns-ttl: -1\n  ipset-keepalive-interval: -5\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if off.Network.ClampDNSTTL != 0 {
		t.Fatalf("clamp -1 must normalize to 0 (off): %d", off.Network.ClampDNSTTL)
	}
	if off.Network.IPSetKeepaliveInterval != 0 {
		t.Fatalf("negative keepalive interval must normalize to 0: %d", off.Network.IPSetKeepaliveInterval)
	}

	explicit, err := LoadFullConfig(write("explicit.yaml", "network:\n  clamp-dns-ttl: 300\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if explicit.Network.ClampDNSTTL != 300 {
		t.Fatalf("explicit clamp not preserved: %d", explicit.Network.ClampDNSTTL)
	}

	legacy, err := LoadFullConfig(write("legacy.yaml", "network:\n  ipset-entry-timeout: -1\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if legacy.Network.ClampDNSTTL != 0 {
		t.Fatalf("legacy mode must leave clamp off: %d", legacy.Network.ClampDNSTTL)
	}

	tiny, err := LoadFullConfig(write("tinyclamp.yaml", "network:\n  ipset-entry-timeout: 60\n"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if tiny.Network.ClampDNSTTL != 30 {
		t.Fatalf("auto clamp for 60s timeout must be 30: %d", tiny.Network.ClampDNSTTL)
	}
}

func TestNormalizeInterfaces(t *testing.T) {
	t.Parallel()

	got := normalizeInterfaces([]string{" br0 ", "tun0", "br0", ""}, "eth0")
	if len(got) != 2 || got[0] != "br0" || got[1] != "tun0" {
		t.Fatalf("unexpected normalized interfaces: %#v", got)
	}

	fallback := normalizeInterfaces(nil, "eth0")
	if len(fallback) != 1 || fallback[0] != "eth0" {
		t.Fatalf("unexpected fallback interfaces: %#v", fallback)
	}
}
