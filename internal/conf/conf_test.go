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
