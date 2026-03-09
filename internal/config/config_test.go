package config

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
