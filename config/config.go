package config

import (
	"fmt"
	"os"

	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"gopkg.in/yaml.v3"
)

type GRPCTCPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Auth    bool   `yaml:"auth"`
}

type GRPCUnixConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type GRPCAuthConfig struct {
	Password string `yaml:"password"`
}

type GRPCConfig struct {
	TCP  GRPCTCPConfig  `yaml:"tcp"`
	Unix GRPCUnixConfig `yaml:"unix"`
	Auth GRPCAuthConfig `yaml:"auth"`
}

type NetworkConfig struct {
	LANInterface string `yaml:"lan-interface"`
	EnableIPv6   bool   `yaml:"enable-ipv6"`
	IPSetDebug   bool   `yaml:"ipset-debug"`
}

type FullConfig struct {
	DNSServer        dnsserver.ServerConfig   `yaml:"dnsServer"`
	GRPC             GRPCConfig               `yaml:"grpc"`
	DoH              dohclient.ResolverConfig `yaml:"doh"`
	UnblockRulesPath string                   `yaml:"unblock-rules-path"`
	Network          NetworkConfig            `yaml:"network"`
}

func LoadFullConfig(path string) (*FullConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg FullConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	// defaults
	if cfg.UnblockRulesPath == "" {
		cfg.UnblockRulesPath = "/opt/etc/vpner/vpner_unblock.yaml"
	}
	if cfg.DNSServer.Port == 0 {
		cfg.DNSServer.Port = 53
	}
	if cfg.DNSServer.MaxConcurrentConn == 0 {
		cfg.DNSServer.MaxConcurrentConn = 100
	}
	if cfg.GRPC.TCP.Address == "" {
		cfg.GRPC.TCP.Address = ":50051"
	}
	if cfg.DoH.CacheTTL == 0 {
		cfg.DoH.CacheTTL = 300
	}
	if cfg.Network.LANInterface == "" {
		cfg.Network.LANInterface = "br0"
	}

	return &cfg, nil
}
