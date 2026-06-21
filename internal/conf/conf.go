package conf

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Port                 int                 `yaml:"port"`
	Listen               string              `yaml:"listen"`
	MaxConcurrentConn    int                 `yaml:"max-concurrent-connections"`
	Verbose              bool                `yaml:"verbose"`
	CustomResolve        map[string][]string `yaml:"custom-resolve"`
	CustomResolveTimeout int                 `yaml:"custom-resolve-timeout"`
	Cache                *bool               `yaml:"cache"`
	CacheMaxEntries      int                 `yaml:"cache-max-entries"`
	RateLimit            int                 `yaml:"rate-limit"`
	Running              bool                `yaml:"running"`
}

type UpstreamConfig struct {
	Servers            []string `yaml:"servers"`
	Resolvers          []string `yaml:"resolvers"`
	CacheTTL           int      `yaml:"cache-ttl"`
	Verbose            bool     `yaml:"verbose"`
	InsecureSkipVerify bool     `yaml:"insecure-skip-verify"`

	HTTPTimeout           int  `yaml:"http-timeout"`
	DialTimeout           int  `yaml:"dial-timeout"`
	TLSHandshakeTimeout   int  `yaml:"tls-handshake-timeout"`
	ResponseHeaderTimeout int  `yaml:"response-header-timeout"`
	BootstrapTimeout      int  `yaml:"bootstrap-timeout"`
	MaxCacheEntries       int  `yaml:"max-cache-entries"`
	StaleTTL              int  `yaml:"stale-ttl"`
	CleanupInterval       int  `yaml:"cleanup-interval"`
	MaxConcurrentRequests int  `yaml:"max-concurrent-requests"`
	PreferIPv6            bool `yaml:"prefer-ipv6"`
}

type GRPCTLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client-ca"`
}

type GRPCTCPConfig struct {
	Enabled bool          `yaml:"enabled"`
	Address string        `yaml:"address"`
	Auth    bool          `yaml:"auth"`
	TLS     GRPCTLSConfig `yaml:"tls"`
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
	LANInterface      string   `yaml:"lan-interface"`
	LANInterfaces     []string `yaml:"lan-interfaces"`
	EnableIPv6        bool     `yaml:"enable-ipv6"`
	EnableTProxy      bool     `yaml:"enable-tproxy"`
	IPSetDebug        bool     `yaml:"ipset-debug"`
	IPSetStaleQueries int      `yaml:"ipset-stale-queries"`
	ReconcileInterval int      `yaml:"reconcile-interval"`
}

type FullConfig struct {
	DNSServer        ServerConfig   `yaml:"dnsServer"`
	GRPC             GRPCConfig     `yaml:"grpc"`
	DoH              UpstreamConfig `yaml:"doh"`
	UnblockRulesPath string         `yaml:"unblock-rules-path"`
	Network          NetworkConfig  `yaml:"network"`
}

func LoadStrict(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg FullConfig
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
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
	cfg.Network.LANInterfaces = normalizeInterfaces(cfg.Network.LANInterfaces, cfg.Network.LANInterface)
	if len(cfg.Network.LANInterfaces) == 0 {
		cfg.Network.LANInterfaces = []string{"br0"}
	}

	return &cfg, nil
}

func normalizeInterfaces(list []string, fallback string) []string {
	var result []string
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	for _, value := range list {
		add(value)
	}
	if len(result) == 0 {
		add(fallback)
	}
	return result
}
