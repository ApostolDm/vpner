package proxy

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"gopkg.in/yaml.v3"
)

type legacyConfig struct {
	Inbounds  []map[string]any `yaml:"inbounds"`
	Outbounds []map[string]any `yaml:"outbounds"`
	AutoRun   bool             `yaml:"auto_run"`
	Metadata  struct {
		Protocol   string `yaml:"protocol"`
		RemoteHost string `yaml:"remote_host"`
		RemotePort int    `yaml:"remote_port"`
		SocksPort  int    `yaml:"socks_port"`
	} `yaml:"metadata"`
}

func (s *store) migrateLegacy() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), legacyExt)
		if !ok {
			continue
		}
		if s.exists(name) {

			_ = removeIfExists(s.legacyPath(name))
			continue
		}
		if err := s.migrateOne(name); err != nil {
			logx.Warnf("xray: failed to migrate legacy chain %s: %v", name, err)
		}
	}
}

func (s *store) migrateOne(name string) error {
	data, err := os.ReadFile(s.legacyPath(name))
	if err != nil {
		return err
	}
	var legacy legacyConfig
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		return err
	}

	protocol, host, port := legacyOutboundInfo(legacy.Outbounds)
	meta := &chainMeta{
		Protocol:    firstNonEmpty(legacy.Metadata.Protocol, protocol),
		Address:     firstNonEmpty(legacy.Metadata.RemoteHost, host),
		Port:        firstPositive(legacy.Metadata.RemotePort, port),
		InboundPort: firstPositive(legacy.Metadata.SocksPort, legacyInboundPort(legacy.Inbounds)),
		AutoRun:     legacy.AutoRun,
	}

	cfg := jobj{"inbounds": legacy.Inbounds, "outbounds": legacy.Outbounds}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := s.writeConfig(name, cfgJSON); err != nil {
		return err
	}
	if err := s.writeMeta(name, meta); err != nil {
		return err
	}
	_ = removeIfExists(s.legacyPath(name))
	logx.Infof("xray: migrated legacy chain %s to JSON config", name)
	return nil
}

func legacyOutboundInfo(outbounds []map[string]any) (protocol, host string, port int) {
	if len(outbounds) == 0 {
		return
	}
	ob := outbounds[0]
	protocol, _ = ob["protocol"].(string)
	settings, _ := ob["settings"].(map[string]any)
	switch protocol {
	case "vmess", "vless":
		host, port = serverFromList(settings["vnext"])
	case "shadowsocks":
		host, port = serverFromList(settings["servers"])
	}
	return
}

func serverFromList(v any) (host string, port int) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		return
	}
	host, _ = first["address"].(string)
	return host, numericPort(first["port"])
}

func legacyInboundPort(inbounds []map[string]any) int {
	for _, in := range inbounds {
		if p := numericPort(in["port"]); p > 0 {
			return p
		}
	}
	return 0
}

func numericPort(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		return atoiDefault(t, 0)
	case json.Number:
		if n, err := strconv.Atoi(t.String()); err == nil {
			return n
		}
	}
	return 0
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}
