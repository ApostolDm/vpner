package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	configExt = ".json"
	metaExt   = ".meta.json"
	legacyExt = ".yaml"
)

type chainMeta struct {
	Link        string `json:"link,omitempty"`
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	InboundPort int    `json:"inbound_port"`
	AutoRun     bool   `json:"auto_run"`
}

type store struct {
	dir string
}

func (s *store) configPath(name string) string { return filepath.Join(s.dir, name+configExt) }
func (s *store) metaPath(name string) string   { return filepath.Join(s.dir, name+metaExt) }
func (s *store) legacyPath(name string) string { return filepath.Join(s.dir, name+legacyExt) }

func (s *store) exists(name string) bool {
	_, err := os.Stat(s.metaPath(name))
	return err == nil
}

func (s *store) readMeta(name string) (*chainMeta, error) {
	data, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		return nil, err
	}
	var m chainMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *store) writeMeta(name string, m *chainMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.metaPath(name), data, 0600)
}

func (s *store) writeConfig(name string, data []byte) error {

	return atomicWrite(s.configPath(name), data, 0600)
}

func (s *store) readConfigOutbound(name string) (jobj, error) {
	data, err := os.ReadFile(s.configPath(name))
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Outbounds []jobj `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Outbounds) == 0 {
		return nil, nil
	}
	return cfg.Outbounds[0], nil
}

func (s *store) readConfigParts(name string) (inbounds, outbounds []jobj, err error) {
	data, err := os.ReadFile(s.configPath(name))
	if err != nil {
		return nil, nil, err
	}
	var cfg struct {
		Inbounds  []jobj `json:"inbounds"`
		Outbounds []jobj `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, err
	}
	return cfg.Inbounds, cfg.Outbounds, nil
}

func (s *store) remove(name string) error {
	cErr := removeIfExists(s.configPath(name))
	mErr := removeIfExists(s.metaPath(name))
	if mErr != nil {
		return mErr
	}
	return cErr
}

func (s *store) chains() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name, ok := strings.CutSuffix(e.Name(), metaExt); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (m *chainMeta) toInfo() ChainInfo {
	return ChainInfo{
		Type:        m.Protocol,
		Host:        m.Address,
		Port:        m.Port,
		AutoRun:     m.AutoRun,
		InboundPort: m.InboundPort,
	}
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
