package network

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const defaultXrayBaseDir = "/opt/etc/vpner/xray"

type VMessConfig struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
}

type xrayMetadata struct {
	Protocol   string `yaml:"protocol"`
	RemoteHost string `yaml:"remote_host"`
	RemotePort int    `yaml:"remote_port"`
	SocksPort  int    `yaml:"socks_port"`
}

type xrayFile struct {
	Inbounds  []map[string]interface{} `yaml:"inbounds"`
	Outbounds []map[string]interface{} `yaml:"outbounds"`
	AutoRun   bool                     `yaml:"auto_run"`
	Metadata  xrayMetadata             `yaml:"metadata"`
}

type XrayInfoDetails struct {
	Type        string `yaml:"type"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	AutoRun     bool   `yaml:"auto_run"`
	InboundPort int    `yaml:"inbound_port"`
}

type XrayManager struct {
	mu      sync.RWMutex
	baseDir string
}

func NewXrayManager() (*XrayManager, error) {
	return newXrayManager(defaultXrayBaseDir)
}

func newXrayManager(dir string) (*XrayManager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to prepare xray directory %s: %w", dir, err)
	}
	return &XrayManager{baseDir: dir}, nil
}

func (x *XrayManager) configPath(name string) string {
	return filepath.Join(x.baseDir, name+".yaml")
}

func (x *XrayManager) checkDependencies() error {
	if _, err := exec.LookPath("xray"); err != nil {
		return fmt.Errorf("xray binary not found in PATH: %w", err)
	}
	return nil
}

func (x *XrayManager) readConfig(path string) (*xrayFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg xrayFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// --- CRUD ---

func (x *XrayManager) CreateXray(link string, autoRun bool) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if err := x.checkDependencies(); err != nil {
		return "", err
	}

	port, err := x.findFreePort(1080, 20000)
	if err != nil {
		return "", err
	}

	config, err := x.buildConfig(link, port)
	if err != nil {
		return "", err
	}

	if x.isDuplicate(config) {
		return "", fmt.Errorf("duplicate configuration exists")
	}

	config.AutoRun = autoRun
	config.Metadata.SocksPort = port

	name := x.generateUniqueName()
	data, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(x.configPath(name), data, 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}
	return name, nil
}

func (x *XrayManager) DeleteXray(name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return os.Remove(x.configPath(name))
}

func (x *XrayManager) StartXray(ctx context.Context, name string) error {
	x.mu.RLock()
	configPath := x.configPath(name)
	_, err := os.Stat(configPath)
	x.mu.RUnlock()

	if err := x.checkDependencies(); err != nil {
		return err
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("no such xray config: %s", name)
	} else if err != nil {
		return fmt.Errorf("failed to stat config: %w", err)
	}
	if err := x.ensureVLESSUserEncryption(configPath); err != nil {
		return err
	}

	// exec.CommandContext handles process kill on ctx cancellation.
	cmd := exec.CommandContext(ctx, "xray", "run", "-config", configPath)
	prefix := fmt.Sprintf("[xray-%s] ", name)
	cmd.Stdout = &taggedPrefixWriter{prefix: prefix, target: os.Stdout}
	cmd.Stderr = &taggedPrefixWriter{prefix: prefix, target: os.Stderr}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited with error: %v\n", name, err)
	} else {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited cleanly\n", name)
	}
	return err
}

func (x *XrayManager) UpdateAutoRun(name string, autoRun bool) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	path := x.configPath(name)
	cfg, err := x.readConfig(path)
	if err != nil {
		return err
	}
	if cfg.AutoRun == autoRun {
		return nil
	}
	cfg.AutoRun = autoRun
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// --- listing ---

func (x *XrayManager) ListXray() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.listNames(func(*xrayFile) bool { return true })
}

func (x *XrayManager) ListAutoRun() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.listNames(func(cfg *xrayFile) bool { return cfg.AutoRun })
}

func (x *XrayManager) listNames(filter func(*xrayFile) bool) ([]string, error) {
	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if filter == nil {
			list = append(list, name)
			continue
		}
		cfg, err := x.readConfig(filepath.Join(x.baseDir, e.Name()))
		if err != nil {
			continue
		}
		if filter(cfg) {
			list = append(list, name)
		}
	}
	return list, nil
}

func (x *XrayManager) ListXrayInfo() (map[string]XrayInfoDetails, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return nil, err
	}

	result := make(map[string]XrayInfoDetails)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		cfg, err := x.readConfig(filepath.Join(x.baseDir, e.Name()))
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		result[name] = cfg.toInfo()
	}
	return result, nil
}

func (x *XrayManager) GetXrayInfo(name string) (XrayInfoDetails, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	cfg, err := x.readConfig(x.configPath(name))
	if err != nil {
		return XrayInfoDetails{}, err
	}
	return cfg.toInfo(), nil
}

func (x *XrayManager) IsXrayChain(name string) bool {
	if len(name) < 4 || name[:4] != "xray" {
		return false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	_, err := os.Stat(x.configPath(name))
	return err == nil
}

// --- internal helpers ---

func (x *XrayManager) getUsedInboundPorts() map[int]bool {
	used := make(map[int]bool)
	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return used
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		cfg, err := x.readConfig(filepath.Join(x.baseDir, e.Name()))
		if err != nil {
			continue
		}
		if cfg.Metadata.SocksPort != 0 {
			used[cfg.Metadata.SocksPort] = true
			continue
		}
		for _, inbound := range cfg.Inbounds {
			if port, ok := inbound["port"]; ok {
				if p := readNumericPort(port); p > 0 {
					used[p] = true
				}
			}
		}
	}
	return used
}

func (x *XrayManager) findFreePort(min, max int) (int, error) {
	used := x.getUsedInboundPorts()
	for i := 0; i < 1000; i++ {
		port := rand.Intn(max-min) + min
		if used[port] {
			continue
		}
		if isPortFree(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port found")
}

func isPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()

	udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = udp.Close()
	return true
}

func (x *XrayManager) generateUniqueName() string {
	for i := 1; ; i++ {
		name := fmt.Sprintf("xray%d", i)
		if _, err := os.Stat(x.configPath(name)); os.IsNotExist(err) {
			return name
		}
	}
}

func (x *XrayManager) isDuplicate(cfg *xrayFile) bool {
	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return false
	}
	for _, f := range entries {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		existing, err := x.readConfig(filepath.Join(x.baseDir, f.Name()))
		if err != nil {
			continue
		}
		if reflect.DeepEqual(existing.Outbounds, cfg.Outbounds) {
			return true
		}
	}
	return false
}

// --- info extraction ---

func (cfg *xrayFile) toInfo() XrayInfoDetails {
	info := XrayInfoDetails{
		Type:        cfg.Metadata.Protocol,
		Host:        cfg.Metadata.RemoteHost,
		Port:        cfg.Metadata.RemotePort,
		AutoRun:     cfg.AutoRun,
		InboundPort: cfg.Metadata.SocksPort,
	}

	if info.InboundPort == 0 {
		info.InboundPort = extractInboundPort(cfg.Inbounds)
	}

	if info.Type == "" || info.Host == "" || info.Port == 0 {
		protocol, host, port := extractOutboundInfo(cfg.Outbounds)
		if info.Type == "" {
			info.Type = protocol
		}
		if info.Host == "" {
			info.Host = host
		}
		if info.Port == 0 {
			info.Port = port
		}
	}

	return info
}

func extractInboundPort(inbounds []map[string]interface{}) int {
	for _, inbound := range inbounds {
		if port, ok := inbound["port"]; ok {
			if p := readNumericPort(port); p > 0 {
				return p
			}
		}
	}
	return 0
}

func extractOutboundInfo(outbounds []map[string]interface{}) (protocol, host string, port int) {
	if len(outbounds) == 0 {
		return
	}
	ob := outbounds[0]
	if proto, ok := ob["protocol"].(string); ok {
		protocol = proto
	}
	settings, _ := ob["settings"].(map[string]interface{})
	switch protocol {
	case "vmess", "vless":
		if vnextList, ok := settings["vnext"].([]interface{}); ok && len(vnextList) > 0 {
			if vnext, ok := vnextList[0].(map[string]interface{}); ok {
				if addr, ok := vnext["address"].(string); ok {
					host = addr
				}
				if p := readNumericPort(vnext["port"]); p > 0 {
					port = p
				}
			}
		}
	case "shadowsocks":
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			if s, ok := servers[0].(map[string]interface{}); ok {
				if addr, ok := s["address"].(string); ok {
					host = addr
				}
				if p := readNumericPort(s["port"]); p > 0 {
					port = p
				}
			}
		}
	}
	return
}

func readNumericPort(val interface{}) int {
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// --- io ---

type taggedPrefixWriter struct {
	prefix string
	target io.Writer
}

func (w *taggedPrefixWriter) Write(p []byte) (int, error) {
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		if line != "" {
			if _, err := fmt.Fprintf(w.target, "%s%s\n", w.prefix, line); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}
