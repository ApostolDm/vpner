package network

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
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

func (x *XrayManager) parseVLESS(link string) (map[string]string, error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" {
		return nil, fmt.Errorf("invalid VLESS URL")
	}
	q := u.Query()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return map[string]string{
		"uuid":          u.User.Username(),
		"address":       u.Hostname(),
		"port":          port,
		"encryption":    q.Get("encryption"),
		"security":      q.Get("security"),
		"type":          q.Get("type"),
		"sni":           q.Get("sni"),
		"fingerprint":   q.Get("fp"),
		"alpn":          q.Get("alpn"),
		"allowInsecure": q.Get("allowInsecure"),
		"flow":          q.Get("flow"),
		"tag":           q.Get("tag"),
		"pbk":           q.Get("pbk"),
		"sid":           q.Get("sid"),
		"spx":           q.Get("spx"),
	}, nil
}

func decodeBase64String(raw string) ([]byte, error) {
	if data, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	if data, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func (x *XrayManager) parseVMESS(link string) (*VMessConfig, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	decoded, err := decodeBase64String(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	var cfg VMessConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, fmt.Errorf("invalid VMess JSON: %w", err)
	}
	return &cfg, nil
}

func (x *XrayManager) parseSS(link string) (map[string]string, error) {
	raw := strings.TrimPrefix(link, "ss://")
	raw = strings.SplitN(raw, "#", 2)[0]
	raw = strings.TrimSpace(raw)

	payload := raw
	if !strings.Contains(raw, "@") {
		decoded, err := decodeBase64String(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid base64: %w", err)
		}
		payload = string(decoded)
	}

	parts := strings.Split(payload, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("unsupported SS link format")
	}

	auth := strings.SplitN(parts[0], ":", 2)
	if len(auth) != 2 {
		return nil, fmt.Errorf("invalid SS credentials")
	}

	hostPort := strings.Split(parts[1], ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("invalid SS address section")
	}

	return map[string]string{
		"method":   auth[0],
		"password": auth[1],
		"address":  hostPort[0],
		"port":     hostPort[1],
	}, nil
}

func (x *XrayManager) buildConfig(link string, port int) (*xrayFile, error) {
	switch {
	case strings.HasPrefix(link, "vless://"):
		cfg, err := x.parseVLESS(link)
		if err != nil {
			return nil, err
		}
		return generateVLESSConfig(cfg, port), nil
	case strings.HasPrefix(link, "vmess://"):
		cfg, err := x.parseVMESS(link)
		if err != nil {
			return nil, err
		}
		return generateVMESSConfig(cfg, port), nil
	case strings.HasPrefix(link, "ss://"):
		cfg, err := x.parseSS(link)
		if err != nil {
			return nil, err
		}
		return generateSSConfig(cfg, port), nil
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
}

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

	cmd := exec.CommandContext(ctx, "xray", "run", "-config", configPath)
	prefix := fmt.Sprintf("[xray-%s] ", name)
	cmd.Stdout = &taggedPrefixWriter{prefix: prefix, target: os.Stdout}
	cmd.Stderr = &taggedPrefixWriter{prefix: prefix, target: os.Stderr}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "[xray-%s] failed to kill: %v\n", name, err)
		} else {
			fmt.Fprintf(os.Stderr, "[xray-%s] process killed by context\n", name)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited with error: %v\n", name, err)
	} else {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited cleanly\n", name)
	}
	return err
}

func (x *XrayManager) ListXray() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			list = append(list, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return list, nil
}

func (x *XrayManager) ListAutoRun() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		cfg, err := x.readConfig(filepath.Join(x.baseDir, e.Name()))
		if err != nil {
			continue
		}
		if cfg.AutoRun {
			list = append(list, strings.TrimSuffix(e.Name(), ".yaml"))
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

func (x *XrayManager) IsXrayChain(name string) bool {
	if len(name) < 4 || name[:4] != "xray" {
		return false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	entries, err := os.ReadDir(x.baseDir)
	if err != nil {
		return false
	}
	target := name + ".yaml"
	for _, e := range entries {
		if !e.IsDir() && e.Name() == target {
			return true
		}
	}
	return false
}

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

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func defaultInbound(port int) map[string]interface{} {
	return map[string]interface{}{
		"port":     port,
		"protocol": "dokodemo-door",
		"settings": map[string]interface{}{
			"network":        "tcp,udp",
			"followRedirect": true,
			"timeout":        0,
		},
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
}

func generateVLESSConfig(cfg map[string]string, port int) *xrayFile {
	encryption := cfg["encryption"]
	if encryption == "" {
		encryption = "none"
	}
	tag := cfg["tag"]
	if tag == "" {
		tag = "vless-reality"
	}

	outbound := map[string]interface{}{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{{
				"address": cfg["address"],
				"port":    toInt(cfg["port"]),
				"users":   []map[string]interface{}{buildVLESSUser(cfg, encryption)},
			}},
		},
	}

	stream := map[string]interface{}{}
	if cfg["type"] != "" {
		stream["network"] = cfg["type"]
	}
	if cfg["security"] != "" {
		stream["security"] = cfg["security"]
		switch cfg["security"] {
		case "tls":
			tlsSettings := map[string]interface{}{}
			if cfg["sni"] != "" {
				tlsSettings["serverName"] = cfg["sni"]
			}
			if cfg["fingerprint"] != "" {
				tlsSettings["fingerprint"] = cfg["fingerprint"]
			}
			if cfg["alpn"] != "" {
				alpn := strings.Split(cfg["alpn"], ",")
				for i := range alpn {
					alpn[i] = strings.TrimSpace(alpn[i])
				}
				tlsSettings["alpn"] = alpn
			}
			if cfg["allowInsecure"] != "" {
				tlsSettings["allowInsecure"] = parseBoolFlag(cfg["allowInsecure"])
			}
			if len(tlsSettings) > 0 {
				stream["tlsSettings"] = tlsSettings
			}
		case "reality":
			realitySettings := map[string]interface{}{}
			if cfg["sni"] != "" {
				realitySettings["serverName"] = cfg["sni"]
			}
			if cfg["fingerprint"] != "" {
				realitySettings["fingerprint"] = cfg["fingerprint"]
			}
			if cfg["pbk"] != "" {
				realitySettings["publicKey"] = cfg["pbk"]
			}
			if cfg["sid"] != "" {
				realitySettings["shortId"] = cfg["sid"]
			}
			spiderX := cfg["spx"]
			if spiderX == "" {
				spiderX = "/"
			}
			realitySettings["spiderX"] = spiderX
			if len(realitySettings) > 0 {
				stream["realitySettings"] = realitySettings
			}
		}
	}
	if len(stream) > 0 {
		outbound["streamSettings"] = stream
	}

	return &xrayFile{
		Inbounds:  []map[string]interface{}{defaultInbound(port)},
		Outbounds: withDefaultOutbounds(outbound),
		Metadata: xrayMetadata{
			Protocol:   "vless",
			RemoteHost: cfg["address"],
			RemotePort: toInt(cfg["port"]),
			SocksPort:  port,
		},
	}
}

func buildVLESSUser(cfg map[string]string, encryption string) map[string]interface{} {
	user := map[string]interface{}{
		"id":         cfg["uuid"],
		"encryption": encryption,
		"level":      0,
	}
	if flow := cfg["flow"]; flow != "" {
		user["flow"] = flow
	}
	return user
}

func generateVMESSConfig(cfg *VMessConfig, port int) *xrayFile {
	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{{
				"address": cfg.Add,
				"port":    toInt(cfg.Port),
				"users": []map[string]interface{}{{
					"id":       cfg.ID,
					"alterId":  toInt(cfg.Aid),
					"security": "auto",
				}},
			}},
		},
	}

	stream := map[string]interface{}{}
	if cfg.Net != "" {
		stream["network"] = cfg.Net
	}
	if cfg.TLS != "" {
		stream["security"] = cfg.TLS
		if cfg.Host != "" {
			stream["tlsSettings"] = map[string]interface{}{
				"serverName": cfg.Host,
			}
		}
	}
	if len(stream) > 0 {
		outbound["streamSettings"] = stream
	}

	if cfg.Path != "" {
		if streamSettings, ok := outbound["streamSettings"].(map[string]interface{}); ok {
			streamSettings["wsSettings"] = map[string]interface{}{
				"path": cfg.Path,
			}
		} else {
			outbound["streamSettings"] = map[string]interface{}{
				"wsSettings": map[string]interface{}{
					"path": cfg.Path,
				},
			}
		}
	}

	return &xrayFile{
		Inbounds:  []map[string]interface{}{defaultInbound(port)},
		Outbounds: []map[string]interface{}{outbound},
		Metadata: xrayMetadata{
			Protocol:   "vmess",
			RemoteHost: cfg.Add,
			RemotePort: toInt(cfg.Port),
			SocksPort:  port,
		},
	}
}

func generateSSConfig(cfg map[string]string, port int) *xrayFile {
	outbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{{
				"address":  cfg["address"],
				"port":     toInt(cfg["port"]),
				"method":   cfg["method"],
				"password": cfg["password"],
			}},
		},
	}

	return &xrayFile{
		Inbounds:  []map[string]interface{}{defaultInbound(port)},
		Outbounds: []map[string]interface{}{outbound},
		Metadata: xrayMetadata{
			Protocol:   "shadowsocks",
			RemoteHost: cfg["address"],
			RemotePort: toInt(cfg["port"]),
			SocksPort:  port,
		},
	}
}

func parseBoolFlag(val string) bool {
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func withDefaultOutbounds(primary map[string]interface{}) []map[string]interface{} {
	direct := map[string]interface{}{
		"tag":      "direct",
		"protocol": "freedom",
	}
	block := map[string]interface{}{
		"tag":      "block",
		"protocol": "blackhole",
		"settings": map[string]interface{}{
			"response": map[string]interface{}{
				"type": "http",
			},
		},
	}
	return []map[string]interface{}{primary, direct, block}
}
