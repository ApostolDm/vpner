package network

import (
	"bytes"
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
	getAny := func(keys ...string) string {
		for _, key := range keys {
			if val := q.Get(key); val != "" {
				return val
			}
		}
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tag := getAny("tag")
	if tag == "" {
		tag = u.Fragment
	}
	return map[string]string{
		"uuid":                u.User.Username(),
		"address":             u.Hostname(),
		"port":                port,
		"encryption":          getAny("encryption"),
		"security":            getAny("security"),
		"type":                getAny("type", "transport", "network", "net"),
		"headerType":          getAny("headerType", "header"),
		"path":                getAny("path"),
		"host":                getAny("host"),
		"sni":                 getAny("sni", "serverName", "peer"),
		"fingerprint":         getAny("fp", "fingerprint"),
		"alpn":                getAny("alpn"),
		"allowInsecure":       getAny("allowInsecure", "insecure"),
		"flow":                getAny("flow"),
		"tag":                 tag,
		"pbk":                 getAny("pbk", "publicKey"),
		"sid":                 getAny("sid", "shortId"),
		"pqv":                 getAny("pqv", "mldsa65Verify"),
		"spx":                 getAny("spx", "spiderX"),
		"serviceName":         getAny("serviceName", "service"),
		"authority":           getAny("authority"),
		"mode":                getAny("mode"),
		"multiMode":           getAny("multiMode"),
		"idleTimeout":         getAny("idle_timeout", "idleTimeout"),
		"healthCheckTimeout":  getAny("health_check_timeout", "healthCheckTimeout"),
		"permitWithoutStream": getAny("permit_without_stream", "permitWithoutStream"),
		"initialWindowsSize":  getAny("initial_windows_size", "initialWindowsSize"),
		"userAgent":           getAny("user_agent", "userAgent"),
		"seed":                getAny("seed"),
		"mtu":                 getAny("mtu"),
		"tti":                 getAny("tti"),
		"uplinkCapacity":      getAny("uplinkCapacity", "upCap"),
		"downlinkCapacity":    getAny("downlinkCapacity", "downCap"),
		"congestion":          getAny("congestion"),
		"readBufferSize":      getAny("readBufferSize"),
		"writeBufferSize":     getAny("writeBufferSize"),
		"acceptProxyProtocol": getAny("acceptProxyProtocol"),
	}, nil
}

func decodeBase64String(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if data, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	if data, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	if data, err := base64.URLEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	if data, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func decodeJSONMap(raw []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var payload map[string]interface{}
	if err := dec.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func stringifyJSONValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []string:
		return strings.Join(v, ",")
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s := stringifyJSONValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func getJSONValue(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		val, ok := payload[key]
		if !ok || val == nil {
			continue
		}
		if s := stringifyJSONValue(val); s != "" {
			return s
		}
	}
	return ""
}

func (x *XrayManager) parseVMESS(link string) (map[string]string, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	decoded, err := decodeBase64String(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	payload, err := decodeJSONMap(decoded)
	if err != nil {
		return nil, fmt.Errorf("invalid VMess JSON: %w", err)
	}

	tag := getJSONValue(payload, "ps", "remark", "remarks", "name")
	address := getJSONValue(payload, "add", "address", "server")
	port := getJSONValue(payload, "port", "serverPort")
	uuid := getJSONValue(payload, "id", "uuid")
	aid := getJSONValue(payload, "aid", "alterId")
	cipher := getJSONValue(payload, "scy", "security")
	network := strings.ToLower(getJSONValue(payload, "net", "network"))
	headerType := getJSONValue(payload, "type")
	if network == "" {
		switch strings.ToLower(headerType) {
		case "tcp", "ws", "websocket", "grpc", "kcp", "mkcp", "httpupgrade", "xhttp", "splithttp":
			network = strings.ToLower(headerType)
			headerType = ""
		}
	}
	tlsVal := strings.ToLower(getJSONValue(payload, "tls"))
	streamSecurity := ""
	if tlsVal != "" && tlsVal != "none" {
		streamSecurity = tlsVal
	}
	if streamSecurity == "" {
		switch strings.ToLower(cipher) {
		case "tls", "reality", "xtls":
			streamSecurity = strings.ToLower(cipher)
			cipher = ""
		}
	}

	return map[string]string{
		"tag":                 tag,
		"address":             address,
		"port":                port,
		"uuid":                uuid,
		"aid":                 aid,
		"cipher":              cipher,
		"type":                network,
		"headerType":          headerType,
		"host":                getJSONValue(payload, "host"),
		"path":                getJSONValue(payload, "path"),
		"sni":                 getJSONValue(payload, "sni", "serverName", "peer"),
		"fingerprint":         getJSONValue(payload, "fp", "fingerprint"),
		"alpn":                getJSONValue(payload, "alpn"),
		"allowInsecure":       getJSONValue(payload, "allowInsecure", "insecure"),
		"security":            streamSecurity,
		"pbk":                 getJSONValue(payload, "pbk", "publicKey"),
		"sid":                 getJSONValue(payload, "sid", "shortId"),
		"pqv":                 getJSONValue(payload, "pqv", "mldsa65Verify"),
		"spx":                 getJSONValue(payload, "spx", "spiderX"),
		"serviceName":         getJSONValue(payload, "serviceName", "service"),
		"authority":           getJSONValue(payload, "authority"),
		"mode":                getJSONValue(payload, "mode"),
		"multiMode":           getJSONValue(payload, "multiMode"),
		"idleTimeout":         getJSONValue(payload, "idle_timeout", "idleTimeout"),
		"healthCheckTimeout":  getJSONValue(payload, "health_check_timeout", "healthCheckTimeout"),
		"permitWithoutStream": getJSONValue(payload, "permit_without_stream", "permitWithoutStream"),
		"initialWindowsSize":  getJSONValue(payload, "initial_windows_size", "initialWindowsSize"),
		"userAgent":           getJSONValue(payload, "user_agent", "userAgent"),
		"seed":                getJSONValue(payload, "seed"),
		"mtu":                 getJSONValue(payload, "mtu"),
		"tti":                 getJSONValue(payload, "tti"),
		"uplinkCapacity":      getJSONValue(payload, "uplinkCapacity", "upCap"),
		"downlinkCapacity":    getJSONValue(payload, "downlinkCapacity", "downCap"),
		"congestion":          getJSONValue(payload, "congestion"),
		"readBufferSize":      getJSONValue(payload, "readBufferSize"),
		"writeBufferSize":     getJSONValue(payload, "writeBufferSize"),
		"acceptProxyProtocol": getJSONValue(payload, "acceptProxyProtocol"),
	}, nil
}

func splitSSUserInfo(raw string) (string, string, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid SS credentials")
	}
	method, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("invalid SS method encoding: %w", err)
	}
	password, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid SS password encoding: %w", err)
	}
	return method, password, nil
}

func splitSSHostPort(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("invalid SS address section")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		return host, port, nil
	}
	if u, err := url.Parse("ss://" + raw); err == nil {
		if host := u.Hostname(); host != "" && u.Port() != "" {
			return host, u.Port(), nil
		}
	}
	if strings.Count(raw, ":") == 1 {
		if idx := strings.LastIndex(raw, ":"); idx != -1 {
			return raw[:idx], raw[idx+1:], nil
		}
	}
	return "", "", fmt.Errorf("invalid SS address section")
}

func (x *XrayManager) parseSS(link string) (map[string]string, error) {
	raw := strings.TrimPrefix(link, "ss://")
	raw = strings.TrimSpace(raw)

	tag := ""
	if idx := strings.Index(raw, "#"); idx != -1 {
		tagPart := raw[idx+1:]
		raw = raw[:idx]
		if decoded, err := url.PathUnescape(tagPart); err == nil {
			tag = decoded
		} else {
			tag = tagPart
		}
	}

	query := ""
	if idx := strings.Index(raw, "?"); idx != -1 {
		query = raw[idx+1:]
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)

	method := ""
	password := ""
	host := ""
	port := ""

	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		userInfo := parts[0]
		hostPort := parts[1]
		if !strings.Contains(userInfo, ":") {
			decoded, err := decodeBase64String(userInfo)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 credentials: %w", err)
			}
			userInfo = string(decoded)
		}
		var err error
		method, password, err = splitSSUserInfo(userInfo)
		if err != nil {
			return nil, err
		}
		host, port, err = splitSSHostPort(hostPort)
		if err != nil {
			return nil, err
		}
	} else {
		decoded, err := decodeBase64String(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 payload: %w", err)
		}
		payload := string(decoded)
		parts := strings.SplitN(payload, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unsupported SS link format")
		}
		method, password, err = splitSSUserInfo(parts[0])
		if err != nil {
			return nil, err
		}
		host, port, err = splitSSHostPort(parts[1])
		if err != nil {
			return nil, err
		}
	}

	cfg := map[string]string{
		"method":   method,
		"password": password,
		"address":  host,
		"port":     port,
	}
	if tag != "" {
		cfg["tag"] = tag
	}
	if query != "" {
		if values, err := url.ParseQuery(query); err == nil {
			if plugin := values.Get("plugin"); plugin != "" {
				cfg["plugin"] = plugin
			}
		}
	}
	return cfg, nil
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

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildStreamSettings(cfg map[string]string) map[string]interface{} {
	stream := map[string]interface{}{}
	network := strings.ToLower(cfg["type"])
	explicitNetwork := cfg["type"] != ""
	if network == "" {
		network = "tcp"
	}
	sni := cfg["sni"]
	if sni == "" {
		sni = cfg["host"]
	}
	security := strings.ToLower(cfg["security"])
	if security != "" {
		stream["security"] = security
		switch security {
		case "tls":
			tlsSettings := map[string]interface{}{}
			if sni != "" {
				tlsSettings["serverName"] = sni
			}
			if cfg["fingerprint"] != "" {
				tlsSettings["fingerprint"] = cfg["fingerprint"]
			}
			if cfg["alpn"] != "" {
				if alpn := splitCSV(cfg["alpn"]); len(alpn) > 0 {
					tlsSettings["alpn"] = alpn
				}
			}
			if cfg["allowInsecure"] != "" {
				tlsSettings["allowInsecure"] = parseBoolFlag(cfg["allowInsecure"])
			}
			if len(tlsSettings) > 0 {
				stream["tlsSettings"] = tlsSettings
			}
		case "reality":
			realitySettings := map[string]interface{}{}
			if sni != "" {
				realitySettings["serverName"] = sni
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
			if cfg["pqv"] != "" {
				realitySettings["mldsa65Verify"] = cfg["pqv"]
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

	if explicitNetwork {
		stream["network"] = network
	}
	switch network {
	case "tcp", "raw":
		tcpSettings := map[string]interface{}{}
		headerType := strings.ToLower(cfg["headerType"])
		if headerType != "" {
			header := map[string]interface{}{
				"type": headerType,
			}
			if headerType == "http" {
				request := map[string]interface{}{}
				path := cfg["path"]
				if path == "" {
					path = "/"
				}
				if path != "" {
					if uris := splitCSV(path); len(uris) > 0 {
						request["uri"] = uris
					}
				}
				host := cfg["host"]
				if host == "" {
					host = sni
				}
				if host != "" {
					hostValues := splitCSV(host)
					if len(hostValues) == 0 {
						hostValues = []string{host}
					}
					request["header"] = []map[string]interface{}{{
						"name":  "Host",
						"value": hostValues,
					}}
				}
				if len(request) > 0 {
					header["request"] = request
				}
			}
			tcpSettings["header"] = header
		}
		if cfg["acceptProxyProtocol"] != "" {
			tcpSettings["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
		}
		if len(tcpSettings) > 0 {
			stream["tcpSettings"] = tcpSettings
		}
	case "ws", "websocket":
		wsSettings := map[string]interface{}{}
		if cfg["path"] != "" {
			wsSettings["path"] = cfg["path"]
		}
		host := cfg["host"]
		if host == "" {
			host = sni
		}
		if host != "" {
			wsSettings["host"] = host
		}
		if cfg["acceptProxyProtocol"] != "" {
			wsSettings["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
		}
		if len(wsSettings) > 0 {
			stream["wsSettings"] = wsSettings
		}
	case "grpc":
		grpcSettings := map[string]interface{}{}
		serviceName := cfg["serviceName"]
		if serviceName == "" && cfg["path"] != "" {
			serviceName = strings.TrimPrefix(cfg["path"], "/")
		}
		if serviceName != "" {
			grpcSettings["serviceName"] = serviceName
		}
		authority := cfg["authority"]
		if authority == "" {
			authority = cfg["host"]
		}
		if authority == "" {
			authority = sni
		}
		if authority != "" {
			grpcSettings["authority"] = authority
		}
		mode := strings.ToLower(cfg["mode"])
		if mode == "multi" || mode == "multimode" || mode == "multi-mode" {
			grpcSettings["multiMode"] = true
		}
		if cfg["multiMode"] != "" {
			grpcSettings["multiMode"] = parseBoolFlag(cfg["multiMode"])
		}
		if cfg["idleTimeout"] != "" {
			grpcSettings["idle_timeout"] = toInt(cfg["idleTimeout"])
		}
		if cfg["healthCheckTimeout"] != "" {
			grpcSettings["health_check_timeout"] = toInt(cfg["healthCheckTimeout"])
		}
		if cfg["permitWithoutStream"] != "" {
			grpcSettings["permit_without_stream"] = parseBoolFlag(cfg["permitWithoutStream"])
		}
		if cfg["initialWindowsSize"] != "" {
			grpcSettings["initial_windows_size"] = toInt(cfg["initialWindowsSize"])
		}
		if cfg["userAgent"] != "" {
			grpcSettings["user_agent"] = cfg["userAgent"]
		}
		if len(grpcSettings) > 0 {
			stream["grpcSettings"] = grpcSettings
		}
	case "kcp", "mkcp":
		kcpSettings := map[string]interface{}{}
		if cfg["mtu"] != "" {
			kcpSettings["mtu"] = toInt(cfg["mtu"])
		}
		if cfg["tti"] != "" {
			kcpSettings["tti"] = toInt(cfg["tti"])
		}
		if cfg["uplinkCapacity"] != "" {
			kcpSettings["uplinkCapacity"] = toInt(cfg["uplinkCapacity"])
		}
		if cfg["downlinkCapacity"] != "" {
			kcpSettings["downlinkCapacity"] = toInt(cfg["downlinkCapacity"])
		}
		if cfg["congestion"] != "" {
			kcpSettings["congestion"] = parseBoolFlag(cfg["congestion"])
		}
		if cfg["readBufferSize"] != "" {
			kcpSettings["readBufferSize"] = toInt(cfg["readBufferSize"])
		}
		if cfg["writeBufferSize"] != "" {
			kcpSettings["writeBufferSize"] = toInt(cfg["writeBufferSize"])
		}
		if cfg["seed"] != "" {
			kcpSettings["seed"] = cfg["seed"]
		}
		kcpHeaderType := strings.ToLower(cfg["headerType"])
		if kcpHeaderType != "" {
			kcpSettings["header"] = map[string]interface{}{
				"type": kcpHeaderType,
			}
		}
		if len(kcpSettings) > 0 {
			stream["kcpSettings"] = kcpSettings
		}
	case "httpupgrade":
		httpUpgradeSettings := map[string]interface{}{}
		if cfg["path"] != "" {
			httpUpgradeSettings["path"] = cfg["path"]
		}
		host := cfg["host"]
		if host == "" {
			host = sni
		}
		if host != "" {
			httpUpgradeSettings["host"] = host
		}
		if cfg["acceptProxyProtocol"] != "" {
			httpUpgradeSettings["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
		}
		if len(httpUpgradeSettings) > 0 {
			stream["httpupgradeSettings"] = httpUpgradeSettings
		}
	case "xhttp", "splithttp":
		splitSettings := map[string]interface{}{}
		if cfg["path"] != "" {
			splitSettings["path"] = cfg["path"]
		}
		host := cfg["host"]
		if host == "" {
			host = sni
		}
		if host != "" {
			splitSettings["host"] = host
		}
		if cfg["mode"] != "" {
			splitSettings["mode"] = strings.ToLower(cfg["mode"])
		}
		if len(splitSettings) > 0 {
			stream["splithttpSettings"] = splitSettings
		}
	}

	if !explicitNetwork && len(stream) > 0 {
		stream["network"] = network
	}
	if len(stream) == 0 {
		return nil
	}
	return stream
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

	if stream := buildStreamSettings(cfg); len(stream) > 0 {
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

func generateVMESSConfig(cfg map[string]string, port int) *xrayFile {
	security := cfg["cipher"]
	if security == "" {
		security = "auto"
	}
	user := map[string]interface{}{
		"id":       cfg["uuid"],
		"security": security,
	}
	if cfg["aid"] != "" {
		user["alterId"] = toInt(cfg["aid"])
	}

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{{
				"address": cfg["address"],
				"port":    toInt(cfg["port"]),
				"users":   []map[string]interface{}{user},
			}},
		},
	}
	if tag := cfg["tag"]; tag != "" {
		outbound["tag"] = tag
	}

	if stream := buildStreamSettings(cfg); len(stream) > 0 {
		outbound["streamSettings"] = stream
	}

	return &xrayFile{
		Inbounds:  []map[string]interface{}{defaultInbound(port)},
		Outbounds: []map[string]interface{}{outbound},
		Metadata: xrayMetadata{
			Protocol:   "vmess",
			RemoteHost: cfg["address"],
			RemotePort: toInt(cfg["port"]),
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
	if tag := cfg["tag"]; tag != "" {
		outbound["tag"] = tag
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
