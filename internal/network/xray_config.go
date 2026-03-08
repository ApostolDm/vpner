package network

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

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

// --- VLESS ---

func generateVLESSConfig(cfg map[string]string, port int) *xrayFile {
	encryption := cfg["encryption"]
	if encryption == "" {
		encryption = "none"
	}
	tag := cfg["tag"]
	if tag == "" {
		tag = "vless-reality"
	}

	user := map[string]interface{}{
		"id":         cfg["uuid"],
		"encryption": encryption,
		"level":      0,
	}
	if flow := cfg["flow"]; flow != "" {
		user["flow"] = flow
	}

	outbound := map[string]interface{}{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{{
				"address": cfg["address"],
				"port":    toInt(cfg["port"]),
				"users":   []map[string]interface{}{user},
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

// --- VMess ---

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

// --- Shadowsocks ---

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

// --- stream settings ---

func buildStreamSettings(cfg map[string]string) map[string]interface{} {
	stream := map[string]interface{}{}
	network := strings.ToLower(cfg["type"])
	if network == "" {
		network = "tcp"
	}
	sni := cfg["sni"]
	if sni == "" {
		sni = cfg["host"]
	}

	addSecuritySettings(stream, cfg, sni)
	addTransportSettings(stream, cfg, network, sni)

	if len(stream) == 0 {
		return nil
	}
	stream["network"] = network
	return stream
}

func addSecuritySettings(stream map[string]interface{}, cfg map[string]string, sni string) {
	security := strings.ToLower(cfg["security"])
	if security == "" {
		return
	}
	stream["security"] = security

	switch security {
	case "tls":
		s := map[string]interface{}{}
		setIfNotEmpty(s, "serverName", sni)
		setIfNotEmpty(s, "fingerprint", cfg["fingerprint"])
		if alpn := splitCSV(cfg["alpn"]); len(alpn) > 0 {
			s["alpn"] = alpn
		}
		if cfg["allowInsecure"] != "" {
			s["allowInsecure"] = parseBoolFlag(cfg["allowInsecure"])
		}
		if len(s) > 0 {
			stream["tlsSettings"] = s
		}

	case "reality":
		s := map[string]interface{}{}
		setIfNotEmpty(s, "serverName", sni)
		setIfNotEmpty(s, "fingerprint", cfg["fingerprint"])
		setIfNotEmpty(s, "publicKey", cfg["pbk"])
		setIfNotEmpty(s, "shortId", cfg["sid"])
		setIfNotEmpty(s, "mldsa65Verify", cfg["pqv"])
		spiderX := cfg["spx"]
		if spiderX == "" {
			spiderX = "/"
		}
		s["spiderX"] = spiderX
		if len(s) > 0 {
			stream["realitySettings"] = s
		}
	}
}

func addTransportSettings(stream map[string]interface{}, cfg map[string]string, network, sni string) {
	var settings map[string]interface{}
	var key string

	switch network {
	case "tcp", "raw":
		settings = buildTCPSettings(cfg, sni)
		key = "tcpSettings"
	case "ws", "websocket":
		settings = buildWSSettings(cfg, sni)
		key = "wsSettings"
	case "grpc":
		settings = buildGRPCSettings(cfg, sni)
		key = "grpcSettings"
	case "kcp", "mkcp":
		settings = buildKCPSettings(cfg)
		key = "kcpSettings"
	case "httpupgrade":
		settings = buildHTTPUpgradeSettings(cfg, sni)
		key = "httpupgradeSettings"
	case "xhttp", "splithttp":
		settings = buildSplitHTTPSettings(cfg, sni)
		key = "splithttpSettings"
	}

	if len(settings) > 0 {
		stream[key] = settings
	}
}

func buildTCPSettings(cfg map[string]string, sni string) map[string]interface{} {
	s := map[string]interface{}{}
	headerType := strings.ToLower(cfg["headerType"])
	if headerType != "" {
		header := map[string]interface{}{"type": headerType}
		if headerType == "http" {
			request := map[string]interface{}{}
			path := cfg["path"]
			if path == "" {
				path = "/"
			}
			if uris := splitCSV(path); len(uris) > 0 {
				request["uri"] = uris
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
		s["header"] = header
	}
	if cfg["acceptProxyProtocol"] != "" {
		s["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
	}
	return s
}

func buildWSSettings(cfg map[string]string, sni string) map[string]interface{} {
	s := map[string]interface{}{}
	setIfNotEmpty(s, "path", cfg["path"])
	host := cfg["host"]
	if host == "" {
		host = sni
	}
	setIfNotEmpty(s, "host", host)
	if cfg["acceptProxyProtocol"] != "" {
		s["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
	}
	return s
}

func buildGRPCSettings(cfg map[string]string, sni string) map[string]interface{} {
	s := map[string]interface{}{}
	serviceName := cfg["serviceName"]
	if serviceName == "" && cfg["path"] != "" {
		serviceName = strings.TrimPrefix(cfg["path"], "/")
	}
	setIfNotEmpty(s, "serviceName", serviceName)

	authority := cfg["authority"]
	if authority == "" {
		authority = cfg["host"]
	}
	if authority == "" {
		authority = sni
	}
	setIfNotEmpty(s, "authority", authority)

	mode := strings.ToLower(cfg["mode"])
	if mode == "multi" || mode == "multimode" || mode == "multi-mode" {
		s["multiMode"] = true
	}
	if cfg["multiMode"] != "" {
		s["multiMode"] = parseBoolFlag(cfg["multiMode"])
	}
	setIntIfNotEmpty(s, "idle_timeout", cfg["idleTimeout"])
	setIntIfNotEmpty(s, "health_check_timeout", cfg["healthCheckTimeout"])
	if cfg["permitWithoutStream"] != "" {
		s["permit_without_stream"] = parseBoolFlag(cfg["permitWithoutStream"])
	}
	setIntIfNotEmpty(s, "initial_windows_size", cfg["initialWindowsSize"])
	setIfNotEmpty(s, "user_agent", cfg["userAgent"])
	return s
}

func buildKCPSettings(cfg map[string]string) map[string]interface{} {
	s := map[string]interface{}{}
	setIntIfNotEmpty(s, "mtu", cfg["mtu"])
	setIntIfNotEmpty(s, "tti", cfg["tti"])
	setIntIfNotEmpty(s, "uplinkCapacity", cfg["uplinkCapacity"])
	setIntIfNotEmpty(s, "downlinkCapacity", cfg["downlinkCapacity"])
	if cfg["congestion"] != "" {
		s["congestion"] = parseBoolFlag(cfg["congestion"])
	}
	setIntIfNotEmpty(s, "readBufferSize", cfg["readBufferSize"])
	setIntIfNotEmpty(s, "writeBufferSize", cfg["writeBufferSize"])
	setIfNotEmpty(s, "seed", cfg["seed"])
	if headerType := strings.ToLower(cfg["headerType"]); headerType != "" {
		s["header"] = map[string]interface{}{"type": headerType}
	}
	return s
}

func buildHTTPUpgradeSettings(cfg map[string]string, sni string) map[string]interface{} {
	s := map[string]interface{}{}
	setIfNotEmpty(s, "path", cfg["path"])
	host := cfg["host"]
	if host == "" {
		host = sni
	}
	setIfNotEmpty(s, "host", host)
	if cfg["acceptProxyProtocol"] != "" {
		s["acceptProxyProtocol"] = parseBoolFlag(cfg["acceptProxyProtocol"])
	}
	return s
}

func buildSplitHTTPSettings(cfg map[string]string, sni string) map[string]interface{} {
	s := map[string]interface{}{}
	setIfNotEmpty(s, "path", cfg["path"])
	host := cfg["host"]
	if host == "" {
		host = sni
	}
	setIfNotEmpty(s, "host", host)
	if cfg["mode"] != "" {
		s["mode"] = strings.ToLower(cfg["mode"])
	}
	return s
}

// --- VLESS encryption fix ---

func fixVLESSUserEncryption(cfg *xrayFile) bool {
	changed := false
	for _, outbound := range cfg.Outbounds {
		protocol, _ := outbound["protocol"].(string)
		if protocol != "vless" {
			continue
		}
		settings, ok := outbound["settings"].(map[string]interface{})
		if !ok {
			continue
		}
		vnext, ok := settings["vnext"].([]interface{})
		if !ok {
			continue
		}
		for _, entry := range vnext {
			entryMap, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			users, ok := entryMap["users"].([]interface{})
			if !ok {
				continue
			}
			for _, user := range users {
				userMap, ok := user.(map[string]interface{})
				if !ok {
					continue
				}
				value, exists := userMap["encryption"]
				if !exists || value == nil {
					userMap["encryption"] = "none"
					changed = true
					continue
				}
				if v, ok := value.(string); ok && strings.TrimSpace(v) == "" {
					userMap["encryption"] = "none"
					changed = true
				}
			}
		}
	}
	return changed
}

func (x *XrayManager) ensureVLESSUserEncryption(path string) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	cfg, err := x.readConfig(path)
	if err != nil {
		return err
	}
	if !fixVLESSUserEncryption(cfg) {
		return nil
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// --- shared helpers ---

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

func withDefaultOutbounds(primary map[string]interface{}) []map[string]interface{} {
	return []map[string]interface{}{
		primary,
		{"tag": "direct", "protocol": "freedom"},
		{
			"tag":      "block",
			"protocol": "blackhole",
			"settings": map[string]interface{}{
				"response": map[string]interface{}{"type": "http"},
			},
		},
	}
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseBoolFlag(val string) bool {
	switch strings.ToLower(val) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func setIfNotEmpty(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func setIntIfNotEmpty(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = toInt(val)
	}
}
