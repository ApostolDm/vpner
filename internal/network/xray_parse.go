package network

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

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

// --- helpers ---

func decodeBase64String(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if data, err := enc.DecodeString(raw); err == nil {
			return data, nil
		}
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
