package proxy

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

type Protocol string

const (
	ProtoVLESS Protocol = "vless"
	ProtoVMESS Protocol = "vmess"
	ProtoSS    Protocol = "shadowsocks"
)

type Link struct {
	Protocol Protocol
	Tag      string
	Address  string
	Port     int

	UUID       string
	AlterID    int
	Cipher     string
	Encryption string
	Flow       string
	Method     string
	Password   string
	Plugin     string

	Network       string
	Security      string
	HeaderType    string
	Path          string
	Host          string
	SNI           string
	ALPN          string
	Fingerprint   string
	AllowInsecure bool

	PublicKey     string
	ShortID       string
	MLDSA65Verify string
	SpiderX       string

	ServiceName         string
	Authority           string
	Mode                string
	MultiMode           bool
	IdleTimeout         int
	HealthCheckTimeout  int
	PermitWithoutStream bool
	InitialWindowsSize  int
	UserAgent           string

	Seed             string
	MTU              int
	TTI              int
	UplinkCapacity   int
	DownlinkCapacity int
	ReadBufferSize   int
	WriteBufferSize  int
	Congestion       bool

	AcceptProxyProtocol bool
}

func ParseLink(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMESS(raw)
	case strings.HasPrefix(raw, "ss://"):
		return parseSS(raw)
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
}

func parseVLESS(raw string) (*Link, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" {
		return nil, fmt.Errorf("invalid VLESS URL")
	}
	q := query(u.Query())

	port := atoiDefault(u.Port(), 443)
	tag := firstNonEmpty(q.get("tag"), u.Fragment)

	return &Link{
		Protocol:            ProtoVLESS,
		Tag:                 tag,
		Address:             u.Hostname(),
		Port:                port,
		UUID:                u.User.Username(),
		Encryption:          q.get("encryption"),
		Flow:                q.get("flow"),
		Network:             firstNonEmpty(q.get("type", "transport", "network", "net"), "tcp"),
		Security:            q.get("security"),
		HeaderType:          q.get("headerType", "header"),
		Path:                q.get("path"),
		Host:                q.get("host"),
		SNI:                 q.get("sni", "serverName", "peer"),
		ALPN:                q.get("alpn"),
		Fingerprint:         q.get("fp", "fingerprint"),
		AllowInsecure:       q.boolGet("allowInsecure", "insecure"),
		PublicKey:           q.get("pbk", "publicKey"),
		ShortID:             q.get("sid", "shortId"),
		MLDSA65Verify:       q.get("pqv", "mldsa65Verify"),
		SpiderX:             q.get("spx", "spiderX"),
		ServiceName:         q.get("serviceName", "service"),
		Authority:           q.get("authority"),
		Mode:                q.get("mode"),
		MultiMode:           q.boolGet("multiMode"),
		IdleTimeout:         q.intGet("idle_timeout", "idleTimeout"),
		HealthCheckTimeout:  q.intGet("health_check_timeout", "healthCheckTimeout"),
		PermitWithoutStream: q.boolGet("permit_without_stream", "permitWithoutStream"),
		InitialWindowsSize:  q.intGet("initial_windows_size", "initialWindowsSize"),
		UserAgent:           q.get("user_agent", "userAgent"),
		Seed:                q.get("seed"),
		MTU:                 q.intGet("mtu"),
		TTI:                 q.intGet("tti"),
		UplinkCapacity:      q.intGet("uplinkCapacity", "upCap"),
		DownlinkCapacity:    q.intGet("downlinkCapacity", "downCap"),
		ReadBufferSize:      q.intGet("readBufferSize"),
		WriteBufferSize:     q.intGet("writeBufferSize"),
		Congestion:          q.boolGet("congestion"),
		AcceptProxyProtocol: q.boolGet("acceptProxyProtocol"),
	}, nil
}

func parseVMESS(raw string) (*Link, error) {
	decoded, err := decodeBase64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	p, err := decodeJSONMap(decoded)
	if err != nil {
		return nil, fmt.Errorf("invalid VMess JSON: %w", err)
	}

	network := strings.ToLower(p.get("net", "network"))
	headerType := p.get("type")

	if network == "" {
		switch strings.ToLower(headerType) {
		case "tcp", "ws", "websocket", "grpc", "kcp", "mkcp", "httpupgrade", "xhttp", "splithttp":
			network, headerType = strings.ToLower(headerType), ""
		}
	}
	if network == "" {
		network = "tcp"
	}

	cipher := p.get("scy", "security")
	security := strings.ToLower(p.get("tls"))
	if security == "none" {
		security = ""
	}

	if security == "" {
		switch strings.ToLower(cipher) {
		case "tls", "reality", "xtls":
			security, cipher = strings.ToLower(cipher), ""
		}
	}

	return &Link{
		Protocol:            ProtoVMESS,
		Tag:                 p.get("ps", "remark", "remarks", "name"),
		Address:             p.get("add", "address", "server"),
		Port:                p.int("port", "serverPort"),
		UUID:                p.get("id", "uuid"),
		AlterID:             p.int("aid", "alterId"),
		Cipher:              cipher,
		Network:             network,
		Security:            security,
		HeaderType:          headerType,
		Host:                p.get("host"),
		Path:                p.get("path"),
		SNI:                 p.get("sni", "serverName", "peer"),
		ALPN:                p.get("alpn"),
		Fingerprint:         p.get("fp", "fingerprint"),
		AllowInsecure:       p.bool("allowInsecure", "insecure"),
		PublicKey:           p.get("pbk", "publicKey"),
		ShortID:             p.get("sid", "shortId"),
		MLDSA65Verify:       p.get("pqv", "mldsa65Verify"),
		SpiderX:             p.get("spx", "spiderX"),
		ServiceName:         p.get("serviceName", "service"),
		Authority:           p.get("authority"),
		Mode:                p.get("mode"),
		MultiMode:           p.bool("multiMode"),
		IdleTimeout:         p.int("idle_timeout", "idleTimeout"),
		HealthCheckTimeout:  p.int("health_check_timeout", "healthCheckTimeout"),
		PermitWithoutStream: p.bool("permit_without_stream", "permitWithoutStream"),
		InitialWindowsSize:  p.int("initial_windows_size", "initialWindowsSize"),
		UserAgent:           p.get("user_agent", "userAgent"),
		Seed:                p.get("seed"),
		MTU:                 p.int("mtu"),
		TTI:                 p.int("tti"),
		UplinkCapacity:      p.int("uplinkCapacity", "upCap"),
		DownlinkCapacity:    p.int("downlinkCapacity", "downCap"),
		ReadBufferSize:      p.int("readBufferSize"),
		WriteBufferSize:     p.int("writeBufferSize"),
		Congestion:          p.bool("congestion"),
		AcceptProxyProtocol: p.bool("acceptProxyProtocol"),
	}, nil
}

func parseSS(raw string) (*Link, error) {
	body := strings.TrimSpace(strings.TrimPrefix(raw, "ss://"))

	var tag string
	if i := strings.IndexByte(body, '#'); i >= 0 {
		tag = unescape(body[i+1:])
		body = body[:i]
	}
	var rawQuery string
	if i := strings.IndexByte(body, '?'); i >= 0 {
		rawQuery = body[i+1:]
		body = body[:i]
	}
	body = strings.TrimSpace(body)

	var userInfo, hostPort string
	if i := strings.LastIndexByte(body, '@'); i >= 0 {

		userInfo, hostPort = body[:i], body[i+1:]
		if !strings.Contains(userInfo, ":") {
			decoded, err := decodeBase64(userInfo)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 credentials: %w", err)
			}
			userInfo = string(decoded)
		}
	} else {

		decoded, err := decodeBase64(body)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 payload: %w", err)
		}
		i := strings.LastIndexByte(string(decoded), '@')
		if i < 0 {
			return nil, fmt.Errorf("unsupported SS link format")
		}
		userInfo, hostPort = string(decoded)[:i], string(decoded)[i+1:]
	}

	method, password, err := splitColon(userInfo, "SS credentials")
	if err != nil {
		return nil, err
	}
	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	link := &Link{
		Protocol: ProtoSS,
		Tag:      tag,
		Address:  host,
		Port:     port,
		Method:   unescape(method),
		Password: unescape(password),
	}
	if rawQuery != "" {
		if vals, err := url.ParseQuery(rawQuery); err == nil {
			link.Plugin = vals.Get("plugin")
		}
	}
	return link, nil
}

type query url.Values

func (q query) get(keys ...string) string {
	for _, k := range keys {
		if v := url.Values(q).Get(k); v != "" {
			return v
		}
	}
	return ""
}

func (q query) intGet(keys ...string) int   { return atoiDefault(q.get(keys...), 0) }
func (q query) boolGet(keys ...string) bool { return parseBool(q.get(keys...)) }

type jsonMap map[string]any

func (m jsonMap) get(keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			if s := stringify(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func (m jsonMap) int(keys ...string) int   { return atoiDefault(m.get(keys...), 0) }
func (m jsonMap) bool(keys ...string) bool { return parseBool(m.get(keys...)) }

func decodeBase64(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if data, err := enc.DecodeString(raw); err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func decodeJSONMap(raw []byte) (jsonMap, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m jsonMap
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s := stringify(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func splitColon(raw, what string) (string, string, error) {
	method, password, ok := strings.Cut(raw, ":")
	if !ok {
		return "", "", fmt.Errorf("invalid %s", what)
	}
	return method, password, nil
}

func splitHostPort(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("invalid SS address section")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		return host, atoiDefault(port, 0), nil
	}
	if u, err := url.Parse("ss://" + raw); err == nil {
		if h, p := u.Hostname(), u.Port(); h != "" && p != "" {
			return h, atoiDefault(p, 0), nil
		}
	}
	if host, port, ok := strings.Cut(raw, ":"); ok && !strings.Contains(port, ":") {
		return host, atoiDefault(port, 0), nil
	}
	return "", 0, fmt.Errorf("invalid SS address section")
}

func unescape(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
