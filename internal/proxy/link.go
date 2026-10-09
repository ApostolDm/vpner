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
	ProtoVLESS     Protocol = "vless"
	ProtoVMESS     Protocol = "vmess"
	ProtoSS        Protocol = "shadowsocks"
	ProtoTrojan    Protocol = "trojan"
	ProtoHysteria2 Protocol = "hysteria2"
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

	ECH                  string
	VerifyPeerCertByName string
	PinnedPeerCertSha256 string
	XPaddingBytes        string
	Extra                map[string]any
	FinalMask            map[string]any

	Obfs         string
	ObfsPassword string
	PacketSize   string
	HopPorts     string

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
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		return parseHysteria2(raw)
	case strings.HasPrefix(raw, "tuic://"):
		return nil, fmt.Errorf("TUIC is not supported by Xray-core (3x-ui runs it inside the panel); use a vless/vmess/trojan/shadowsocks/hysteria2 inbound instead")
	case strings.HasPrefix(raw, "vpn://"), strings.HasPrefix(raw, "wireguard://"), strings.HasPrefix(raw, "wg://"), strings.HasPrefix(raw, "[Interface]"):
		return nil, fmt.Errorf("WireGuard/AmneziaWG configs cannot run inside xray; import the config as a Keenetic WireGuard connection (ASC parameters are supported natively) and add it with 'vpnerctl interface add'")
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

	l := linkFromQuery(q)
	l.Protocol = ProtoVLESS
	l.Tag = firstNonEmpty(q.get("tag"), u.Fragment)
	l.Address = u.Hostname()
	l.Port = atoiDefault(u.Port(), 443)
	l.UUID = u.User.Username()
	l.Encryption = q.get("encryption")
	l.Flow = q.get("flow")
	return l, nil
}

func parseTrojan(raw string) (*Link, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "trojan" {
		return nil, fmt.Errorf("invalid Trojan URL")
	}
	password := u.User.Username()
	if rest, ok := u.User.Password(); ok {
		password += ":" + rest
	}
	if password == "" {
		return nil, fmt.Errorf("invalid Trojan URL: missing password")
	}
	q := query(u.Query())

	l := linkFromQuery(q)
	l.Protocol = ProtoTrojan
	l.Tag = firstNonEmpty(q.get("tag"), u.Fragment)
	l.Address = u.Hostname()
	l.Port = atoiDefault(u.Port(), 443)
	l.Password = password
	return l, nil
}

func parseHysteria2(raw string) (*Link, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "hysteria2" && u.Scheme != "hy2") {
		return nil, fmt.Errorf("invalid Hysteria2 URL")
	}
	auth := u.User.Username()
	if rest, ok := u.User.Password(); ok {
		auth += ":" + rest
	}
	q := query(u.Query())

	l := linkFromQuery(q)
	l.Protocol = ProtoHysteria2
	l.Tag = firstNonEmpty(q.get("tag"), u.Fragment)
	l.Address = u.Hostname()
	l.Port = atoiDefault(u.Port(), 443)
	l.Password = auth
	l.Network = "hysteria"
	l.Security = "tls"
	l.PinnedPeerCertSha256 = firstNonEmpty(q.get("pinSHA256"), l.PinnedPeerCertSha256)
	l.Obfs = strings.ToLower(q.get("obfs"))
	l.ObfsPassword = q.get("obfs-password", "obfs_password", "obfsPassword")
	if minSize, maxSize := q.intGet("minPacketSize"), q.intGet("maxPacketSize"); l.Obfs == "gecko" && minSize > 0 && maxSize >= minSize && maxSize <= 2048 {
		l.PacketSize = fmt.Sprintf("%d-%d", minSize, maxSize)
	}
	l.HopPorts = q.get("mport")
	if err := validateHysteriaECH(l.ECH); err != nil {
		return nil, fmt.Errorf("invalid Hysteria2 ECH: %w; replace ech/echConfigList with a valid config, or remove it to connect without ECH (the server name will be visible)", err)
	}
	return l, nil
}

func linkFromQuery(q query) *Link {
	return &Link{
		Network:              firstNonEmpty(q.get("type", "transport", "network", "net"), "tcp"),
		Security:             inferSecurity(q),
		HeaderType:           q.get("headerType", "header"),
		Path:                 q.get("path"),
		Host:                 q.get("host"),
		SNI:                  q.get("sni", "serverName", "peer"),
		ALPN:                 q.get("alpn"),
		Fingerprint:          q.get("fp", "fingerprint"),
		AllowInsecure:        q.boolGet("allowInsecure", "insecure"),
		PublicKey:            q.get("pbk", "publicKey"),
		ShortID:              q.get("sid", "shortId"),
		MLDSA65Verify:        q.get("pqv", "mldsa65Verify"),
		SpiderX:              q.get("spx", "spiderX"),
		ECH:                  q.get("ech", "echConfigList"),
		VerifyPeerCertByName: q.get("vcn", "verifyPeerCertByName"),
		PinnedPeerCertSha256: q.get("pcs", "pinnedPeerCertSha256"),
		ServiceName:          q.get("serviceName", "service"),
		Authority:            q.get("authority"),
		Mode:                 q.get("mode"),
		MultiMode:            q.boolGet("multiMode"),
		IdleTimeout:          q.intGet("idle_timeout", "idleTimeout"),
		HealthCheckTimeout:   q.intGet("health_check_timeout", "healthCheckTimeout"),
		PermitWithoutStream:  q.boolGet("permit_without_stream", "permitWithoutStream"),
		InitialWindowsSize:   q.intGet("initial_windows_size", "initialWindowsSize"),
		UserAgent:            q.get("user_agent", "userAgent"),
		Seed:                 q.get("seed"),
		MTU:                  q.intGet("mtu"),
		TTI:                  q.intGet("tti"),
		UplinkCapacity:       q.intGet("uplinkCapacity", "upCap"),
		DownlinkCapacity:     q.intGet("downlinkCapacity", "downCap"),
		ReadBufferSize:       q.intGet("readBufferSize"),
		WriteBufferSize:      q.intGet("writeBufferSize"),
		Congestion:           q.boolGet("congestion"),
		AcceptProxyProtocol:  q.boolGet("acceptProxyProtocol"),
		XPaddingBytes:        q.get("x_padding_bytes", "xPaddingBytes"),
		Extra:                jsonObject(q.get("extra")),
		FinalMask:            jsonObject(q.get("fm", "finalmask")),
	}
}

func inferSecurity(q query) string {
	switch security := strings.ToLower(q.get("security")); {
	case security != "":
		return security
	case q.get("pbk", "publicKey") != "":
		return "reality"
	case q.get("sni", "serverName", "peer") != "":
		return "tls"
	default:
		return ""
	}
}

func jsonObject(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	m, err := decodeJSONMap([]byte(raw))
	if err != nil || len(m) == 0 {
		return nil
	}
	return map[string]any(m)
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
	if strings.EqualFold(headerType, "none") {
		headerType = ""
	}
	var mode string
	multiMode := p.bool("multiMode") || strings.EqualFold(p.get("mode"), "multi")
	switch canonicalNetwork(network) {
	case "grpc":
		multiMode = multiMode || strings.EqualFold(headerType, "multi")
		headerType = ""
	case "xhttp":
		mode, headerType = xhttpMode(firstNonEmpty(p.get("mode"), headerType)), ""
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
		Protocol:             ProtoVMESS,
		Tag:                  p.get("ps", "remark", "remarks", "name"),
		Address:              p.get("add", "address", "server"),
		Port:                 p.int("port", "serverPort"),
		UUID:                 p.get("id", "uuid"),
		AlterID:              p.int("aid", "alterId"),
		Cipher:               cipher,
		Network:              network,
		Security:             security,
		HeaderType:           headerType,
		Host:                 p.get("host"),
		Path:                 p.get("path"),
		SNI:                  p.get("sni", "serverName", "peer"),
		ALPN:                 p.get("alpn"),
		Fingerprint:          p.get("fp", "fingerprint"),
		AllowInsecure:        p.bool("allowInsecure", "insecure"),
		PublicKey:            p.get("pbk", "publicKey"),
		ShortID:              p.get("sid", "shortId"),
		MLDSA65Verify:        p.get("pqv", "mldsa65Verify"),
		SpiderX:              p.get("spx", "spiderX"),
		ECH:                  p.get("ech", "echConfigList"),
		VerifyPeerCertByName: p.get("vcn", "verifyPeerCertByName"),
		PinnedPeerCertSha256: p.get("pcs", "pinnedPeerCertSha256"),
		ServiceName:          firstNonEmpty(p.get("serviceName", "service"), grpcServiceFromPath(network, p.get("path"))),
		Authority:            p.get("authority"),
		Mode:                 mode,
		MultiMode:            multiMode,
		IdleTimeout:          p.int("idle_timeout", "idleTimeout"),
		HealthCheckTimeout:   p.int("health_check_timeout", "healthCheckTimeout"),
		PermitWithoutStream:  p.bool("permit_without_stream", "permitWithoutStream"),
		InitialWindowsSize:   p.int("initial_windows_size", "initialWindowsSize"),
		UserAgent:            p.get("user_agent", "userAgent"),
		Seed:                 p.get("seed"),
		MTU:                  p.int("mtu"),
		TTI:                  p.int("tti"),
		UplinkCapacity:       p.int("uplinkCapacity", "upCap"),
		DownlinkCapacity:     p.int("downlinkCapacity", "downCap"),
		ReadBufferSize:       p.int("readBufferSize"),
		WriteBufferSize:      p.int("writeBufferSize"),
		Congestion:           p.bool("congestion"),
		AcceptProxyProtocol:  p.bool("acceptProxyProtocol"),
		XPaddingBytes:        p.get("x_padding_bytes", "xPaddingBytes"),
		Extra:                vmessExtra(p),
		FinalMask:            jsonObject(p.get("fm", "finalmask")),
	}, nil
}

func xhttpMode(raw string) string {
	switch mode := strings.ToLower(strings.TrimSpace(raw)); mode {
	case "auto", "packet-up", "stream-up", "stream-one":
		return mode
	default:
		return ""
	}
}

func grpcServiceFromPath(network, path string) string {
	if canonicalNetwork(network) != "grpc" {
		return ""
	}
	return strings.TrimPrefix(path, "/")
}

var xhttpExtraKeys = []string{
	"xPaddingBytes", "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod",
	"uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey", "sessionIDTable", "sessionIDLength",
	"seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize",
	"scMaxEachPostBytes", "scMinPostsIntervalMs", "scMaxBufferedPosts", "scStreamUpServerSecs",
	"noGRPCHeader", "noSSEHeader", "xmux", "downloadSettings", "headers", "sessionPlacement", "sessionKey",
}

func vmessExtra(p jsonMap) map[string]any {
	if raw, ok := p["extra"]; ok {
		switch v := raw.(type) {
		case string:
			return jsonObject(v)
		case map[string]any:
			if len(v) > 0 {
				return v
			}
		}
	}
	extra := map[string]any{}
	for _, key := range xhttpExtraKeys {
		if v, ok := p[key]; ok && v != nil {
			extra[key] = v
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
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
		if decoded := unescape(userInfo); strings.Contains(decoded, ":") {
			userInfo = decoded
		} else {
			raw, err := decodeBase64(decoded)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 credentials: %w", err)
			}
			userInfo = string(raw)
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

	link := &Link{Network: "tcp"}
	if rawQuery != "" {
		if vals, err := url.ParseQuery(rawQuery); err == nil {
			q := query(vals)
			link = linkFromQuery(q)
			if err := applySSPlugin(link, q.get("plugin")); err != nil {
				return nil, err
			}
		}
	}
	link.Protocol = ProtoSS
	link.Tag = tag
	link.Address = host
	link.Port = port
	link.Method = method
	link.Password = password
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

func applySSPlugin(l *Link, plugin string) error {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return nil
	}
	name, rawOpts, _ := strings.Cut(plugin, ";")
	opts := map[string]string{}
	for _, kv := range strings.Split(rawOpts, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			opts[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if (name == "obfs-local" || name == "simple-obfs") && opts["obfs"] == "http" {
		l.Network = "tcp"
		l.HeaderType = "http"
		l.Host = firstNonEmpty(opts["obfs-host"], l.Host)
		return nil
	}
	return fmt.Errorf("shadowsocks plugin %q is not supported by xray", plugin)
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
