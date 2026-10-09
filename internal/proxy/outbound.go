package proxy

import "strings"

type jobj = map[string]any

func buildOutbound(l *Link) jobj {
	switch l.Protocol {
	case ProtoVMESS:
		return vmessOutbound(l)
	case ProtoSS:
		return ssOutbound(l)
	case ProtoTrojan:
		return trojanOutbound(l)
	case ProtoHysteria2:
		return hysteria2Outbound(l)
	default:
		return vlessOutbound(l)
	}
}

func hysteria2Outbound(l *Link) jobj {
	tls := jobj{"alpn": firstNonEmptyList(splitCSV(l.ALPN), []string{"h3"})}
	// Hysteria's HTTP/3 authentication uses the synthetic host "hysteria".
	// Set the TLS name explicitly so an empty SNI cannot select that host.
	put(tls, "serverName", firstNonEmpty(l.SNI, l.Address))
	put(tls, "fingerprint", l.Fingerprint)
	put(tls, "echConfigList", l.ECH)
	put(tls, "verifyPeerCertByName", l.VerifyPeerCertByName)
	put(tls, "pinnedPeerCertSha256", l.PinnedPeerCertSha256)
	if l.AllowInsecure {
		tls["allowInsecure"] = true
	}
	stream := jobj{
		"network":  "hysteria",
		"security": "tls",
		"hysteriaSettings": jobj{
			"version":        2,
			"auth":           l.Password,
			"udpIdleTimeout": 60,
		},
		"tlsSettings": tls,
	}
	if fm := withUDPMasks(l.FinalMask, hysteriaMasks(l)); len(fm) > 0 {
		stream["finalmask"] = fm
	}
	return jobj{
		"tag":            firstNonEmpty(l.Tag, "hysteria2"),
		"protocol":       "hysteria",
		"settings":       jobj{"address": l.Address, "port": l.Port, "version": 2},
		"streamSettings": stream,
	}
}

func hysteriaMasks(l *Link) []jobj {
	var masks []jobj
	if (l.Obfs == "salamander" || l.Obfs == "gecko") && l.ObfsPassword != "" {
		settings := jobj{"password": l.ObfsPassword}
		put(settings, "packetSize", l.PacketSize)
		masks = append(masks, jobj{"type": "salamander", "settings": settings})
	}
	if l.HopPorts != "" {
		masks = append(masks, jobj{"type": "udphop", "settings": jobj{
			"mode":        "intervalremote",
			"interval":    "5-10",
			"remotePorts": l.HopPorts,
		}})
	}
	return masks
}

var mkcpHeaders = map[string]string{
	"dns": "dns", "dtls": "dtls", "srtp": "srtp", "utp": "utp",
	"wechat-video": "wechat", "wechat": "wechat", "wireguard": "wireguard",
}

func mkcpMasks(l *Link) []jobj {
	var masks []jobj
	if l.Seed != "" {
		masks = append(masks, jobj{"type": "mkcp-legacy", "settings": jobj{"header": "", "value": l.Seed}})
	}
	if header, ok := mkcpHeaders[strings.ToLower(l.HeaderType)]; ok {
		masks = append(masks, jobj{"type": "mkcp-legacy", "settings": jobj{"header": header, "value": ""}})
	}
	return masks
}

func withUDPMasks(base map[string]any, masks []jobj) jobj {
	out := make(jobj, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	udp, _ := out["udp"].([]any)
	present := make(map[string]bool, len(udp))
	for _, m := range udp {
		if mm, ok := m.(map[string]any); ok {
			if t, _ := mm["type"].(string); t != "" {
				present[t] = true
			}
		}
	}
	for _, m := range masks {
		if t, _ := m["type"].(string); !present[t] {
			udp = append(udp, m)
		}
	}
	if len(udp) > 0 {
		out["udp"] = udp
	}
	return nilIfEmpty(out)
}

func firstNonEmptyList(values, fallback []string) []string {
	if len(values) > 0 {
		return values
	}
	return fallback
}

func trojanOutbound(l *Link) jobj {
	return proxyOutbound(l, "trojan", firstNonEmpty(l.Tag, "trojan"), jobj{
		"servers": []jobj{{
			"address":  l.Address,
			"port":     l.Port,
			"password": l.Password,
		}},
	})
}

func vlessOutbound(l *Link) jobj {
	user := jobj{
		"id":         l.UUID,
		"encryption": firstNonEmpty(l.Encryption, "none"),
		"level":      0,
	}
	if l.Flow != "" {
		user["flow"] = l.Flow
	}
	return proxyOutbound(l, "vless", firstNonEmpty(l.Tag, "vless"), jobj{
		"vnext": []jobj{{
			"address": l.Address,
			"port":    l.Port,
			"users":   []jobj{user},
		}},
	})
}

func vmessOutbound(l *Link) jobj {
	user := jobj{
		"id":       l.UUID,
		"security": firstNonEmpty(l.Cipher, "auto"),
	}
	if l.AlterID != 0 {
		user["alterId"] = l.AlterID
	}
	return proxyOutbound(l, "vmess", firstNonEmpty(l.Tag, "vmess"), jobj{
		"vnext": []jobj{{
			"address": l.Address,
			"port":    l.Port,
			"users":   []jobj{user},
		}},
	})
}

func ssOutbound(l *Link) jobj {
	server := jobj{
		"address":  l.Address,
		"port":     l.Port,
		"method":   l.Method,
		"password": l.Password,
	}
	return proxyOutbound(l, "shadowsocks", firstNonEmpty(l.Tag, "shadowsocks"), jobj{"servers": []jobj{server}})
}

func proxyOutbound(l *Link, protocol, tag string, settings jobj) jobj {
	ob := jobj{
		"tag":      tag,
		"protocol": protocol,
		"settings": settings,
	}
	if stream := buildStream(l); stream != nil {
		ob["streamSettings"] = stream
	}
	return ob
}

func buildStream(l *Link) jobj {
	network := canonicalNetwork(l.Network)
	sni := firstNonEmpty(l.SNI, l.Host)

	stream := jobj{}
	if network != "tcp" {
		stream["network"] = network
	}
	addSecurity(stream, l, sni)
	if t := transportSettings(l, network, sni); t != nil {
		stream[network+"Settings"] = t
	}
	var masks []jobj
	if network == "kcp" {
		masks = mkcpMasks(l)
	}
	if fm := withUDPMasks(l.FinalMask, masks); len(fm) > 0 {
		stream["finalmask"] = fm
	}
	if len(stream) == 0 {
		return nil
	}
	stream["network"] = network
	return stream
}

func canonicalNetwork(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "kcp", "mkcp":
		return "kcp"
	case "xhttp", "splithttp":
		return "xhttp"
	case "grpc", "httpupgrade":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func addSecurity(stream jobj, l *Link, sni string) {
	switch strings.ToLower(l.Security) {
	case "tls":
		stream["security"] = "tls"
		s := jobj{}
		put(s, "serverName", sni)
		put(s, "fingerprint", l.Fingerprint)
		if alpn := splitCSV(l.ALPN); len(alpn) > 0 {
			s["alpn"] = alpn
		}
		if l.AllowInsecure {
			s["allowInsecure"] = true
		}
		put(s, "echConfigList", l.ECH)
		put(s, "verifyPeerCertByName", l.VerifyPeerCertByName)
		put(s, "pinnedPeerCertSha256", l.PinnedPeerCertSha256)
		if len(s) > 0 {
			stream["tlsSettings"] = s
		}
	case "reality":
		stream["security"] = "reality"
		s := jobj{"spiderX": firstNonEmpty(l.SpiderX, "/")}
		put(s, "serverName", sni)
		put(s, "fingerprint", l.Fingerprint)
		put(s, "publicKey", l.PublicKey)
		put(s, "shortId", l.ShortID)
		put(s, "mldsa65Verify", l.MLDSA65Verify)
		stream["realitySettings"] = s
	}
}

func transportSettings(l *Link, network, sni string) jobj {
	switch network {
	case "tcp":
		return tcpSettings(l, sni)
	case "ws", "httpupgrade":
		return httpHostSettings(l, sni)
	case "grpc":
		return grpcSettings(l, sni)
	case "kcp":
		return kcpSettings(l)
	case "xhttp":
		return xhttpSettings(l, sni)
	default:
		return nil
	}
}

func tcpSettings(l *Link, sni string) jobj {
	s := jobj{}
	if ht := strings.ToLower(l.HeaderType); ht != "" {
		header := jobj{"type": ht}
		if ht == "http" {
			request := jobj{}
			if uris := splitCSV(firstNonEmpty(l.Path, "/")); len(uris) > 0 {
				request["path"] = uris
			}
			if host := splitCSV(firstNonEmpty(l.Host, sni)); len(host) > 0 {
				request["headers"] = jobj{"Host": host}
			}
			if len(request) > 0 {
				header["request"] = request
			}
		}
		s["header"] = header
	}
	if l.AcceptProxyProtocol {
		s["acceptProxyProtocol"] = true
	}
	return nilIfEmpty(s)
}

func httpHostSettings(l *Link, sni string) jobj {
	s := jobj{}
	put(s, "path", l.Path)
	put(s, "host", firstNonEmpty(l.Host, sni))
	if l.AcceptProxyProtocol {
		s["acceptProxyProtocol"] = true
	}
	return nilIfEmpty(s)
}

func grpcSettings(l *Link, sni string) jobj {
	s := jobj{}
	put(s, "serviceName", firstNonEmpty(l.ServiceName, strings.TrimPrefix(l.Path, "/")))
	put(s, "authority", firstNonEmpty(l.Authority, l.Host, sni))
	if mode := strings.ToLower(l.Mode); mode == "multi" || mode == "multimode" || mode == "multi-mode" || l.MultiMode {
		s["multiMode"] = true
	}
	putInt(s, "idle_timeout", l.IdleTimeout)
	putInt(s, "health_check_timeout", l.HealthCheckTimeout)
	if l.PermitWithoutStream {
		s["permit_without_stream"] = true
	}
	putInt(s, "initial_windows_size", l.InitialWindowsSize)
	put(s, "user_agent", l.UserAgent)
	return nilIfEmpty(s)
}

func kcpSettings(l *Link) jobj {
	s := jobj{}
	putInt(s, "mtu", l.MTU)
	putInt(s, "tti", l.TTI)
	putInt(s, "uplinkCapacity", l.UplinkCapacity)
	putInt(s, "downlinkCapacity", l.DownlinkCapacity)
	if l.Congestion {
		s["congestion"] = true
	}
	putInt(s, "readBufferSize", l.ReadBufferSize)
	putInt(s, "writeBufferSize", l.WriteBufferSize)
	put(s, "seed", l.Seed)
	if ht := strings.ToLower(l.HeaderType); ht != "" {
		s["header"] = jobj{"type": ht}
	}
	return nilIfEmpty(s)
}

func xhttpSettings(l *Link, sni string) jobj {
	s := jobj{}
	put(s, "path", l.Path)
	put(s, "host", firstNonEmpty(l.Host, sni))
	if l.Mode != "" {
		s["mode"] = strings.ToLower(l.Mode)
	}
	if len(l.Extra) == 0 {
		put(s, "xPaddingBytes", l.XPaddingBytes)
		return nilIfEmpty(s)
	}
	extra := make(jobj, len(l.Extra)+1)
	for k, v := range l.Extra {
		extra[k] = v
	}
	if _, ok := extra["xPaddingBytes"]; !ok {
		put(extra, "xPaddingBytes", l.XPaddingBytes)
	}
	s["extra"] = extra
	return s
}

func put(m jobj, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func putInt(m jobj, key string, val int) {
	if val != 0 {
		m[key] = val
	}
}

func nilIfEmpty(m jobj) jobj {
	if len(m) == 0 {
		return nil
	}
	return m
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
