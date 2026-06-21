package proxy

import "strings"

type jobj = map[string]any

func buildOutbound(l *Link) jobj {
	switch l.Protocol {
	case ProtoVMESS:
		return vmessOutbound(l)
	case ProtoSS:
		return ssOutbound(l)
	default:
		return vlessOutbound(l)
	}
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
	ob := jobj{
		"tag":      firstNonEmpty(l.Tag, "shadowsocks"),
		"protocol": "shadowsocks",
		"settings": jobj{
			"servers": []jobj{{
				"address":  l.Address,
				"port":     l.Port,
				"method":   l.Method,
				"password": l.Password,
			}},
		},
	}

	return ob
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
	addSecurity(stream, l, sni)
	if t := transportSettings(l, network, sni); t != nil {
		stream[network+"Settings"] = t
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
		return "splithttp"
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
	case "splithttp":
		return splitHTTPSettings(l, sni)
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
				request["uri"] = uris
			}
			if host := splitCSV(firstNonEmpty(l.Host, sni)); len(host) > 0 {
				request["header"] = []jobj{{"name": "Host", "value": host}}
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

func splitHTTPSettings(l *Link, sni string) jobj {
	s := jobj{}
	put(s, "path", l.Path)
	put(s, "host", firstNonEmpty(l.Host, sni))
	if l.Mode != "" {
		s["mode"] = strings.ToLower(l.Mode)
	}
	return nilIfEmpty(s)
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
