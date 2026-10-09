package proxy

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestParseLinkTrojanWithStream(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("trojan://p%40ss@example.com:443?type=ws&path=%2Ftrojan&host=cdn.example.com&security=tls&sni=edge.example.com&fp=chrome&alpn=h2,http/1.1&ech=AEX%2Bech&vcn=edge.example.com&pcs=abcd#tr")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Protocol != ProtoTrojan || l.Password != "p@ss" || l.Address != "example.com" || l.Port != 443 || l.Tag != "tr" {
		t.Fatalf("unexpected core fields: %+v", l)
	}

	ob := buildOutbound(l)
	if ob["protocol"] != "trojan" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	server := ob["settings"].(jobj)["servers"].([]jobj)[0]
	if server["password"] != "p@ss" || server["address"] != "example.com" || server["port"] != 443 {
		t.Fatalf("unexpected trojan server: %#v", server)
	}
	stream := ob["streamSettings"].(jobj)
	if stream["network"] != "ws" || stream["security"] != "tls" {
		t.Fatalf("unexpected stream: %#v", stream)
	}
	ws := stream["wsSettings"].(jobj)
	if ws["path"] != "/trojan" || ws["host"] != "cdn.example.com" {
		t.Fatalf("unexpected ws settings: %#v", ws)
	}
	tls := stream["tlsSettings"].(jobj)
	for key, want := range map[string]string{
		"serverName":           "edge.example.com",
		"fingerprint":          "chrome",
		"echConfigList":        "AEX+ech",
		"verifyPeerCertByName": "edge.example.com",
		"pinnedPeerCertSha256": "abcd",
	} {
		if tls[key] != want {
			t.Errorf("tls %s = %v, want %q", key, tls[key], want)
		}
	}
	if alpn := tls["alpn"].([]string); len(alpn) != 2 || alpn[0] != "h2" {
		t.Errorf("alpn = %v", alpn)
	}
}

func TestVLESSXHTTPExtraAndFinalMask(t *testing.T) {
	t.Parallel()

	extra := `{"xPaddingObfsMode":true,"xPaddingKey":"k","sessionIDPlacement":"query","scMaxEachPostBytes":"500000","xmux":{"maxConcurrency":"16-32"}}`
	fm := `{"xmc":{"a":1}}`
	link := "vless://uuid@example.com:443?type=xhttp&path=%2Fx&host=cdn.example.com&mode=packet-up&x_padding_bytes=100-1000&security=reality&sni=edge.example.com&pbk=pub&sid=01&pqv=pq&support-x25519mlkem768=true&encryption=mlkem768x25519plus.native.1rtt.key&extra=" +
		url.QueryEscape(extra) + "&fm=" + url.QueryEscape(fm)

	l, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Encryption != "mlkem768x25519plus.native.1rtt.key" || l.MLDSA65Verify != "pq" {
		t.Fatalf("encryption/pqv not carried: %+v", l)
	}

	ob := buildOutbound(l)
	users := ob["settings"].(jobj)["vnext"].([]jobj)[0]["users"].([]jobj)
	if users[0]["encryption"] != "mlkem768x25519plus.native.1rtt.key" {
		t.Fatalf("vless encryption lost: %#v", users[0])
	}
	stream := ob["streamSettings"].(jobj)
	if stream["network"] != "xhttp" {
		t.Fatalf("network = %v, want xhttp", stream["network"])
	}
	if _, legacy := stream["splithttpSettings"]; legacy {
		t.Fatal("legacy splithttpSettings must not be emitted")
	}
	x := stream["xhttpSettings"].(jobj)
	if x["path"] != "/x" || x["host"] != "cdn.example.com" || x["mode"] != "packet-up" {
		t.Fatalf("unexpected xhttp settings: %#v", x)
	}
	xe := x["extra"].(map[string]any)
	if xe["xPaddingObfsMode"] != true || xe["sessionIDPlacement"] != "query" || xe["xPaddingBytes"] != "100-1000" {
		t.Fatalf("extra not passed through: %#v", xe)
	}
	if xmux, ok := xe["xmux"].(map[string]any); !ok || xmux["maxConcurrency"] != "16-32" {
		t.Fatalf("nested extra lost: %#v", xe["xmux"])
	}
	if mask, ok := stream["finalmask"].(map[string]any); !ok || mask["xmc"] == nil {
		t.Fatalf("finalmask not carried: %#v", stream["finalmask"])
	}
	reality := stream["realitySettings"].(jobj)
	if reality["publicKey"] != "pub" || reality["shortId"] != "01" || reality["mldsa65Verify"] != "pq" || reality["serverName"] != "edge.example.com" {
		t.Fatalf("unexpected reality settings: %#v", reality)
	}
}

func TestShadowsocksWithTransportAndTLS(t *testing.T) {
	t.Parallel()

	creds := url.QueryEscape("2022-blake3-aes-128-gcm:serverpsk:clientpsk")
	l, err := ParseLink("ss://" + creds + "@example.com:8443?type=ws&path=%2Fss&host=cdn.example.com&sni=edge.example.com&fp=chrome#ss2022")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Method != "2022-blake3-aes-128-gcm" || l.Password != "serverpsk:clientpsk" {
		t.Fatalf("unexpected creds: %s / %s", l.Method, l.Password)
	}

	ob := buildOutbound(l)
	stream, ok := ob["streamSettings"].(jobj)
	if !ok {
		t.Fatalf("shadowsocks outbound must carry streamSettings: %#v", ob)
	}
	if stream["network"] != "ws" || stream["security"] != "tls" {
		t.Fatalf("unexpected stream: %#v", stream)
	}
	if stream["wsSettings"].(jobj)["path"] != "/ss" {
		t.Fatalf("ws path lost: %#v", stream["wsSettings"])
	}

	plain, err := ParseLink("ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@example.com:8388")
	if err != nil {
		t.Fatalf("ParseLink plain: %v", err)
	}
	if _, has := buildOutbound(plain)["streamSettings"]; has {
		t.Fatal("plain shadowsocks must not emit streamSettings")
	}
}

func TestVMESSGrpcMultiAndXHTTPMode(t *testing.T) {
	t.Parallel()

	grpc := `{"v":"2","add":"g.example.com","port":"443","id":"uuid","net":"grpc","type":"multi","path":"svc","authority":"a.example.com","tls":"tls","sni":"g.example.com","ech":"AEX"}`
	l, err := ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(grpc)))
	if err != nil {
		t.Fatalf("ParseLink grpc: %v", err)
	}
	if !l.MultiMode || l.HeaderType != "" || l.ServiceName != "svc" {
		t.Fatalf("grpc multi not recognised: %+v", l)
	}
	stream := buildOutbound(l)["streamSettings"].(jobj)
	g := stream["grpcSettings"].(jobj)
	if g["multiMode"] != true || g["serviceName"] != "svc" || g["authority"] != "a.example.com" {
		t.Fatalf("unexpected grpc settings: %#v", g)
	}
	if stream["tlsSettings"].(jobj)["echConfigList"] != "AEX" {
		t.Fatalf("vmess ech lost: %#v", stream["tlsSettings"])
	}

	xhttp := `{"v":"2","add":"x.example.com","port":"443","id":"uuid","net":"xhttp","type":"stream-up","path":"/p","host":"h.example.com","xPaddingBytes":"100-1000","sessionIDPlacement":"header","tls":"none"}`
	l, err = ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(xhttp)))
	if err != nil {
		t.Fatalf("ParseLink xhttp: %v", err)
	}
	if l.Mode != "stream-up" || l.HeaderType != "" {
		t.Fatalf("xhttp mode not recognised: %+v", l)
	}
	x := buildOutbound(l)["streamSettings"].(jobj)["xhttpSettings"].(jobj)
	if x["mode"] != "stream-up" {
		t.Fatalf("unexpected xhttp settings: %#v", x)
	}
	if xe := x["extra"].(map[string]any); xe["sessionIDPlacement"] != "header" || xe["xPaddingBytes"] != "100-1000" {
		t.Fatalf("flat vmess extra keys not collected: %#v", x["extra"])
	}

	tcp := `{"v":"2","add":"t.example.com","port":"80","id":"uuid","net":"tcp","type":"none"}`
	l, err = ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(tcp)))
	if err != nil {
		t.Fatalf("ParseLink tcp: %v", err)
	}
	if _, has := buildOutbound(l)["streamSettings"]; has || l.HeaderType != "" {
		t.Fatalf("type=none must not become a header: %+v", l)
	}
}

func TestWireGuardLinksRejectedWithHint(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"vpn://W0ludGVyZmFjZV0K", "[Interface]\nPrivateKey = x\n"} {
		_, err := ParseLink(raw)
		if err == nil || !strings.Contains(err.Error(), "vpnerctl interface add") {
			t.Fatalf("%q: expected a WireGuard hint, got %v", raw[:5], err)
		}
	}
}

func TestShadowsocksObfsHTTPPluginBecomesTCPHeader(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("ss://YWVzLTI1Ni1nY206cHc@h.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#ss")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	ob := buildOutbound(l)
	server := ob["settings"].(jobj)["servers"].([]jobj)[0]
	if _, has := server["plugin"]; has {
		t.Fatal("xray has no SIP003 plugins: plugin must not be emitted")
	}
	stream := ob["streamSettings"].(jobj)
	if stream["network"] != "tcp" {
		t.Fatalf("network = %v", stream["network"])
	}
	header := stream["tcpSettings"].(jobj)["header"].(jobj)
	if header["type"] != "http" {
		t.Fatalf("header type = %v", header["type"])
	}
	request := header["request"].(jobj)
	if paths := request["path"].([]string); len(paths) != 1 || paths[0] != "/" {
		t.Fatalf("path = %v", request["path"])
	}
	if hosts := request["headers"].(jobj)["Host"].([]string); len(hosts) != 1 || hosts[0] != "cdn.example.com" {
		t.Fatalf("Host = %v", request["headers"])
	}
	if _, legacy := request["uri"]; legacy {
		t.Fatal("legacy uri/header keys must not be emitted")
	}

	if _, err := ParseLink("ss://YWVzLTI1Ni1nY206cHc@h.example.com:8388?plugin=v2ray-plugin%3Btls"); err == nil {
		t.Fatal("unsupported plugins must be rejected")
	}
}

func TestEmptyTransportSettingsKeepNetwork(t *testing.T) {
	t.Parallel()

	for _, link := range []string{
		"vless://uuid@h.example.com:443?type=grpc&encryption=none&serviceName=&authority=&security=none#g",
		"vless://uuid@h.example.com:80?type=httpupgrade&path=&host=&security=none",
	} {
		l, err := ParseLink(link)
		if err != nil {
			t.Fatalf("ParseLink: %v", err)
		}
		stream, ok := buildOutbound(l)["streamSettings"].(jobj)
		if !ok || stream["network"] != canonicalNetwork(l.Network) {
			t.Fatalf("%s: network must survive empty transport settings: %#v", link, stream)
		}
	}
	plain, _ := ParseLink("vless://uuid@h.example.com:80?type=tcp&encryption=none&security=none")
	if _, has := buildOutbound(plain)["streamSettings"]; has {
		t.Fatal("plain tcp without settings must not emit streamSettings")
	}
}

func TestVMESSEdgeCases(t *testing.T) {
	t.Parallel()

	xhttpNone := `{"v":"2","add":"x.example.com","port":443,"id":"uuid","net":"xhttp","type":"none","path":"/p","tls":"none"}`
	l, err := ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(xhttpNone)))
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Mode != "" {
		t.Fatalf("type=none must not become an xhttp mode: %q", l.Mode)
	}
	if _, has := buildOutbound(l)["streamSettings"].(jobj)["xhttpSettings"].(jobj)["mode"]; has {
		t.Fatal("mode must be omitted so xray defaults to auto")
	}

	grpcMode := `{"v":"2","add":"g.example.com","port":"443","id":"uuid","net":"grpc","mode":"multi","path":"svc"}`
	l, err = ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(grpcMode)))
	if err != nil {
		t.Fatalf("ParseLink grpc: %v", err)
	}
	if buildOutbound(l)["streamSettings"].(jobj)["grpcSettings"].(jobj)["multiMode"] != true {
		t.Fatal("vmess grpc mode=multi must enable multiMode")
	}
}

func TestLinkParsingEdgeCases(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("ss://YWVzLTI1Ni1nY206cHc%3D@h.example.com:8388#pad")
	if err != nil || l.Method != "aes-256-gcm" || l.Password != "pw" {
		t.Fatalf("percent-encoded base64 padding: %+v %v", l, err)
	}

	l, err = ParseLink("trojan://pa:ss@h.example.com:443")
	if err != nil || l.Password != "pa:ss" {
		t.Fatalf("raw colon in trojan password: %+v %v", l, err)
	}

	l, err = ParseLink("vless://uuid@h.example.com:443?type=xhttp&path=%2Fx&x_padding_bytes=200-300&extra=" + url.QueryEscape(`{"xmux":{"maxConcurrency":"16"}}`))
	if err != nil {
		t.Fatalf("ParseLink xhttp: %v", err)
	}
	x := buildOutbound(l)["streamSettings"].(jobj)["xhttpSettings"].(jobj)
	if _, outer := x["xPaddingBytes"]; outer {
		t.Fatal("outer xPaddingBytes is discarded by xray when extra is present")
	}
	if x["extra"].(jobj)["xPaddingBytes"] != "200-300" {
		t.Fatalf("xPaddingBytes must move into extra: %#v", x["extra"])
	}
}

func TestDuplicateDetectionReRendersStoredLinks(t *testing.T) {
	t.Parallel()

	mgr, err := newManager(t.TempDir(), false)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	link := "vless://uuid@h.example.com:443?type=xhttp&path=%2Fx&security=none#old"
	legacy := []byte(`{"inbounds":[],"outbounds":[{"tag":"old","protocol":"vless","settings":{},"streamSettings":{"network":"splithttp","splithttpSettings":{"path":"/x"}}}]}`)
	if err := mgr.store.writeMeta("xray1", &chainMeta{Link: link, Protocol: "vless", InboundPort: 1234}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.store.writeConfig("xray1", legacy); err != nil {
		t.Fatal(err)
	}
	parsed, _ := ParseLink(link)
	dup, err := mgr.isDuplicate(buildOutbound(parsed), "")
	if err != nil || !dup {
		t.Fatalf("same link stored under the legacy splithttp naming must be a duplicate: dup=%v err=%v", dup, err)
	}
}

func TestMKCPHeaderAndSeedBecomeFinalMask(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("vless://uuid@h.example.com:443?type=kcp&headerType=wechat-video&seed=s3cret&mtu=1350&tti=20&security=none&encryption=none")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	stream := buildOutbound(l)["streamSettings"].(jobj)
	if stream["network"] != "kcp" {
		t.Fatalf("network = %v", stream["network"])
	}
	udp := stream["finalmask"].(jobj)["udp"].([]any)
	if len(udp) != 2 {
		t.Fatalf("expected seed+header masks, got %#v", udp)
	}
	seed := udp[0].(jobj)
	header := udp[1].(jobj)
	if seed["type"] != "mkcp-legacy" || seed["settings"].(jobj)["value"] != "s3cret" || seed["settings"].(jobj)["header"] != "" {
		t.Fatalf("seed mask = %#v", seed)
	}
	if header["settings"].(jobj)["header"] != "wechat" || header["settings"].(jobj)["value"] != "" {
		t.Fatalf("header mask = %#v", header)
	}
	kcp := stream["kcpSettings"].(jobj)
	if kcp["mtu"] != 1350 || kcp["seed"] != "s3cret" || kcp["header"].(jobj)["type"] != "wechat-video" {
		t.Fatalf("legacy kcp settings must stay for older xray: %#v", kcp)
	}

	withFM, err := ParseLink("vless://uuid@h.example.com:443?type=kcp&headerType=dtls&security=none&fm=" + url.QueryEscape(`{"udp":[{"type":"mkcp-legacy","settings":{"header":"srtp","value":""}}]}`))
	if err != nil {
		t.Fatalf("ParseLink fm: %v", err)
	}
	udp = buildOutbound(withFM)["streamSettings"].(jobj)["finalmask"].(jobj)["udp"].([]any)
	if len(udp) != 1 || udp[0].(map[string]any)["settings"].(map[string]any)["header"] != "srtp" {
		t.Fatalf("fm mkcp-legacy must win over headerType: %#v", udp)
	}

	none, _ := ParseLink("vless://uuid@h.example.com:443?type=kcp&headerType=none&security=none")
	if _, has := buildOutbound(none)["streamSettings"].(jobj)["finalmask"]; has {
		t.Fatal("headerType=none must not create a mask")
	}
}

func TestParseLinkHysteria2(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("hysteria2://p%40ss@hy.example.com:8443?security=tls&sni=hy.example.com&alpn=h3&fp=chrome&pinSHA256=AB:CD&obfs=gecko&obfs-password=obfspw&minPacketSize=100&maxPacketSize=1200&mport=20000-30000#hy")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Protocol != ProtoHysteria2 || l.Password != "p@ss" || l.Address != "hy.example.com" || l.Port != 8443 || l.Tag != "hy" {
		t.Fatalf("unexpected core fields: %+v", l)
	}
	ob := buildOutbound(l)
	if ob["protocol"] != "hysteria" {
		t.Fatalf("protocol = %v", ob["protocol"])
	}
	settings := ob["settings"].(jobj)
	if settings["address"] != "hy.example.com" || settings["port"] != 8443 || settings["version"] != 2 {
		t.Fatalf("unexpected settings: %#v", settings)
	}
	stream := ob["streamSettings"].(jobj)
	if stream["network"] != "hysteria" || stream["security"] != "tls" {
		t.Fatalf("unexpected stream: %#v", stream)
	}
	hs := stream["hysteriaSettings"].(jobj)
	if hs["version"] != 2 || hs["auth"] != "p@ss" || hs["udpIdleTimeout"] != 60 {
		t.Fatalf("unexpected hysteriaSettings: %#v", hs)
	}
	tls := stream["tlsSettings"].(jobj)
	if tls["serverName"] != "hy.example.com" || tls["pinnedPeerCertSha256"] != "AB:CD" || tls["fingerprint"] != "chrome" {
		t.Fatalf("unexpected tls: %#v", tls)
	}
	udp := stream["finalmask"].(jobj)["udp"].([]any)
	if len(udp) != 2 {
		t.Fatalf("expected salamander+udphop masks: %#v", udp)
	}
	sal := udp[0].(jobj)
	if sal["type"] != "salamander" || sal["settings"].(jobj)["password"] != "obfspw" || sal["settings"].(jobj)["packetSize"] != "100-1200" {
		t.Fatalf("salamander mask = %#v", sal)
	}
	hop := udp[1].(jobj)
	if hop["type"] != "udphop" || hop["settings"].(jobj)["remotePorts"] != "20000-30000" || hop["settings"].(jobj)["mode"] != "intervalremote" {
		t.Fatalf("udphop mask = %#v", hop)
	}

	plain, err := ParseLink("hy2://auth@hy.example.com?insecure=1")
	if err != nil {
		t.Fatalf("ParseLink hy2: %v", err)
	}
	if plain.Port != 443 {
		t.Fatalf("default port = %d", plain.Port)
	}
	pstream := buildOutbound(plain)["streamSettings"].(jobj)
	if alpn := pstream["tlsSettings"].(jobj)["alpn"].([]string); len(alpn) != 1 || alpn[0] != "h3" {
		t.Fatalf("alpn default = %v", alpn)
	}
	if pstream["tlsSettings"].(jobj)["allowInsecure"] != true {
		t.Fatal("insecure=1 must map to allowInsecure")
	}
	if _, has := pstream["finalmask"]; has {
		t.Fatal("no obfs/mport must mean no finalmask")
	}

	if _, err := ParseLink("tuic://uuid:pw@h.example.com:443"); err == nil {
		t.Fatal("tuic must be rejected with an explanation")
	}
}

func TestSecurityInferredFromRealityAndSNI(t *testing.T) {
	t.Parallel()

	cut, err := ParseLink("vless://uuid@h.example.com:12572?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=pub&pqv=truncated")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if cut.Security != "reality" {
		t.Fatalf("pbk without security must imply reality, got %q", cut.Security)
	}
	stream := buildOutbound(cut)["streamSettings"].(jobj)
	if stream["security"] != "reality" || stream["realitySettings"].(jobj)["publicKey"] != "pub" {
		t.Fatalf("reality settings missing: %#v", stream)
	}

	tls, _ := ParseLink("trojan://pw@h.example.com:443?sni=h.example.com&fp=chrome")
	if tls.Security != "tls" {
		t.Fatalf("sni without security must imply tls, got %q", tls.Security)
	}
	none, _ := ParseLink("vless://uuid@h.example.com:80?type=ws&path=%2Fx&encryption=none")
	if none.Security != "" {
		t.Fatalf("no tls hints must stay plain, got %q", none.Security)
	}
	explicit, _ := ParseLink("vless://uuid@h.example.com:80?security=none&sni=ignored&encryption=none")
	if explicit.Security != "none" {
		t.Fatalf("explicit security must win, got %q", explicit.Security)
	}
}

func TestCreateRejectsConfigXrayCannotLoad(t *testing.T) {
	if err := checkXrayBinary(); err != nil {
		t.Skipf("xray binary unavailable: %v", err)
	}
	mgr, err := newManager(t.TempDir(), false)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	_, err = mgr.Create("vless://uuid@h.example.com:12572?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=pub&pqv=truncated&sni=h.example.com", false)
	if err == nil || !strings.Contains(err.Error(), "xray rejected") {
		t.Fatalf("truncated REALITY link must be rejected by the xray config test, got %v", err)
	}
	if names, _ := mgr.List(); len(names) != 0 {
		t.Fatalf("rejected chain must not be stored: %v", names)
	}
}
