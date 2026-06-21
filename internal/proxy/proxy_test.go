package proxy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLinkVLESS(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("vless://11111111-1111-1111-1111-111111111111@example.com:8443?type=ws&security=reality&host=cdn.example.com&sni=edge.example.com&pbk=pubkey&sid=short&spx=%2Fgrpc#demo")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	cases := map[string]struct{ got, want string }{
		"protocol":  {string(l.Protocol), "vless"},
		"uuid":      {l.UUID, "11111111-1111-1111-1111-111111111111"},
		"address":   {l.Address, "example.com"},
		"network":   {l.Network, "ws"},
		"security":  {l.Security, "reality"},
		"host":      {l.Host, "cdn.example.com"},
		"sni":       {l.SNI, "edge.example.com"},
		"publicKey": {l.PublicKey, "pubkey"},
		"shortId":   {l.ShortID, "short"},
		"spiderX":   {l.SpiderX, "/grpc"},
		"tag":       {l.Tag, "demo"},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", name, c.got, c.want)
		}
	}
	if l.Port != 8443 {
		t.Errorf("port: got %d, want 8443", l.Port)
	}
}

func TestParseLinkVMESS(t *testing.T) {
	t.Parallel()

	payload := `{"v":"2","ps":"node","add":"vmess.example.com","port":"443","id":"22222222-2222-2222-2222-222222222222","aid":"0","net":"ws","host":"h.example.com","path":"/ray","tls":"tls"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	l, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Protocol != ProtoVMESS || l.Address != "vmess.example.com" || l.Port != 443 {
		t.Fatalf("unexpected core fields: %+v", l)
	}
	if l.Network != "ws" || l.Security != "tls" || l.Path != "/ray" {
		t.Fatalf("unexpected transport fields: net=%s sec=%s path=%s", l.Network, l.Security, l.Path)
	}
}

func TestParseLinkSS(t *testing.T) {
	t.Parallel()

	creds := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret"))
	l, err := ParseLink("ss://" + creds + "@198.51.100.10:8388#node")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if l.Method != "chacha20-ietf-poly1305" || l.Password != "secret" {
		t.Fatalf("unexpected creds: method=%s pass=%s", l.Method, l.Password)
	}
	if l.Address != "198.51.100.10" || l.Port != 8388 || l.Tag != "node" {
		t.Fatalf("unexpected fields: %+v", l)
	}
}

func TestCanonicalNetwork(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":            "tcp",
		"raw":         "tcp",
		"tcp":         "tcp",
		"websocket":   "ws",
		"ws":          "ws",
		"mkcp":        "kcp",
		"xhttp":       "splithttp",
		"httpupgrade": "httpupgrade",
		"grpc":        "grpc",
	}
	for in, want := range cases {
		if got := canonicalNetwork(in); got != want {
			t.Errorf("canonicalNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderConfigTProxy(t *testing.T) {
	t.Parallel()

	l, err := ParseLink("vless://uuid@example.com:443?type=tcp&security=none")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	data, _, err := renderConfig(l, 1080, true)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}

	cfg := decodeConfig(t, data)
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("expected one inbound, got %d", len(cfg.Inbounds))
	}
	in := cfg.Inbounds[0]
	if in["listen"] != "0.0.0.0" {
		t.Fatalf("expected listen 0.0.0.0, got %#v", in["listen"])
	}
	sock := in["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if sock["tproxy"] != "tproxy" {
		t.Fatalf("expected tproxy sockopt, got %#v", sock["tproxy"])
	}
}

func TestRenderConfigHasNoVpnerMetadata(t *testing.T) {
	t.Parallel()

	l, _ := ParseLink("vless://uuid@example.com:443?type=tcp")
	data, outbound, err := renderConfig(l, 1080, false)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}

	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	for _, forbidden := range []string{"auto_run", "metadata", "socks_port"} {
		if _, ok := top[forbidden]; ok {
			t.Errorf("config leaked vpner field %q", forbidden)
		}
	}

	users := outbound["settings"].(jobj)["vnext"].([]jobj)[0]["users"].([]jobj)
	if users[0]["encryption"] != "none" {
		t.Errorf("expected encryption=none, got %#v", users[0]["encryption"])
	}
}

func TestMigrateLegacyChain(t *testing.T) {
	dir := t.TempDir()
	legacy := `inbounds:
  - port: 4321
    protocol: dokodemo-door
outbounds:
  - protocol: vless
    tag: vless
    settings:
      vnext:
        - address: old.example.com
          port: 8443
          users:
            - id: 33333333-3333-3333-3333-333333333333
auto_run: true
metadata:
  protocol: vless
  remote_host: old.example.com
  remote_port: 8443
  socks_port: 4321
`
	if err := os.WriteFile(filepath.Join(dir, "xray1.yaml"), []byte(legacy), 0644); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	mgr, err := newManager(dir, false)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "xray1.yaml")); !os.IsNotExist(err) {
		t.Errorf("legacy yaml should be removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "xray1.json")); err != nil {
		t.Errorf("config json missing: %v", err)
	}

	info, err := mgr.Get("xray1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if info.Type != "vless" || info.Host != "old.example.com" || info.Port != 8443 || info.InboundPort != 4321 || !info.AutoRun {
		t.Fatalf("unexpected migrated info: %+v", info)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "xray1.json"))
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("migrated config not JSON: %v", err)
	}
	if _, ok := top["auto_run"]; ok {
		t.Errorf("migrated config leaked auto_run")
	}
	if _, ok := top["metadata"]; ok {
		t.Errorf("migrated config leaked metadata")
	}
}

func TestCreateAndUpdatePreservePortAndAutoRun(t *testing.T) {
	if err := checkXrayBinary(); err != nil {
		t.Skipf("xray binary unavailable: %v", err)
	}
	mgr, err := newManager(t.TempDir(), false)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}

	name, err := mgr.Create("vless://uuid@old.example.com:8443?type=tcp&security=none#first", true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := mgr.Get(name)

	if err := mgr.Update(name, "vless://uuid@new.example.com:9443?type=tcp&security=none#second"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, _ := mgr.Get(name)

	if after.InboundPort != before.InboundPort {
		t.Errorf("inbound port changed: %d -> %d", before.InboundPort, after.InboundPort)
	}
	if !after.AutoRun {
		t.Errorf("autorun not preserved")
	}
	if after.Host != "new.example.com" {
		t.Errorf("host not updated: %s", after.Host)
	}
}

type testConfig struct {
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
}

func decodeConfig(t *testing.T, data []byte) testConfig {
	t.Helper()
	var cfg testConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return cfg
}
