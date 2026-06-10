package xray

import (
	"encoding/base64"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseVLESSExtractsFields(t *testing.T) {
	t.Parallel()

	manager := &XrayManager{}
	cfg, err := manager.parseVLESS("vless://11111111-1111-1111-1111-111111111111@example.com:8443?type=ws&security=reality&host=cdn.example.com&sni=edge.example.com&pbk=pubkey&sid=short&spx=%2Fgrpc#demo")
	if err != nil {
		t.Fatalf("parseVLESS: %v", err)
	}

	if cfg["uuid"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("unexpected uuid: %s", cfg["uuid"])
	}
	if cfg["address"] != "example.com" {
		t.Fatalf("unexpected address: %s", cfg["address"])
	}
	if cfg["port"] != "8443" {
		t.Fatalf("unexpected port: %s", cfg["port"])
	}
	if cfg["type"] != "ws" {
		t.Fatalf("unexpected type: %s", cfg["type"])
	}
	if cfg["security"] != "reality" {
		t.Fatalf("unexpected security: %s", cfg["security"])
	}
	if cfg["host"] != "cdn.example.com" {
		t.Fatalf("unexpected host: %s", cfg["host"])
	}
	if cfg["sni"] != "edge.example.com" {
		t.Fatalf("unexpected sni: %s", cfg["sni"])
	}
	if cfg["pbk"] != "pubkey" || cfg["sid"] != "short" {
		t.Fatalf("unexpected reality params: pbk=%s sid=%s", cfg["pbk"], cfg["sid"])
	}
	if cfg["tag"] != "demo" {
		t.Fatalf("unexpected tag: %s", cfg["tag"])
	}
}

func TestBuildConfigHonorsTProxy(t *testing.T) {
	t.Parallel()

	encoded := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret"))
	manager := &XrayManager{tproxyEnabled: true}

	cfg, err := manager.buildConfig("ss://"+encoded+"@198.51.100.10:8388#demo", 1080)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	if len(cfg.Inbounds) != 1 {
		t.Fatalf("unexpected inbound count: %d", len(cfg.Inbounds))
	}
	inbound := cfg.Inbounds[0]
	if inbound["listen"] != "0.0.0.0" {
		t.Fatalf("expected listen=0.0.0.0, got %#v", inbound["listen"])
	}

	streamSettings, ok := inbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected streamSettings map")
	}
	sockopt, ok := streamSettings["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sockopt map")
	}
	if sockopt["tproxy"] != "tproxy" {
		t.Fatalf("expected tproxy sockopt, got %#v", sockopt["tproxy"])
	}
}

func TestFixVLESSUserEncryption(t *testing.T) {
	t.Parallel()

	cfg := &xrayFile{
		Outbounds: []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"users": []interface{}{
								map[string]interface{}{
									"id": "11111111-1111-1111-1111-111111111111",
								},
							},
						},
					},
				},
			},
		},
	}

	if !fixVLESSUserEncryption(cfg) {
		t.Fatalf("expected config to be patched")
	}

	settings := cfg.Outbounds[0]["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})
	entry := vnext[0].(map[string]interface{})
	users := entry["users"].([]interface{})
	user := users[0].(map[string]interface{})
	if user["encryption"] != "none" {
		t.Fatalf("expected encryption=none, got %#v", user["encryption"])
	}
}

func TestUpdateXrayPreservesPortAndAutoRun(t *testing.T) {
	manager, err := newXrayManager(t.TempDir(), false)
	if err != nil {
		t.Fatalf("newXrayManager: %v", err)
	}

	if err := manager.checkDependencies(); err != nil {
		t.Skipf("xray dependency unavailable: %v", err)
	}

	const link = "vless://11111111-1111-1111-1111-111111111111@old.example.com:8443?type=tcp&security=none#first"
	cfg, err := manager.buildConfig(link, 4321)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	cfg.AutoRun = true
	cfg.Metadata.SocksPort = 4321
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(manager.configPath("xray1"), data, 0644); err != nil {
		t.Fatalf("write seed config: %v", err)
	}

	const newLink = "vless://22222222-2222-2222-2222-222222222222@new.example.com:9443?type=tcp&security=none#second"
	if err := manager.UpdateXray("xray1", newLink); err != nil {
		t.Fatalf("UpdateXray: %v", err)
	}

	info, err := manager.GetXrayInfo("xray1")
	if err != nil {
		t.Fatalf("GetXrayInfo: %v", err)
	}
	if info.InboundPort != 4321 {
		t.Fatalf("inbound port changed: got %d, want 4321", info.InboundPort)
	}
	if !info.AutoRun {
		t.Fatalf("autorun flag not preserved")
	}
	if info.Host != "new.example.com" {
		t.Fatalf("outbound host not updated: got %s", info.Host)
	}
}

func TestPatchInboundTProxyRemovesTransportSettingsWhenDisabled(t *testing.T) {
	t.Parallel()

	cfg := &xrayFile{
		Inbounds: []map[string]interface{}{
			defaultInbound(1080, true),
		},
	}

	if !patchInboundTProxy(cfg, false) {
		t.Fatalf("expected patch to report changes")
	}

	inbound := cfg.Inbounds[0]
	if _, exists := inbound["listen"]; exists {
		t.Fatalf("listen should be removed when tproxy is disabled")
	}
	if _, exists := inbound["streamSettings"]; exists {
		t.Fatalf("streamSettings should be removed when tproxy is disabled")
	}
}
