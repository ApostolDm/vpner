package proxy

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// This exported ECHConfigList has an empty public_name and is rejected by
// native Go TLS even though its base64 encoding and vector lengths are valid.
const emptyPublicNameECH = "AFP+DQBPAAAgACCb7up/qy9TIeQmQ3VkdUi67od7nrD7H3Rw4qAxmzI1ewAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAAAAAA=="

const validHysteriaECH = "AF7+DQBaAAAgACA51i3Ssu4wUMV4FNCc8iRX5J+YC4Bhigz9sacl2lCfSQAkAAEAAQABAAIAAQADAAIAAQACAAIAAgADAAMAAQADAAIAAwADAAtleGFtcGxlLmNvbQAA"

func TestHysteria2TLSName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, address, query, want string
	}{
		{"missing SNI", "hy.example.com", "", "hy.example.com"},
		{"empty SNI", "hy.example.com", "sni=", "hy.example.com"},
		{"explicit SNI", "hy.example.com", "sni=edge.example.com", "edge.example.com"},
		{"serverName alias", "hy.example.com", "sni=&serverName=edge.example.com", "edge.example.com"},
		{"IP address", "192.0.2.1", "", "192.0.2.1"},
		{"IPv6 address", "[2001:db8::1]", "", "2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := ParseLink("hysteria2://auth@" + tc.address + ":46814?" + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			data, _, err := renderConfig(l, 13747, true)
			if err != nil {
				t.Fatal(err)
			}
			tls := decodeConfig(t, data).Outbounds[0]["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
			if tls["serverName"] != tc.want {
				t.Errorf("serverName = %v, want %q", tls["serverName"], tc.want)
			}
			if tls["allowInsecure"] == true {
				t.Error("TLS certificate verification must stay enabled")
			}
		})
	}
}

func TestHysteria2InvalidECHRejected(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, ech string }{
		{"empty public name", emptyPublicNameECH},
		{"invalid base64", "not base64!"},
		{"truncated list", "AFP+DQ=="},
		{"empty list", "AAA="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseLink("hysteria2://auth@hy.example.com:46814?alpn=h3&ech=" + url.QueryEscape(tc.ech) + "&obfs=salamander&obfs-password=mask&security=tls&sni=#hy")
			if err == nil || !strings.Contains(err.Error(), "invalid Hysteria2 ECH") || !strings.Contains(err.Error(), "remove it") {
				t.Fatalf("expected an actionable ECH error, got %v", err)
			}
		})
	}
}

func TestHysteria2ValidECHPreserved(t *testing.T) {
	t.Parallel()

	for _, ech := range []string{validHysteriaECH, "udp://1.1.1.1", "example.com+https://1.1.1.1/dns-query"} {
		t.Run(ech, func(t *testing.T) {
			l, err := ParseLink("hy2://auth@hy.example.com:46814?echConfigList=" + url.QueryEscape(ech) + "&sni=edge.example.com")
			if err != nil {
				t.Fatal(err)
			}
			tls := buildOutbound(l)["streamSettings"].(jobj)["tlsSettings"].(jobj)
			if tls["echConfigList"] != ech || tls["serverName"] != "edge.example.com" {
				t.Fatalf("ECH or explicit SNI lost: %#v", tls)
			}
		})
	}
}

func TestHysteria2StoredLinkUsesTLSNameOnRestart(t *testing.T) {
	t.Parallel()

	mgr, err := newManager(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	meta := &chainMeta{
		Link:        "hysteria2://auth@hy.example.com:46814?alpn=h3&obfs=salamander&obfs-password=mask&security=tls&sni=#hy",
		Protocol:    "hysteria2",
		Address:     "hy.example.com",
		Port:        46814,
		InboundPort: 13747,
		AutoRun:     true,
		XUDPBaseKey: newXUDPBaseKey(),
	}
	if err := mgr.store.writeMeta("xray1", meta); err != nil {
		t.Fatal(err)
	}
	if err := mgr.store.writeConfig("xray1", []byte(`{"inbounds":[],"outbounds":[]}`)); err != nil {
		t.Fatal(err)
	}
	path, _, err := mgr.prepareConfig("xray1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := decodeConfig(t, data)
	stream := cfg.Outbounds[0]["streamSettings"].(map[string]any)
	tls := stream["tlsSettings"].(map[string]any)
	if tls["serverName"] != "hy.example.com" || tls["allowInsecure"] == true {
		t.Fatalf("incorrect TLS settings after restart: %#v", tls)
	}
	if cfg.Inbounds[0]["port"] != float64(13747) {
		t.Errorf("inbound port changed: %v", cfg.Inbounds[0]["port"])
	}
	masks := stream["finalmask"].(map[string]any)["udp"].([]any)
	if mask := masks[0].(map[string]any); mask["type"] != "salamander" || mask["settings"].(map[string]any)["password"] != "mask" {
		t.Fatalf("obfuscation lost: %#v", masks)
	}
	stored, err := mgr.store.readMeta("xray1")
	if err != nil || *stored != *meta {
		t.Fatalf("metadata changed: %#v, err=%v", stored, err)
	}
}
