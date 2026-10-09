package proxy

import "testing"

func TestXUDPBaseKeyPersistsAcrossRestarts(t *testing.T) {
	t.Parallel()

	mgr, err := newManager(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	meta := &chainMeta{
		Link:        "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443?security=reality&pbk=key&sni=example.com#vl",
		Protocol:    "vless",
		Address:     "vl.example.com",
		Port:        443,
		InboundPort: 13747,
	}
	if err := mgr.store.writeMeta("xray1", meta); err != nil {
		t.Fatal(err)
	}
	_, first, err := mgr.prepareConfig("xray1")
	if err != nil {
		t.Fatal(err)
	}
	if !validXUDPBaseKey(first) {
		t.Fatalf("generated key is not a 32-byte raw-url base64 value: %q", first)
	}
	_, second, err := mgr.prepareConfig("xray1")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("key changed between starts: %q -> %q", first, second)
	}
	stored, err := mgr.store.readMeta("xray1")
	if err != nil || stored.XUDPBaseKey != first {
		t.Fatalf("key not persisted: %#v err=%v", stored, err)
	}
	if err := mgr.write("xray1", meta.Link, &Link{Protocol: ProtoVLESS, Address: meta.Address, Port: meta.Port}, meta.InboundPort, false, stored.XUDPBaseKey, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if stored, err = mgr.store.readMeta("xray1"); err != nil || stored.XUDPBaseKey != first {
		t.Fatalf("update dropped the key: %#v err=%v", stored, err)
	}
	if newXUDPBaseKey() == first {
		t.Fatal("keys are not random")
	}
}
