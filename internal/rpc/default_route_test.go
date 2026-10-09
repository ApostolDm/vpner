package rpc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRouteStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", DefaultRouteFileName)
	if d, err := loadDefaultRoute(path); err != nil || d.set() {
		t.Fatalf("missing file must read as unset: %+v %v", d, err)
	}

	want := defaultRoute{Type: "OpenVPN", Chain: "OpenVPN0"}
	if err := saveDefaultRoute(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := loadDefaultRoute(path)
	if err != nil || got != want {
		t.Fatalf("load = %+v, %v; want %+v", got, err, want)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file must not survive a save")
	}

	if err := saveDefaultRoute(path, defaultRoute{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("clearing must remove the state file")
	}
	if err := saveDefaultRoute(path, defaultRoute{}); err != nil {
		t.Fatalf("clearing twice must be a no-op: %v", err)
	}

	if err := os.WriteFile(path, []byte("type: Xray\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if d, err := loadDefaultRoute(path); err != nil || d.set() {
		t.Fatalf("partial state must read as unset: %+v %v", d, err)
	}
	if err := os.WriteFile(path, []byte("type: [\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDefaultRoute(path); err == nil {
		t.Fatal("corrupt state must surface an error")
	}
}
