package backup

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateRestoreRoundTrip(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "xray"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"vpner.yaml":       "dnsServer:\n  port: 53\n",
		"xray/chain.json":  "{\"a\":1}",
		"xray/chain.vpner": "meta",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	arc := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := Create(src, arc); err != nil {
		t.Fatalf("create: %v", err)
	}

	dst := t.TempDir()
	if err := Restore(arc, dst); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for name, body := range files {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		if string(got) != body {
			t.Fatalf("%s content mismatch: %q != %q", name, got, body)
		}
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	arc := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(arc)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("pwned")
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	tw.Close()
	gz.Close()
	f.Close()

	dst := t.TempDir()
	if err := Restore(arc, dst); err == nil {
		t.Fatal("expected restore to reject path traversal")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "escape.txt")); err == nil {
		t.Fatal("path traversal wrote outside the state dir")
	}
}
