package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveOptionsMergesConfigAndFlags(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vpnerctl.yaml")
	cfgBody := []byte("addr: router.local:50051\nunix: /tmp/from-config.sock\npassword: secret\ntimeout: 30s\ndefault-chain: ovpn0\n")
	if err := os.WriteFile(cfgPath, cfgBody, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	opts, err := ResolveOptions(Options{
		ConfigPath:   cfgPath,
		Addr:         "10.0.0.2:9000",
		Timeout:      "45",
		DefaultChain: "wg0",
	})
	if err != nil {
		t.Fatalf("ResolveOptions: %v", err)
	}

	if opts.Addr != "10.0.0.2:9000" {
		t.Fatalf("unexpected addr: %s", opts.Addr)
	}
	if opts.Unix != "/tmp/from-config.sock" {
		t.Fatalf("unexpected unix path: %s", opts.Unix)
	}
	if opts.Password != "secret" {
		t.Fatalf("unexpected password: %s", opts.Password)
	}
	if opts.Timeout != 45*time.Second {
		t.Fatalf("unexpected timeout: %s", opts.Timeout)
	}
	if opts.DefaultChain != "wg0" {
		t.Fatalf("unexpected default chain: %s", opts.DefaultChain)
	}
}

func TestResolveOptionsDefaultsWhenConfigMissing(t *testing.T) {
	t.Parallel()

	opts, err := ResolveOptions(Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if err != nil {
		t.Fatalf("ResolveOptions: %v", err)
	}

	if opts.Unix != "/tmp/vpner.sock" {
		t.Fatalf("unexpected default unix path: %s", opts.Unix)
	}
	if opts.Addr != ":50051" {
		t.Fatalf("unexpected default addr: %s", opts.Addr)
	}
	if opts.Timeout != defaultTimeout {
		t.Fatalf("unexpected default timeout: %s", opts.Timeout)
	}
}

func TestParseTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "duration", value: "30s", want: 30 * time.Second},
		{name: "seconds as number", value: "2.5", want: 2500 * time.Millisecond},
		{name: "negative", value: "-1", wantErr: true},
		{name: "invalid", value: "abc", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTimeout(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("unexpected timeout for %q: got %s want %s", tc.value, got, tc.want)
			}
		})
	}
}
