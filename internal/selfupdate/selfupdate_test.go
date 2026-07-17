package selfupdate

import "testing"

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v0.1.2", 1},
		{"v0.1.2", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0", 0},
		{"1.0.0", "v1.0.0", 0},
		{"v1.0.1", "v1.0.1-RC", 1}, // release > prerelease
		{"v1.0.1-RC", "v1.0.0", 1}, // RC of newer > older release
		{"v1.0.1-RC", "v1.0.1-RC", 0},
		{"v0.1.10", "v0.1.2", 1}, // numeric, not lexical
		{"dev", "v1.0.0", -1},    // unparseable current -> older
		{"v1.0.0", "dev", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPickLatest(t *testing.T) {
	t.Parallel()

	releases := []Release{
		{TagName: "v0.1.2", Prerelease: false},
		{TagName: "v1.0.0", Prerelease: true},
		{TagName: "v1.0.1-RC", Prerelease: true},
		{TagName: "v0.1.1", Prerelease: false},
		{TagName: "v9.9.9", Draft: true},
	}

	stable, ok := PickLatest(releases, false)
	if !ok || stable.TagName != "v0.1.2" {
		t.Fatalf("stable latest = %q (ok=%v), want v0.1.2", stable.TagName, ok)
	}

	withPre, ok := PickLatest(releases, true)
	if !ok || withPre.TagName != "v1.0.1-RC" {
		t.Fatalf("prerelease latest = %q (ok=%v), want v1.0.1-RC", withPre.TagName, ok)
	}
}

func TestSelectIPK(t *testing.T) {
	t.Parallel()

	rel := Release{Assets: []Asset{
		{Name: "vpnerd_v0.1.2_aarch64-3.10.ipk"},
		{Name: "vpnerd_v0.1.2_aarch64-3.10_kn.ipk"},
		{Name: "vpnerd_v0.1.2_mips-3.4.ipk"},
		{Name: "vpnerhookcli-aarch64-3.10"},
	}}

	plain, ok := rel.SelectIPK("vpnerd", []string{"aarch64-3.10"}, false)
	if !ok || plain.Name != "vpnerd_v0.1.2_aarch64-3.10.ipk" {
		t.Fatalf("plain select = %q ok=%v", plain.Name, ok)
	}

	kn, ok := rel.SelectIPK("vpnerd", []string{"aarch64-3.10"}, true)
	if !ok || kn.Name != "vpnerd_v0.1.2_aarch64-3.10_kn.ipk" {
		t.Fatalf("kn select = %q ok=%v", kn.Name, ok)
	}

	mips, ok := rel.SelectIPK("vpnerd", []string{"mips-3.4"}, true)
	if !ok || mips.Name != "vpnerd_v0.1.2_mips-3.4.ipk" {
		t.Fatalf("mips fallback select = %q ok=%v", mips.Name, ok)
	}

	if _, ok := rel.SelectIPK("vpnerd", []string{"riscv64-6.1"}, false); ok {
		t.Fatalf("expected no match for unknown arch")
	}

	// arch priority order: first tag that matches wins
	got, ok := rel.SelectIPK("vpnerd", []string{"mips-3.4", "aarch64-3.10"}, false)
	if !ok || got.Name != "vpnerd_v0.1.2_mips-3.4.ipk" {
		t.Fatalf("priority select = %q ok=%v", got.Name, ok)
	}
}

func TestParseOpkgArchitectures(t *testing.T) {
	t.Parallel()

	out := "arch all 1\narch noarch 1\narch aarch64-3.10 160\narch mips-3.4 10\n"
	got := ParseOpkgArchitectures(out)
	if len(got) != 2 || got[0] != "aarch64-3.10" || got[1] != "mips-3.4" {
		t.Fatalf("ParseOpkgArchitectures = %v, want [aarch64-3.10 mips-3.4]", got)
	}
}
