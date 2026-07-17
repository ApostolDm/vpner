package firewall

import (
	"strings"
	"testing"
)

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestResolveLocalExceptionsDefault(t *testing.T) {
	t.Parallel()

	v4, v6 := resolveLocalExceptions(nil)
	if !contains(v4, "192.168.0.0/16") {
		t.Fatalf("default v4 exceptions must contain 192.168.0.0/16, got %v", v4)
	}
	if !contains(v6, "fe80::/10") {
		t.Fatalf("default v6 exceptions must contain fe80::/10, got %v", v6)
	}
}

func TestResolveLocalExceptionsOverridePerFamily(t *testing.T) {
	t.Parallel()

	// User overrides only IPv4 -> IPv6 defaults must remain intact.
	v4, v6 := resolveLocalExceptions([]string{"192.168.1.0/24", "10.0.0.0/8"})
	if contains(v4, "192.168.0.0/16") {
		t.Fatalf("overridden v4 must not keep default 192.168.0.0/16: %v", v4)
	}
	if !contains(v4, "192.168.1.0/24") || !contains(v4, "10.0.0.0/8") {
		t.Fatalf("overridden v4 must contain the user entries: %v", v4)
	}
	if !contains(v6, "fe80::/10") {
		t.Fatalf("v6 defaults must remain when only v4 is overridden: %v", v6)
	}
}

func TestResolveLocalExceptionsSplitsAndBareIP(t *testing.T) {
	t.Parallel()

	v4, v6 := resolveLocalExceptions([]string{"192.168.14.88", "fd00::/8"})
	if !contains(v4, "192.168.14.88") {
		t.Fatalf("bare IPv4 must be accepted as a v4 exception: %v", v4)
	}
	if contains(v6, "fe80::/10") {
		t.Fatalf("v6 must be overridden when a v6 entry is provided: %v", v6)
	}
	if !contains(v6, "fd00::/8") {
		t.Fatalf("v6 entry must be present: %v", v6)
	}
}

func TestResolveLocalExceptionsIgnoresInvalid(t *testing.T) {
	t.Parallel()

	// Only an invalid entry -> both families fall back to defaults.
	v4, v6 := resolveLocalExceptions([]string{"not-an-ip", "   "})
	if !contains(v4, "192.168.0.0/16") {
		t.Fatalf("invalid-only override must keep v4 defaults: %v", v4)
	}
	if !contains(v6, "fe80::/10") {
		t.Fatalf("invalid-only override must keep v6 defaults: %v", v6)
	}
}

func TestExceptionsForSelectsFamily(t *testing.T) {
	t.Parallel()

	m := NewIptablesManager(true, false, 3600, []string{"192.168.1.0/24"})
	if !contains(m.exceptionsFor(familyV4), "192.168.1.0/24") {
		t.Fatalf("v4 family must use overridden list: %v", m.exceptionsFor(familyV4))
	}
	if !contains(m.exceptionsFor(familyV6), "fe80::/10") {
		t.Fatalf("v6 family must use default list: %v", m.exceptionsFor(familyV6))
	}
	if strings.Join(m.exceptionsFor(familyV4), ",") == strings.Join(m.exceptionsFor(familyV6), ",") {
		t.Fatalf("v4 and v6 exception lists must differ here")
	}
}
