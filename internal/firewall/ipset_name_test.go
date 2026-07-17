package firewall

import (
	"strings"
	"testing"
)

func TestValidateIpsetNameBoundary(t *testing.T) {
	t.Parallel()

	ok := strings.Repeat("a", maxIpsetNameLen)
	if got, err := validateIpsetName(ok); err != nil || got != ok {
		t.Fatalf("name of %d chars must be accepted, got %q err=%v", maxIpsetNameLen, got, err)
	}

	tooLong := strings.Repeat("a", maxIpsetNameLen+1)
	if _, err := validateIpsetName(tooLong); err == nil {
		t.Fatalf("name of %d chars must be rejected", maxIpsetNameLen+1)
	}
}

func TestIpsetNameLengthLimit(t *testing.T) {
	t.Parallel()

	// "vpner-OpenVPN-" is 14 chars; a 17-char chain hits the 31-char limit exactly.
	chain31 := strings.Repeat("c", maxIpsetNameLen-len("vpner-OpenVPN-"))
	name, err := IpsetName("OpenVPN", chain31)
	if err != nil {
		t.Fatalf("31-char name must be accepted: %v", err)
	}
	if len(name) != maxIpsetNameLen {
		t.Fatalf("expected length %d, got %d (%s)", maxIpsetNameLen, len(name), name)
	}

	if _, err := IpsetName("OpenVPN", chain31+"c"); err == nil {
		t.Fatalf("32-char name must be rejected")
	}
}

func TestIpsetName6SuffixFits(t *testing.T) {
	t.Parallel()

	// A v4 base at the 31-char limit cannot fit the "-6" suffix.
	base := strings.Repeat("b", maxIpsetNameLen)
	if _, err := IpsetName6FromBase(base); err == nil {
		t.Fatalf("v6 name %q (base+\"-6\") exceeds %d chars and must be rejected", base+ipv6Suffix, maxIpsetNameLen)
	}

	// The longest base that still leaves room for "-6".
	fits := strings.Repeat("b", maxIpsetNameLen-len(ipv6Suffix))
	name, err := IpsetName6FromBase(fits)
	if err != nil {
		t.Fatalf("v6 name must be accepted: %v", err)
	}
	if len(name) != maxIpsetNameLen {
		t.Fatalf("expected v6 length %d, got %d (%s)", maxIpsetNameLen, len(name), name)
	}
}

func TestIpsetNamePairFitsForRealisticNames(t *testing.T) {
	t.Parallel()

	// Both families must fit for the longest VPN type and a realistic chain name.
	// v6 name = "vpner-WireGuard-" (16) + chain + "-6" (2) must be <= 31 => chain <= 13.
	const chain = "wireguard0abc" // 13 chars

	v4, err := IpsetName("WireGuard", chain)
	if err != nil {
		t.Fatalf("v4 name rejected: %v", err)
	}
	v6, err := IpsetName6("WireGuard", chain)
	if err != nil {
		t.Fatalf("v6 name rejected: %v", err)
	}
	if len(v4) > maxIpsetNameLen || len(v6) > maxIpsetNameLen {
		t.Fatalf("names exceed limit: v4=%q(%d) v6=%q(%d)", v4, len(v4), v6, len(v6))
	}
}
