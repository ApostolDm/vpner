package firewall

import (
	"testing"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func TestDelChainMissingIsNoop(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.DelChain(vpnkind.OpenVPN.String(), "ovpn0"); err != nil {
		t.Fatalf("DelChain on empty config: %v", err)
	}

	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "*.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := mgr.DelChain(vpnkind.OpenVPN.String(), "other"); err != nil {
		t.Fatalf("DelChain on missing chain: %v", err)
	}
	if err := mgr.DelChain(vpnkind.OpenVPN.String(), "ovpn0"); err != nil {
		t.Fatalf("DelChain: %v", err)
	}
	if n := mgr.RuleCount(vpnkind.OpenVPN.String(), "ovpn0"); n != 0 {
		t.Fatalf("chain rules survived DelChain: %d", n)
	}
}

func TestGroupsReturnsCopies(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "*.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	groups := mgr.Groups()
	groups[0].Rules[0] = "mutated.example.com"

	again := mgr.Groups()
	if again[0].Rules[0] != "*.example.com" {
		t.Fatalf("Groups leaked internal slice mutation: %#v", again[0].Rules)
	}
}
