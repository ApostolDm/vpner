package firewall

import (
	"path/filepath"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func TestDelChainMissingIsNoop(t *testing.T) {
	t.Parallel()

	mgr := NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, 0, nil)
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
	if rules, err := mgr.GetRules(vpnkind.OpenVPN.String(), "ovpn0"); err == nil && len(rules) != 0 {
		t.Fatalf("chain rules survived DelChain: %#v", rules)
	}
}

func TestUnblockManagerReturnsCopies(t *testing.T) {
	t.Parallel()

	mgr := NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, 0, nil)
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "*.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	rules, err := mgr.GetRules(vpnkind.OpenVPN.String(), "ovpn0")
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	rules[0] = "mutated.example.com"

	rulesAgain, err := mgr.GetRules(vpnkind.OpenVPN.String(), "ovpn0")
	if err != nil {
		t.Fatalf("GetRules again: %v", err)
	}
	if rulesAgain[0] != "*.example.com" {
		t.Fatalf("GetRules leaked internal slice mutation: %#v", rulesAgain)
	}

	conf, err := mgr.GetAllRules()
	if err != nil {
		t.Fatalf("GetAllRules: %v", err)
	}
	conf.Rules[vpnkind.OpenVPN.String()]["ovpn0"][0] = "mutated-again.example.com"

	confAgain, err := mgr.GetAllRules()
	if err != nil {
		t.Fatalf("GetAllRules again: %v", err)
	}
	if confAgain.Rules[vpnkind.OpenVPN.String()]["ovpn0"][0] != "*.example.com" {
		t.Fatalf("GetAllRules leaked internal config mutation: %#v", confAgain.Rules)
	}
}
