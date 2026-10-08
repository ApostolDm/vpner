package firewall

import (
	"path/filepath"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func newTestUnblockManager(t *testing.T) *UnblockManager {
	t.Helper()
	return NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, 0, 0, nil)
}

func TestAddRuleAndGroups(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "*.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	groups := mgr.Groups()
	if len(groups) != 1 {
		t.Fatalf("unexpected rule groups: %d", len(groups))
	}
	if groups[0].TypeName != vpnkind.OpenVPN.String() || groups[0].ChainName != "ovpn0" {
		t.Fatalf("unexpected rule group: %#v", groups[0])
	}
	if len(groups[0].Rules) != 1 || groups[0].Rules[0] != "*.example.com" {
		t.Fatalf("unexpected rules: %#v", groups[0].Rules)
	}
}

func TestAddRuleRejectsOverlapAndInvalid(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "*.example.com"); err != nil {
		t.Fatalf("first AddRule: %v", err)
	}
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "api.example.com"); err == nil {
		t.Fatal("expected overlap error")
	}
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "bad/pattern"); err == nil {
		t.Fatal("expected validation error")
	}
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "", "x.example.org"); err == nil {
		t.Fatal("expected empty chain error")
	}
}

func TestDeleteRuleByPatternAndCount(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "api.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if got := mgr.RuleCount(vpnkind.OpenVPN.String(), "ovpn0"); got != 1 {
		t.Fatalf("unexpected rule count: %d", got)
	}

	delType, delChain, err := mgr.DeleteRuleByPattern("api.example.com")
	if err != nil {
		t.Fatalf("DeleteRuleByPattern: %v", err)
	}
	if delType != vpnkind.OpenVPN.String() || delChain != "ovpn0" {
		t.Fatalf("unexpected delete result: %s/%s", delType, delChain)
	}
	if got := mgr.RuleCount(delType, delChain); got != 0 {
		t.Fatalf("unexpected rule count after delete: %d", got)
	}
	if _, _, err := mgr.DeleteRuleByPattern("api.example.com"); err == nil {
		t.Fatal("deleting a missing rule must fail")
	}
}

func TestMatchDomainUsesIndexAfterMutations(t *testing.T) {
	t.Parallel()

	mgr := newTestUnblockManager(t)
	if err := mgr.AddRule(vpnkind.Xray.String(), "xray1", "*.netflix.com"); err != nil {
		t.Fatalf("AddRule wildcard: %v", err)
	}
	if err := mgr.AddRule(vpnkind.OpenVPN.String(), "ovpn0", "exact.example.org"); err != nil {
		t.Fatalf("AddRule exact: %v", err)
	}

	if typ, chain, rule, ok := mgr.MatchDomain("www.netflix.com"); !ok || typ != vpnkind.Xray.String() || chain != "xray1" || rule != "*.netflix.com" {
		t.Fatalf("wildcard match = %s/%s/%s ok=%v", typ, chain, rule, ok)
	}
	if typ, chain, _, ok := mgr.MatchDomain("exact.example.org"); !ok || typ != vpnkind.OpenVPN.String() || chain != "ovpn0" {
		t.Fatalf("exact match = %s/%s ok=%v", typ, chain, ok)
	}
	if _, _, _, ok := mgr.MatchDomain("other.example.org"); ok {
		t.Fatal("unrelated domain must not match")
	}

	if _, _, err := mgr.DeleteRuleByPattern("exact.example.org"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, _, ok := mgr.MatchDomain("exact.example.org"); ok {
		t.Fatal("index must be rebuilt after delete")
	}
	if err := mgr.DelChain(vpnkind.Xray.String(), "xray1"); err != nil {
		t.Fatalf("DelChain: %v", err)
	}
	if _, _, _, ok := mgr.MatchDomain("www.netflix.com"); ok {
		t.Fatal("index must be rebuilt after DelChain")
	}
}
