package unblockservice

import (
	"path/filepath"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/network"
	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
)

type interfaceLookupStub struct {
	types map[string]string
}

func (s interfaceLookupStub) LookupTrackedType(name string) (string, bool) {
	value, ok := s.types[name]
	return value, ok
}

type xrayLookupStub struct {
	chains map[string]bool
}

func (s xrayLookupStub) IsChain(name string) bool {
	return s.chains[name]
}

func TestAddRuleAndList(t *testing.T) {
	t.Parallel()

	manager := network.NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, nil)
	service := New(manager, interfaceLookupStub{
		types: map[string]string{"ovpn0": vpntypes.OpenVPN.String()},
	}, xrayLookupStub{})

	if err := service.AddRule("ovpn0", "*.example.com"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	rules, err := service.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("unexpected rule groups: %d", len(rules))
	}
	if rules[0].TypeName != vpntypes.OpenVPN.String() || rules[0].ChainName != "ovpn0" {
		t.Fatalf("unexpected rule group: %#v", rules[0])
	}
	if len(rules[0].Rules) != 1 || rules[0].Rules[0] != "*.example.com" {
		t.Fatalf("unexpected rules: %#v", rules[0].Rules)
	}
}

func TestAddRuleRejectsOverlap(t *testing.T) {
	t.Parallel()

	manager := network.NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, nil)
	service := New(manager, interfaceLookupStub{
		types: map[string]string{"ovpn0": vpntypes.OpenVPN.String()},
	}, xrayLookupStub{})

	if err := service.AddRule("ovpn0", "*.example.com"); err != nil {
		t.Fatalf("first AddRule: %v", err)
	}
	if err := service.AddRule("ovpn0", "api.example.com"); err == nil {
		t.Fatalf("expected overlap error")
	}
}

func TestResolveXrayChainType(t *testing.T) {
	t.Parallel()

	manager := network.NewUnblockManager(filepath.Join(t.TempDir(), "rules.yaml"), false, false, 0, nil)
	service := New(manager, interfaceLookupStub{}, xrayLookupStub{
		chains: map[string]bool{"xray1": true},
	})

	if err := service.AddRule("xray1", "*.netflix.com"); err != nil {
		t.Fatalf("AddRule for xray chain: %v", err)
	}

	rules, err := service.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 1 || rules[0].TypeName != vpntypes.Xray.String() {
		t.Fatalf("unexpected xray rules: %#v", rules)
	}
}
