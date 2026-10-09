package firewall

import (
	"net"
	"strings"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func TestDefaultMarkRulesShape(t *testing.T) {
	t.Parallel()

	rules := defaultMarkRules([]string{"br0"}, []string{"10.0.0.0/8", "192.168.1.1/32"}, 125, true, true)
	want := []string{
		"-A VPN_DEFAULT -i br0 -j CONNMARK --restore-mark --nfmask 0x1fff --ctmask 0x1fff",
		"-A VPN_DEFAULT -i br0 -m mark ! --mark 0/0x1fff -j RETURN",
		"-A VPN_DEFAULT -i br0 -d 10.0.0.0/8 -j RETURN",
		"-A VPN_DEFAULT -i br0 -d 192.168.1.1/32 -j RETURN",
		"-A VPN_DEFAULT -i br0 -m conntrack --ctdir ORIGINAL -j MARK --set-mark 125",
		"-A VPN_DEFAULT -i br0 -m mark --mark 125 -j CONNMARK --save-mark --nfmask 0x1fff --ctmask 0x1fff",
	}
	if strings.Join(rules, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected mark rules:\n%s", strings.Join(rules, "\n"))
	}

	plain := defaultMarkRules([]string{"br0"}, nil, 125, false, false)
	wantPlain := []string{
		"-A VPN_DEFAULT -i br0 -m mark ! --mark 0/0x1fff -j RETURN",
		"-A VPN_DEFAULT -i br0 -j MARK --set-mark 125",
	}
	if strings.Join(plain, "\n") != strings.Join(wantPlain, "\n") {
		t.Fatalf("unexpected plain mark rules:\n%s", strings.Join(plain, "\n"))
	}
}

func TestDefaultTProxyAndRedirectRulesShape(t *testing.T) {
	t.Parallel()

	tproxy := defaultTProxyRules([]string{"br0", "br1"}, []string{"127.0.0.0/8"}, 12345, true, true)
	wantTail := []string{
		"-A VPN_DEFAULT -i br1 -j CONNMARK --restore-mark --nfmask 0x1fff --ctmask 0x1fff",
		"-A VPN_DEFAULT -i br1 -m mark ! --mark 0/0x1fff -j RETURN",
		"-A VPN_DEFAULT -i br1 -d 127.0.0.0/8 -j RETURN",
		"-A VPN_DEFAULT -i br1 -p tcp -m conntrack --ctdir ORIGINAL -j TPROXY --on-port 12345 --tproxy-mark 200",
		"-A VPN_DEFAULT -i br1 -p udp -m conntrack --ctdir ORIGINAL -j TPROXY --on-port 12345 --tproxy-mark 200",
	}
	if got := strings.Join(tproxy[len(tproxy)-5:], "\n"); got != strings.Join(wantTail, "\n") {
		t.Fatalf("unexpected tproxy tail:\n%s", got)
	}
	noCtdir := defaultTProxyRules([]string{"br0"}, nil, 1, false, false)
	if noCtdir[len(noCtdir)-1] != "-A VPN_DEFAULT -i br0 -p udp -j TPROXY --on-port 1 --tproxy-mark 200" {
		t.Fatalf("ctdir fallback must emit the plain TPROXY rule: %s", noCtdir[len(noCtdir)-1])
	}

	redirect := defaultRedirectRules([]string{"br0"}, []string{"127.0.0.0/8"}, 12345)
	want := []string{
		"-A VPN_DEFAULT -i br0 -m mark ! --mark 0/0x1fff -j RETURN",
		"-A VPN_DEFAULT -i br0 -d 127.0.0.0/8 -j RETURN",
		"-A VPN_DEFAULT -i br0 -p tcp -j REDIRECT --to-ports 12345",
	}
	if strings.Join(redirect, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected redirect rules:\n%s", strings.Join(redirect, "\n"))
	}
}

func TestDefaultExceptionsUnionKeepsBuiltins(t *testing.T) {
	t.Parallel()

	m := NewIptablesManager(true, false, 3600, []string{"192.168.1.0/24", "10.0.0.0/8"}, nil)
	v4 := m.defaultExceptionsFor(familyV4)
	for _, cidr := range append(localExceptionsV4[:], "100.64.0.0/10", "192.168.1.0/24") {
		if !contains(v4, cidr) {
			t.Fatalf("v4 default exceptions must contain %s: %v", cidr, v4)
		}
	}
	if n := strings.Count(strings.Join(v4, ","), "10.0.0.0/8"); n != 1 {
		t.Fatalf("duplicate exception must be collapsed, got %d copies: %v", n, v4)
	}
	v6 := m.defaultExceptionsFor(familyV6)
	if strings.Join(v6, ",") != strings.Join(localExceptionsIPv6[:], ",") {
		t.Fatalf("v6 defaults must be the built-in list when the user lists only v4: %v", v6)
	}
}

func TestLocalNetworksAreFamilyScopedCIDRs(t *testing.T) {
	t.Parallel()

	for _, f := range []ipFamily{familyV4, familyV6} {
		for _, cidr := range localNetworks(f) {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatalf("%s: %q is not a CIDR: %v", f.iptablesCmd, cidr, err)
			}
			if (ip.To4() != nil) != (f.iptablesCmd == familyV4.iptablesCmd) {
				t.Fatalf("%s: %q belongs to the other family", f.iptablesCmd, cidr)
			}
		}
	}
	v4 := localNetworks(familyV4)
	if !contains(v4, "127.0.0.1/32") {
		t.Skipf("loopback not enumerated on this host: %v", v4)
	}
	if !contains(v4, "127.0.0.0/8") {
		t.Fatalf("connected network of each address must be listed: %v", v4)
	}
}

func TestDefaultSpecFollowsRoutingEntry(t *testing.T) {
	t.Parallel()

	m := NewIptablesManager(false, true, 3600, nil, []string{"br0"})
	yes := true
	m.connmarkV4 = &yes
	m.ctdirV4 = &yes

	if _, ok, _ := m.defaultSpecLocked(familyV4, m.routingV4); ok {
		t.Fatal("no target must yield no spec")
	}

	m.defaultTarget = &defaultTarget{kind: vpnkind.OpenVPN, ipsetName: "vpner-OpenVPN-OpenVPN0"}
	if _, ok, err := m.defaultSpecLocked(familyV4, m.routingV4); ok || err != nil {
		t.Fatalf("target without a routing entry must be pending without error: ok=%v err=%v", ok, err)
	}

	m.routingV4["vpner-OpenVPN-OpenVPN0"] = vpnRoutingInfo{VPNType: vpnkind.OpenVPN, Mark: 125, TableID: 125, Table: tableMangle}
	spec, ok, _ := m.defaultSpecLocked(familyV4, m.routingV4)
	if !ok || spec.table != tableMangle || !strings.HasPrefix(spec.key, "mark|125|true|br0|true|") {
		t.Fatalf("unexpected mark spec: ok=%v %+v", ok, spec)
	}
	if !strings.Contains(spec.rules[len(spec.rules)-2], "--ctdir ORIGINAL -j MARK --set-mark 125") {
		t.Fatalf("mark spec must gate on ctdir: %v", spec.rules)
	}

	m.defaultTarget = &defaultTarget{kind: vpnkind.Xray, ipsetName: "vpner-Xray-xray1"}
	m.routingV4["vpner-Xray-xray1"] = vpnRoutingInfo{VPNType: vpnkind.Xray, Port: 12345, Table: tableMangle}
	spec, ok, _ = m.defaultSpecLocked(familyV4, m.routingV4)
	if !ok || spec.table != tableMangle || !strings.HasPrefix(spec.key, "tproxy|12345|true|br0|true|") {
		t.Fatalf("unexpected tproxy spec: ok=%v %+v", ok, spec)
	}

	m.routingV4["vpner-Xray-xray1"] = vpnRoutingInfo{VPNType: vpnkind.Xray, Port: 12345, Table: tableNat}
	spec, ok, _ = m.defaultSpecLocked(familyV4, m.routingV4)
	if !ok || spec.table != tableNat || !strings.HasPrefix(spec.key, "redirect|12345|br0|true|") {
		t.Fatalf("unexpected redirect spec: ok=%v %+v", ok, spec)
	}

	m.defaultTarget = &defaultTarget{kind: vpnkind.OpenVPN, ipsetName: "vpner-Xray-xray1"}
	if _, ok, _ := m.defaultSpecLocked(familyV4, m.routingV4); ok {
		t.Fatal("kind mismatch between target and routing entry must yield no spec")
	}
}

func TestResetDefaultKeepsTableAndNotifies(t *testing.T) {
	t.Parallel()

	m := NewIptablesManager(true, true, 3600, nil, nil)
	var seen []bool
	m.defaultObserver = func(applied bool) { seen = append(seen, applied) }
	m.setAppliedLocked(defaultFamily{familyV4, m.routingV4, &m.defaultV4}, tableMangle, "k")
	m.setAppliedLocked(defaultFamily{familyV6, m.routingV6, &m.defaultV6}, tableMangle, "k")

	m.resetDefaultLocked(tableNat, true, true)
	if m.defaultV4.key == "" || m.defaultV6.key == "" {
		t.Fatal("nat flush must not clear a mangle default record")
	}
	m.resetDefaultLocked(tableMangle, true, false)
	if m.defaultV4.key != "" || m.defaultV4.table != tableMangle || m.defaultV6.key == "" {
		t.Fatalf("v4-only mangle flush must clear only the v4 key and keep the table: %+v %+v", m.defaultV4, m.defaultV6)
	}
	m.resetDefaultLocked("", false, true)
	if m.defaultV6.key != "" || m.defaultV6.table != tableMangle {
		t.Fatalf("untabled flush must clear the v6 key and keep the table: %+v", m.defaultV6)
	}
	if len(seen) != 2 || !seen[0] || seen[1] {
		t.Fatalf("observer must see v4 applied then unapplied, got %v", seen)
	}
}

func TestParseChainRulesCountsDuplicates(t *testing.T) {
	t.Parallel()

	save := `*mangle
:PREROUTING ACCEPT [0:0]
:VPN_DEFAULT - [0:0]
-A PREROUTING -i br0 -p tcp -m socket --transparent -j VPN_DIVERT
-A PREROUTING -i br0 -j VPN_00000001
-A PREROUTING -i br0 -j VPN_DEFAULT
-A PREROUTING -i br0 -j VPN_DEFAULT
-A VPN_DEFAULT -i br0 -j MARK --set-mark 125
COMMIT
`
	counts := parseChainRules(strings.NewReader(save), chainPrerouting)
	if counts[preroutingJumpSpec(chainDefault, "br0")] != 2 {
		t.Fatalf("duplicate jumps must be counted: %v", counts)
	}
	if counts[preroutingJumpSpec("VPN_00000001", "br0")] != 1 || len(counts) != 3 {
		t.Fatalf("unexpected PREROUTING parse: %v", counts)
	}
	if _, ok := counts["-A VPN_DEFAULT -i br0 -j MARK --set-mark 125"]; ok {
		t.Fatal("rules of other chains must not be counted")
	}
}

func TestRegisterXrayEntryPreservesJumps(t *testing.T) {
	t.Parallel()

	m := NewIptablesManager(false, true, 3600, nil, []string{"br0"})
	m.routingV4["vpner-Xray-xray1"] = vpnRoutingInfo{
		VPNType:   vpnkind.Xray,
		ChainName: buildChainName("vpner-Xray-xray1"),
		Table:     tableMangle,
		Port:      12345,
		Ifaces:    []string{"br0"},
		JumpRules: []jumpRule{newJumpRule("iptables", tableMangle, buildChainName("vpner-Xray-xray1"), "br0")},
	}
	m.registerXrayEntryLocked("vpner-Xray-xray1", 12345, []string{"br0"})
	if len(m.routingV4["vpner-Xray-xray1"].JumpRules) != 1 {
		t.Fatal("re-registering an unchanged xray entry must keep its applied jumps")
	}
	m.registerXrayEntryLocked("vpner-Xray-xray1", 23456, []string{"br0"})
	if len(m.routingV4["vpner-Xray-xray1"].JumpRules) != 0 {
		t.Fatal("a port change must reset the applied jumps")
	}
}
