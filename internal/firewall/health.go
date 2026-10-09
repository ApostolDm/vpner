package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
)

func (i *IptablesManager) RoutingIntact() bool {
	type probe struct{ iptablesCmd, table, chain, ipsetName string }

	var probes []probe
	type defaultProbe struct {
		f     ipFamily
		table string
	}
	var defaults []defaultProbe
	var tproxyFamilies []ipFamily
	i.mu.Lock()
	for _, fam := range i.defaultFamilies() {
		if spec, ok, _ := i.defaultSpecLocked(fam.f, fam.routing); ok {
			defaults = append(defaults, defaultProbe{fam.f, spec.table})
		}
	}
	for _, fam := range []struct {
		f       ipFamily
		routing map[string]vpnRoutingInfo
	}{
		{familyV4, i.routingV4},
		{familyV6, i.routingV6},
	} {
		for ipsetName, info := range fam.routing {
			probes = append(probes, probe{fam.f.iptablesCmd, info.Table, info.ChainName, ipsetName})
		}
		if i.tproxyEnabled && len(fam.routing) > 0 {
			tproxyFamilies = append(tproxyFamilies, fam.f)
		}
	}
	i.mu.Unlock()

	for _, p := range probes {
		if !chainExists(p.iptablesCmd, p.table, p.chain) || !IPSetExists(p.ipsetName) {
			return false
		}
	}
	for _, d := range defaults {
		if !i.defaultIntact(d.f, d.table) {
			return false
		}
	}
	for _, f := range tproxyFamilies {
		if !tproxyLocalRoutingIntact(f) {
			return false
		}
	}
	return true
}

func chainExists(iptablesCmd, table, chain string) bool {
	return exec.Command(iptablesCmd, "-t", table, "-n", "-L", chain).Run() == nil
}

func routeTablePopulated(f ipFamily, tableID int) bool {
	args := append(f.ipFlags, "route", "show", "table", fmt.Sprintf("%d", tableID))
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		return true
	}
	return len(bytes.TrimSpace(out)) > 0
}
