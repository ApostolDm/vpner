package firewall

import (
	"os/exec"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (i *IptablesManager) XrayRoutingIntact() bool {
	type probe struct{ iptablesCmd, table, chain, ipsetName string }

	var probes []probe
	i.mu.Lock()
	for _, fam := range []struct {
		f       ipFamily
		routing map[string]vpnRoutingInfo
	}{
		{familyV4, i.routingV4},
		{familyV6, i.routingV6},
	} {
		for ipsetName, info := range fam.routing {
			if info.VPNType == vpnkind.Xray {
				probes = append(probes, probe{fam.f.iptablesCmd, info.Table, info.ChainName, ipsetName})
			}
		}
	}
	i.mu.Unlock()

	for _, p := range probes {
		if !chainExists(p.iptablesCmd, p.table, p.chain) || !IPSetExists(p.ipsetName) {
			return false
		}
	}
	return true
}

func chainExists(iptablesCmd, table, chain string) bool {
	return exec.Command(iptablesCmd, "-t", table, "-n", "-L", chain).Run() == nil
}
