package network

import (
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/logging"
	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
)

// RestoreRouting rebuilds iptables rules for all stored VPN routes.
// table may be empty to restore both nat and mangle rules.
func (i *IptablesManager) RestoreRouting(table string, restoreV4, restoreV6 bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if restoreV6 && !i.ipv6Enabled {
		restoreV6 = false
	}
	if !restoreV4 && !restoreV6 {
		return
	}

	xrayApplied := false
	if i.restoreXrayFamily(restoreV4, familyV4, i.routingV4, table) {
		xrayApplied = true
	}
	if i.restoreXrayFamily(restoreV6, familyV6, i.routingV6, table) {
		xrayApplied = true
	}

	if i.tproxyEnabled && xrayApplied {
		i.tproxyInfraReady = true
		i.ipInfraReady = true
	}
}

func (i *IptablesManager) restoreXrayFamily(enabled bool, f ipFamily, routing map[string]vpnRoutingInfo, table string) bool {
	if !enabled {
		return false
	}

	specs := i.restoreForFamily(f, routing, table)
	if len(specs) == 0 {
		return false
	}

	if err := i.applyXrayBatch(f, routing, specs); err != nil {
		logging.Errorf("restore Xray %s batch: %v", f.iptablesCmd, err)
		return false
	}
	return true
}

// restoreForFamily iterates all routing entries for one IP family,
// restores non-Xray entries inline, and returns Xray ChainSpecs for
// batch application. Checks IPSetExists uniformly for all VPN types.
func (i *IptablesManager) restoreForFamily(f ipFamily, routing map[string]vpnRoutingInfo, table string) []ChainSpec {
	var xraySpecs []ChainSpec

	for ipsetName, info := range routing {
		if table != "" && info.Table != table {
			continue
		}
		if !IPSetExists(ipsetName) {
			logging.Warnf("restore: ipset %s missing; skip %s chain %s", ipsetName, info.VPNType, info.ChainName)
			continue
		}

		switch info.VPNType {
		case vpntypes.Xray:
			if info.Port == 0 {
				continue
			}
			xraySpecs = append(xraySpecs, ChainSpec{IPSetName: ipsetName, Port: info.Port, Ifaces: info.Ifaces})
		default:
			i.restoreMarkEntry(f, routing, ipsetName, info)
		}
	}

	return xraySpecs
}

// restoreMarkEntry rebuilds a single non-Xray VPN entry.
func (i *IptablesManager) restoreMarkEntry(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName string, info vpnRoutingInfo) {
	logging.Infof("restore routing: vpn=%s ipset=%s chain=%s", info.VPNType, ipsetName, info.ChainName)

	if err := ensureChain(f.iptablesCmd, info.Table, info.ChainName); err != nil {
		logging.Errorf("restore ensureChain %s: %v", info.ChainName, err)
		return
	}
	_ = run(f.iptablesCmd, "-t", info.Table, "-F", info.ChainName)

	var newJumps []jumpRule
	for _, iface := range info.Ifaces {
		jmp, err := linkChain(f.iptablesCmd, info.Table, info.ChainName, iface)
		if err != nil {
			logging.Errorf("restore linkChain %s: %v", info.ChainName, err)
			continue
		}
		newJumps = appendJumpRule(newJumps, jmp)
	}

	if info.Mark != 0 {
		for _, iface := range info.Ifaces {
			if err := addMarkRules(f, info.ChainName, ipsetName, info.Mark, iface); err != nil {
				logging.Errorf("restore addMarkRules %s: %v", info.ChainName, err)
			}
		}
	}

	if info.Mark != 0 && info.TableID != 0 && info.Dev != "" {
		mark := fmt.Sprintf("%d", info.Mark)
		tableID := fmt.Sprintf("%d", info.TableID)
		if !ipRuleExists(f, mark, tableID) {
			_ = addIPRule(f, info.Mark, info.TableID)
			_ = addIPRoute(f, info.TableID, info.Dev)
		}
	}

	info.JumpRules = newJumps
	routing[ipsetName] = info
}
