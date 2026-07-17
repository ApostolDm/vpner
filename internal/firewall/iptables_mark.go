package firewall

import (
	"fmt"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (i *IptablesManager) MarkRouteKnown(ipsetName string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()

	info, ok := i.routingV4[ipsetName]
	return ok && info.VPNType != vpnkind.Xray
}

func (i *IptablesManager) EnsureMarkIPSets(ipsetName string) error {
	if err := ensureManagedIPSet(ipsetName, false, i.entryTimeout); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return ensureManagedIPSet(ipsetName6, true, i.entryTimeout)
}

func (i *IptablesManager) AddMarkRoute(vpnType vpnkind.Kind, ipsetName string, lanIfaces []string, vpnIface string) error {
	if vpnIface == "" {
		return fmt.Errorf("vpn interface is required for %s routing", vpnType)
	}
	if len(lanIfaces) == 0 {
		return fmt.Errorf("no LAN interfaces configured for %s routing", vpnType)
	}

	if err := i.AddRules(vpnType, ipsetName, 0, lanIfaces[0], vpnIface); err != nil {
		_ = i.RemoveMarkRoute(ipsetName)
		return err
	}
	for _, iface := range lanIfaces[1:] {
		if err := i.extendMarkRoute(ipsetName, iface); err != nil {
			_ = i.RemoveRules(ipsetName)
			return err
		}
	}
	return nil
}

func (i *IptablesManager) SyncMarkRoute(ipsetName, vpnIface string) error {
	if vpnIface == "" {
		return fmt.Errorf("vpn interface is required")
	}
	if err := validateIface(vpnIface); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.syncMarkRouteForFamily(familyV4, i.routingV4, ipsetName, vpnIface); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.syncMarkRouteForFamily(familyV6, i.routingV6, ipsetName6, vpnIface)
}

func (i *IptablesManager) syncMarkRouteForFamily(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName, vpnIface string) error {
	info, ok := routing[ipsetName]
	if !ok || info.VPNType == vpnkind.Xray || info.Mark == 0 || info.TableID == 0 {
		return nil
	}

	if info.Dev != vpnIface {
		logx.Infof("update mark route %s: dev %s -> %s", ipsetName, info.Dev, vpnIface)
		flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", info.TableID))
		tryRun("ip", flushArgs...)
		info.Dev = vpnIface
		routing[ipsetName] = info
	}

	mark := fmt.Sprintf("%d", info.Mark)
	tableID := fmt.Sprintf("%d", info.TableID)
	if !ipRuleExists(f, mark, tableID) {
		if err := addIPRule(f, info.Mark, info.TableID); err != nil {
			return err
		}
	}
	if err := addIPRoute(f, info.TableID, vpnIface); err != nil && !isExistsError(err) {
		return err
	}
	return nil
}

func isExistsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "exists")
}

func (i *IptablesManager) MarkRouteIntact(ipsetName string) bool {
	i.mu.Lock()
	info, ok := i.routingV4[ipsetName]
	var info6 vpnRoutingInfo
	var ok6 bool
	if i.ipv6Enabled {
		if ipsetName6, err := IpsetName6FromBase(ipsetName); err == nil {
			info6, ok6 = i.routingV6[ipsetName6]
		}
	}
	i.mu.Unlock()

	if !ok || info.VPNType == vpnkind.Xray {
		return false
	}
	if !markRouteFamilyIntact(familyV4, info) {
		return false
	}
	if !ok6 || info6.VPNType == vpnkind.Xray {
		return true
	}
	return markRouteFamilyIntact(familyV6, info6)
}

func markRouteFamilyIntact(f ipFamily, info vpnRoutingInfo) bool {
	if info.TableID == 0 || info.Dev == "" {
		return true
	}
	return routeTablePopulated(f, info.TableID)
}

func (i *IptablesManager) RemoveMarkRoute(ipsetName string) error {
	if !i.MarkRouteKnown(ipsetName) {
		return nil
	}
	return i.RemoveRules(ipsetName)
}

func (i *IptablesManager) extendMarkRoute(ipsetName, iface string) error {
	if err := validateIface(iface); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.extendMarkRouteForFamily(familyV4, i.routingV4, ipsetName, iface); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.extendMarkRouteForFamily(familyV6, i.routingV6, ipsetName6, iface)
}

func (i *IptablesManager) extendMarkRouteForFamily(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName, iface string) error {
	info, ok := routing[ipsetName]
	if !ok {
		return fmt.Errorf("no routing info found for ipset: %s", ipsetName)
	}
	for _, existing := range info.Ifaces {
		if existing == iface {
			return nil
		}
	}

	jmp, err := linkChain(f.iptablesCmd, info.Table, info.ChainName, iface)
	if err != nil {
		return err
	}
	if err := addMarkRules(f, info.ChainName, ipsetName, info.Mark, iface, i.exceptionsFor(f)); err != nil {
		tryRun(jmp.Cmd, jmp.deleteArgs()...)
		return err
	}

	info.Ifaces = append(info.Ifaces, iface)
	info.JumpRules = appendJumpRule(info.JumpRules, jmp)
	routing[ipsetName] = info
	return nil
}
