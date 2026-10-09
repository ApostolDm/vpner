package firewall

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

type XrayRouteState struct {
	Known     bool
	V4Applied bool
	V6Applied bool
}

func (i *IptablesManager) IPv6Enabled() bool {
	return i.ipv6Enabled
}

func (i *IptablesManager) XrayTable() string {
	if i.tproxyEnabled {
		return tableMangle
	}
	return tableNat
}

func routeApplied(info vpnRoutingInfo) bool {
	return len(info.JumpRules) > 0
}

func (i *IptablesManager) XrayState(ipsetName string) XrayRouteState {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.xrayStateLocked(ipsetName)
}

func (i *IptablesManager) xrayStateLocked(ipsetName string) XrayRouteState {
	var state XrayRouteState

	if info, ok := i.routingV4[ipsetName]; ok && info.VPNType == vpnkind.Xray {
		state.Known = true
		state.V4Applied = routeApplied(info)
	}
	if !i.ipv6Enabled {
		return state
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return state
	}
	if info, ok := i.routingV6[ipsetName6]; ok && info.VPNType == vpnkind.Xray {
		state.Known = true
		state.V6Applied = routeApplied(info)
	}

	return state
}

func (i *IptablesManager) ListXrayIPSets() []string {
	i.mu.Lock()
	defer i.mu.Unlock()

	list := make([]string, 0)
	for ipsetName, info := range i.routingV4 {
		if info.VPNType == vpnkind.Xray {
			list = append(list, ipsetName)
		}
	}
	sort.Strings(list)
	return list
}

func (i *IptablesManager) RemoveXrayChain(chain string) error {
	ipsetName, err := IpsetName(vpnkind.Xray.String(), chain)
	if err != nil {
		return err
	}
	if !i.XrayState(ipsetName).Known {
		return nil
	}
	return i.RemoveRules(ipsetName)
}

func (i *IptablesManager) ResetXrayFamilies(resetV4, resetV6 bool) {
	if !resetV4 && !resetV6 {
		return
	}
	for _, ipsetName := range i.ListXrayIPSets() {
		if resetV4 {
			_ = i.RemoveRulesV4(ipsetName)
		}
		if resetV6 {
			_ = i.RemoveRulesV6(ipsetName)
		}
	}
	i.mu.Lock()
	i.resetDefaultLocked("", resetV4, resetV6)
	i.ensureDefaultLocked()
	i.mu.Unlock()
}

func (i *IptablesManager) RemoveAllXrayRoutes() {
	for _, ipsetName := range i.ListXrayIPSets() {
		_ = i.RemoveRules(ipsetName)
	}
}

func (i *IptablesManager) PrepareXrayChain(chain string, port int, ifaces []string) (ChainSpec, XrayRouteState, error) {
	if port == 0 {
		return ChainSpec{}, XrayRouteState{}, fmt.Errorf("missing inbound port for chain %s", chain)
	}

	ipsetName, err := IpsetName(vpnkind.Xray.String(), chain)
	if err != nil {
		return ChainSpec{}, XrayRouteState{}, err
	}
	if err := ensureManagedIPSet(ipsetName, false, i.entryTimeout); err != nil {
		return ChainSpec{}, XrayRouteState{}, err
	}
	if i.ipv6Enabled {
		ipsetName6, err := IpsetName6FromBase(ipsetName)
		if err != nil {
			return ChainSpec{}, XrayRouteState{}, err
		}
		if err := ensureManagedIPSet(ipsetName6, true, i.entryTimeout); err != nil {
			return ChainSpec{}, XrayRouteState{}, err
		}
	}

	spec := ChainSpec{IPSetName: ipsetName, Port: port, Ifaces: append([]string(nil), ifaces...)}

	i.mu.Lock()
	defer i.mu.Unlock()

	state := i.xrayStateLocked(ipsetName)
	i.registerXrayEntryLocked(ipsetName, port, spec.Ifaces)
	return spec, state, nil
}

func ensureManagedIPSet(ipsetName string, ipv6 bool, entryTimeout int) error {
	if IPSetExists(ipsetName) {
		return nil
	}
	family := "inet"
	if ipv6 {
		family = "inet6"
	}
	if _, err := EnsureIPSet(ipsetName, family, entryTimeout); err != nil {
		return fmt.Errorf("ensure ipset %s: %w", ipsetName, err)
	}
	return nil
}

func (i *IptablesManager) registerXrayEntryLocked(ipsetName string, port int, ifaces []string) {
	i.registerXrayFamilyLocked(i.routingV4, ipsetName, port, ifaces)
	if !i.ipv6Enabled {
		return
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return
	}
	i.registerXrayFamilyLocked(i.routingV6, ipsetName6, port, ifaces)
}

func (i *IptablesManager) registerXrayFamilyLocked(routing map[string]vpnRoutingInfo, ipsetName string, port int, ifaces []string) {
	info := vpnRoutingInfo{
		VPNType:   vpnkind.Xray,
		ChainName: buildChainName(ipsetName),
		Table:     i.XrayTable(),
		Port:      port,
		Ifaces:    append([]string(nil), ifaces...),
	}
	if prev, ok := routing[ipsetName]; ok && prev.VPNType == vpnkind.Xray && prev.Table == info.Table && prev.Port == port && strings.Join(prev.Ifaces, ",") == strings.Join(ifaces, ",") {
		info.JumpRules = prev.JumpRules
	}
	routing[ipsetName] = info
}

func (i *IptablesManager) ResetAfterFlush(table string, resetV4, resetV6 bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.resetJumpState(table, resetV4, resetV6)
	i.resetDefaultLocked(table, resetV4, resetV6)
}

func (i *IptablesManager) resetJumpState(table string, resetV4, resetV6 bool) {
	clearJumps := func(routing map[string]vpnRoutingInfo) {
		for key, info := range routing {
			if table != "" && info.Table != table {
				continue
			}
			info.JumpRules = nil
			routing[key] = info
		}
	}

	if resetV4 {
		clearJumps(i.routingV4)
	}
	if resetV6 {
		clearJumps(i.routingV6)
	}
}
