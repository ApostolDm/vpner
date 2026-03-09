package network

import (
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/logging"
	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
)

func (i *IptablesManager) AddRules(vpnType vpntypes.Type, ipsetName string, param int, iface, vpnIface string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.addRulesForFamily(familyV4, i.routingV4, vpnType, ipsetName, param, iface, vpnIface); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.addRulesForFamily(familyV6, i.routingV6, vpnType, ipsetName6, param, iface, vpnIface)
}

func (i *IptablesManager) RemoveRules(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.removeRulesForFamily(familyV4, i.routingV4, ipsetName); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.removeRulesForFamily(familyV6, i.routingV6, ipsetName6)
}

func (i *IptablesManager) RemoveRulesV4(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.removeRulesForFamily(familyV4, i.routingV4, ipsetName)
}

func (i *IptablesManager) RemoveRulesV6(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.ipv6Enabled {
		return nil
	}

	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.removeRulesForFamily(familyV6, i.routingV6, ipsetName6)
}

func (i *IptablesManager) addRulesForFamily(f ipFamily, routing map[string]vpnRoutingInfo, vpnType vpntypes.Type, ipsetName string, param int, iface, vpnIface string) error {
	logging.Infof("add routing ipset=%s vpn=%s iface=%s", ipsetName, vpnType, iface)

	if !isSupportedVPNType(vpnType) {
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
	if vpnType == vpntypes.Xray {
		return fmt.Errorf("xray routing must use PrepareXrayChain and batch apply")
	}
	if err := validateIface(iface); err != nil {
		return err
	}
	if err := validateIface(vpnIface); err != nil {
		return err
	}

	chainName := buildChainName(ipsetName)

	switch vpnType {
	case vpntypes.OpenVPN, vpntypes.Wireguard, vpntypes.IKE, vpntypes.SSTP, vpntypes.PPPOE, vpntypes.L2TP, vpntypes.PPTP:
		if err := ensureChain(f.iptablesCmd, tableMangle, chainName); err != nil {
			return err
		}
		jmp, err := linkChain(f.iptablesCmd, tableMangle, chainName, iface)
		if err != nil {
			return err
		}
		mark, tableID := markAndTableFromIPSet(ipsetName)
		if err := addMarkRules(f, chainName, ipsetName, mark, iface); err != nil {
			return err
		}
		if err := addIPRule(f, mark, tableID); err != nil {
			return err
		}
		if err := addIPRoute(f, tableID, vpnIface); err != nil {
			return err
		}
		routing[ipsetName] = vpnRoutingInfo{
			VPNType:   vpnType,
			Mark:      mark,
			TableID:   tableID,
			Dev:       vpnIface,
			ChainName: chainName,
			Table:     tableMangle,
			Ifaces:    []string{iface},
			JumpRules: []jumpRule{jmp},
		}
		return nil
	default:
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

func (i *IptablesManager) removeRulesForFamily(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName string) error {
	info, ok := routing[ipsetName]
	if !ok {
		if f.iptablesCmd == familyV4.iptablesCmd {
			return fmt.Errorf("no routing info found for ipset: %s", ipsetName)
		}
		return nil
	}

	for _, jmp := range info.JumpRules {
		_ = run(jmp.Cmd, jmp.deleteArgs()...)
	}

	table := info.Table
	if table == "" {
		table = tableNat
	}
	_ = run(f.iptablesCmd, "-t", table, "-F", info.ChainName)
	_ = run(f.iptablesCmd, "-t", table, "-X", info.ChainName)

	if info.Mark != 0 && info.TableID != 0 {
		delArgs := append(f.ipFlags, "rule", "del", "fwmark", fmt.Sprintf("%d", info.Mark), "table", fmt.Sprintf("%d", info.TableID))
		_ = run("ip", delArgs...)
		flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", info.TableID))
		_ = run("ip", flushArgs...)
	}

	delete(routing, ipsetName)
	return nil
}

func (i *IptablesManager) BatchApplyAllTProxy(specs []ChainSpec) error {
	if !i.tproxyEnabled || len(specs) == 0 {
		return nil
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.batchApplyBothFamilies(specs, i.buildTProxyBatch); err != nil {
		return err
	}
	i.tproxyInfraReady = true
	i.ipInfraReady = true
	return nil
}

func (i *IptablesManager) BatchApplyAllRedirect(specs []ChainSpec) error {
	if i.tproxyEnabled || len(specs) == 0 {
		return nil
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	return i.batchApplyBothFamilies(specs, i.buildRedirectBatch)
}

type batchBuilder func(f ipFamily, routing map[string]vpnRoutingInfo, specs []ChainSpec) error

type xrayChainInit func(b *iptablesBatch, chainName string, spec ChainSpec)

type xrayChainIfaceRules func(b *iptablesBatch, chainName string, spec ChainSpec, iface string)

func (i *IptablesManager) batchApplyBothFamilies(specs []ChainSpec, build batchBuilder) error {
	if err := build(familyV4, i.routingV4, specs); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}

	v6Specs := specsToV6(specs)
	if len(v6Specs) == 0 {
		return nil
	}
	return build(familyV6, i.routingV6, v6Specs)
}

func specsToV6(specs []ChainSpec) []ChainSpec {
	v6 := make([]ChainSpec, 0, len(specs))
	for _, spec := range specs {
		v6Name, err := IpsetName6FromBase(spec.IPSetName)
		if err != nil {
			logging.Warnf("skip v6 batch for %s: %v", spec.IPSetName, err)
			continue
		}
		v6 = append(v6, ChainSpec{IPSetName: v6Name, Port: spec.Port, Ifaces: spec.Ifaces})
	}
	return v6
}

func (i *IptablesManager) applyXrayBatch(f ipFamily, routing map[string]vpnRoutingInfo, specs []ChainSpec) error {
	if i.tproxyEnabled {
		return i.buildTProxyBatch(f, routing, specs)
	}
	return i.buildRedirectBatch(f, routing, specs)
}

func (i *IptablesManager) buildTProxyBatch(f ipFamily, routing map[string]vpnRoutingInfo, specs []ChainSpec) error {
	i.ensureTProxyLocalRouting(f)

	existing := listPreroutingRules(f.iptablesCmd, tableMangle)
	b := newBatch(f.iptablesCmd, tableMangle)

	b.Add(fmt.Sprintf(":%s - [0:0]", chainDivert))
	b.Add(fmt.Sprintf("-A %s -j MARK --set-mark %s", chainDivert, tproxyMark))
	b.Add(fmt.Sprintf("-A %s -j ACCEPT", chainDivert))

	socketRule := fmt.Sprintf("-A %s -p tcp -m socket -j %s", chainPrerouting, chainDivert)
	if !existing[socketRule] {
		b.Add(socketRule)
	}

	buildXrayChains(b, existing, specs,
		func(batch *iptablesBatch, chainName string, _ ChainSpec) {
			batch.Add(fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", chainName, tproxyMark))
		},
		func(batch *iptablesBatch, chainName string, spec ChainSpec, iface string) {
			addReturnCIDRs(batch, chainName, iface, f.localExceptions)
			addTProxyProtocolRules(batch, chainName, iface, spec.IPSetName, spec.Port)
		},
	)

	if err := b.Commit(); err != nil {
		return err
	}
	updateRoutingMap(routing, specs, tableMangle, f.iptablesCmd)
	return nil
}

func (i *IptablesManager) buildRedirectBatch(f ipFamily, routing map[string]vpnRoutingInfo, specs []ChainSpec) error {
	existing := listPreroutingRules(f.iptablesCmd, tableNat)
	b := newBatch(f.iptablesCmd, tableNat)

	buildXrayChains(b, existing, specs, nil,
		func(batch *iptablesBatch, chainName string, spec ChainSpec, iface string) {
			batch.Add(redirectRuleSpec(chainName, iface, spec.IPSetName, spec.Port))
		},
	)

	if err := b.Commit(); err != nil {
		return err
	}
	updateRoutingMap(routing, specs, tableNat, f.iptablesCmd)
	return nil
}

func buildXrayChains(b *iptablesBatch, existing map[string]bool, specs []ChainSpec, initChain xrayChainInit, addIfaceRules xrayChainIfaceRules) {
	for _, spec := range specs {
		chainName := buildChainName(spec.IPSetName)
		b.Add(fmt.Sprintf(":%s - [0:0]", chainName))
		if initChain != nil {
			initChain(b, chainName, spec)
		}

		for _, iface := range spec.Ifaces {
			addJumpRuleIfMissing(b, existing, chainName, iface)
			addIfaceRules(b, chainName, spec, iface)
		}
	}
}

func updateRoutingMap(routing map[string]vpnRoutingInfo, specs []ChainSpec, table, iptablesCmd string) {
	for _, spec := range specs {
		chainName := buildChainName(spec.IPSetName)
		info := vpnRoutingInfo{
			VPNType:   vpntypes.Xray,
			ChainName: chainName,
			Table:     table,
			Port:      spec.Port,
			Ifaces:    spec.Ifaces,
		}
		for _, iface := range spec.Ifaces {
			info.JumpRules = appendJumpRule(info.JumpRules, newJumpRule(iptablesCmd, table, chainName, iface))
		}
		routing[spec.IPSetName] = info
	}
}

func redirectRuleSpec(chainName, iface, ipsetName string, port int) string {
	return fmt.Sprintf(
		"-A %s -i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d",
		chainName,
		iface,
		ipsetName,
		port,
	)
}

func addReturnCIDRs(b *iptablesBatch, chainName, iface string, cidrs []string) {
	for _, cidr := range cidrs {
		b.Add(fmt.Sprintf("-A %s -i %s -d %s -j RETURN", chainName, iface, cidr))
	}
}

func addMarkRules(f ipFamily, chainName, ipsetName string, mark int, iface string) error {
	b := newBatch(f.iptablesCmd, tableMangle)

	addReturnCIDRs(b, chainName, iface, f.localExceptions)

	for _, proto := range []string{"tcp", "udp"} {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -p %s -m set --match-set %s dst -j MARK --set-mark %d",
			chainName, iface, proto, ipsetName, mark,
		))
	}

	return b.Commit()
}

func addIPRule(f ipFamily, mark, tableID int) error {
	args := append(f.ipFlags, "rule", "add", "fwmark", fmt.Sprintf("%d", mark), "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

func addIPRoute(f ipFamily, tableID int, iface string) error {
	args := append(f.ipFlags, "route", "add", "default", "dev", iface, "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

func markAndTableFromIPSet(ipsetName string) (mark int, tableID int) {
	id := int(checksumIPSetName(ipsetName)&0xFFF) + 100
	return id, id
}
