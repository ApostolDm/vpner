package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const chainInput = "INPUT"

func kernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func loadKernelModule(path string) error {
	out, err := exec.Command("insmod", path).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "File exists") {
			return nil
		}
		if msg != "" {
			return fmt.Errorf("%s (%s)", msg, err)
		}
		return err
	}
	return nil
}

func EnsureTProxySupport(ipv6Enabled bool) error {
	release := kernelRelease()
	if release == "" {
		return fmt.Errorf("failed to determine kernel release (uname -r)")
	}
	for _, mod := range []string{"xt_TPROXY", "xt_socket"} {
		path := fmt.Sprintf("/lib/modules/%s/%s.ko", release, mod)
		if err := loadKernelModule(path); err != nil {
			return fmt.Errorf("module %s: %w", mod, err)
		}
	}

	if err := probeTProxyUserspace(familyV4); err != nil {
		return fmt.Errorf("ipv4 tproxy probe: %w", err)
	}
	if ipv6Enabled {
		if !commandExists(familyV6.iptablesCmd) {
			return fmt.Errorf("ipv6 enabled but %s not found", familyV6.iptablesCmd)
		}
		if err := probeTProxyUserspace(familyV6); err != nil {
			return fmt.Errorf("ipv6 tproxy probe: %w", err)
		}
	}
	if err := probeTransparentBind(ipv6Enabled); err != nil {
		return fmt.Errorf("transparent socket bind probe failed: %w", err)
	}
	return nil
}

const tproxyProbeChain = "VPN_TPROXY_PROBE"

func probeTProxyUserspace(f ipFamily) error {
	tryRun(f.iptablesCmd, "-t", tableMangle, "-F", tproxyProbeChain)
	tryRun(f.iptablesCmd, "-t", tableMangle, "-X", tproxyProbeChain)

	if err := run(f.iptablesCmd, "-t", tableMangle, "-N", tproxyProbeChain); err != nil {
		return fmt.Errorf("create probe chain: %w", err)
	}
	defer func() {
		tryRun(f.iptablesCmd, "-t", tableMangle, "-F", tproxyProbeChain)
		tryRun(f.iptablesCmd, "-t", tableMangle, "-X", tproxyProbeChain)
	}()

	if err := run(f.iptablesCmd, "-t", tableMangle, "-A", tproxyProbeChain,
		"-p", "tcp", "-m", "socket", "--transparent", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("xt_socket --transparent not supported by iptables/kernel: %w", err)
	}

	if err := run(f.iptablesCmd, "-t", tableMangle, "-A", tproxyProbeChain,
		"-p", "tcp", "-j", "TPROXY", "--on-port", "1", "--tproxy-mark", tproxyMark); err != nil {
		return fmt.Errorf("xt_TPROXY tcp target not supported: %w", err)
	}

	if err := run(f.iptablesCmd, "-t", tableMangle, "-A", tproxyProbeChain,
		"-p", "udp", "-j", "TPROXY", "--on-port", "1", "--tproxy-mark", tproxyMark); err != nil {
		return fmt.Errorf("xt_TPROXY udp target not supported: %w", err)
	}
	return nil
}

func (i *IptablesManager) ensureTProxyLocalRouting(f ipFamily) {
	if i.ipInfraReady {
		return
	}

	tbl := fmt.Sprintf("%d", tproxyTableID)
	if !ipRuleExists(f, tproxyMark, tbl) {
		addRule := append(f.ipFlags, "rule", "add", "fwmark", tproxyMark, "lookup", tbl)
		tryRun("ip", addRule...)
	}
	routeArgs := append(f.ipFlags, "route", "replace", "local", "default", "dev", "lo", "table", tbl)
	tryRun("ip", routeArgs...)
	i.ipInfraReady = true
}

func (i *IptablesManager) ensureMangleInputBypass(f ipFamily) error {
	existing := listChainRules(f.iptablesCmd, tableMangle, chainInput)

	if existing[inputBypassRuleSpec()] || existing[inputBypassRuleSpecHex()] {
		return nil
	}
	insert := []string{"-t", tableMangle, "-I", chainInput, "1",
		"-m", "mark", "--mark", tproxyMark, "-j", "ACCEPT"}
	return run(f.iptablesCmd, insert...)
}

func (i *IptablesManager) cleanupMangleInputBypass(f ipFamily) {
	args := []string{"-t", tableMangle, "-D", chainInput,
		"-m", "mark", "--mark", tproxyMark, "-j", "ACCEPT"}
	for run(f.iptablesCmd, args...) == nil {
	}
}

func (i *IptablesManager) cleanupLegacyTProxySocketRule(f ipFamily) {
	tryRun(f.iptablesCmd, "-t", tableMangle, "-D", chainPrerouting,
		"-p", "tcp", "-m", "socket", "-j", chainDivert)
}

func tproxySocketRuleSpec() string {
	return fmt.Sprintf("-A %s -p tcp -m socket --transparent -j %s", chainPrerouting, chainDivert)
}

func inputBypassRuleSpec() string {
	return fmt.Sprintf("-A %s -m mark --mark %s -j ACCEPT", chainInput, tproxyMark)
}

func inputBypassRuleSpecHex() string {
	mark, _ := strconv.Atoi(tproxyMark)
	return fmt.Sprintf("-A %s -m mark --mark 0x%x -j ACCEPT", chainInput, mark)
}

func addTProxyProtocolRules(b *iptablesBatch, chainName, iface, ipsetName string, port int) {
	for _, proto := range []string{"tcp", "udp"} {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -p %s -m set --match-set %s dst -j TPROXY --on-port %d --tproxy-mark %s",
			chainName, iface, proto, ipsetName, port, tproxyMark,
		))
	}
}

func addTProxyRules(f ipFamily, chainName, ipsetName string, port int, iface string) error {
	b := newBatch(f.iptablesCmd, tableMangle)
	b.Add(fmt.Sprintf("-A %s -m mark --mark %s -j RETURN", chainName, tproxyMark))
	addReturnCIDRs(b, chainName, iface, f.localExceptions)
	addTProxyProtocolRules(b, chainName, iface, ipsetName, port)
	return b.Commit()
}

func ipRuleExists(f ipFamily, fwmark, table string) bool {
	args := append(f.ipFlags, "rule", "show")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		return false
	}

	var fwmarkInt int
	fmt.Sscanf(fwmark, "%d", &fwmarkInt)
	fwmarkHex := fmt.Sprintf("0x%x", fwmarkInt)

	for _, line := range strings.Split(string(out), "\n") {
		hasMark := strings.Contains(line, "fwmark "+fwmark) || strings.Contains(line, "fwmark "+fwmarkHex)
		if hasMark && strings.Contains(line, "lookup "+table) {
			return true
		}
	}
	return false
}

func (i *IptablesManager) cleanupTProxyIPRule(f ipFamily) {
	tbl := fmt.Sprintf("%d", tproxyTableID)
	delArgs := append(f.ipFlags, "rule", "del", "fwmark", tproxyMark, "lookup", tbl)
	for ipRuleExists(f, tproxyMark, tbl) {
		tryRun("ip", delArgs...)
	}
	flushArgs := append(f.ipFlags, "route", "flush", "table", tbl)
	tryRun("ip", flushArgs...)
}

func (i *IptablesManager) cleanupTProxyInfraForFamily(f ipFamily) {
	i.cleanupMangleInputBypass(f)
	tryRun(f.iptablesCmd, "-t", tableMangle, "-D", chainPrerouting,
		"-p", "tcp", "-m", "socket", "--transparent", "-j", chainDivert)
	i.cleanupLegacyTProxySocketRule(f)
	tryRun(f.iptablesCmd, "-t", tableMangle, "-F", chainDivert)
	tryRun(f.iptablesCmd, "-t", tableMangle, "-X", chainDivert)
	i.cleanupTProxyIPRule(f)
}

func (i *IptablesManager) TProxyEnabled() bool {
	return i.tproxyEnabled
}

func (i *IptablesManager) Shutdown() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.tproxyEnabled {
		i.cleanupTProxyInfraForFamily(familyV4)
		if i.ipv6Enabled {
			i.cleanupTProxyInfraForFamily(familyV6)
		}
		i.ipInfraReady = false
	}
}
