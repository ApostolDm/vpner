package network

import (
	"fmt"
	"os/exec"
	"strings"
)

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

// EnsureTProxySupport loads required kernel modules (xt_TPROXY, xt_socket).
func EnsureTProxySupport() error {
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
	return nil
}

func (i *IptablesManager) ensureTProxyLocalRouting(f ipFamily) {
	if i.ipInfraReady {
		return
	}

	tbl := fmt.Sprintf("%d", tproxyTableID)
	if !ipRuleExists(f, tproxyMark, tbl) {
		addRule := append(f.ipFlags, "rule", "add", "fwmark", tproxyMark, "lookup", tbl)
		_ = run("ip", addRule...)
	}
	routeArgs := append(f.ipFlags, "route", "replace", "local", "default", "dev", "lo", "table", tbl)
	_ = run("ip", routeArgs...)
	i.ipInfraReady = true
}

func (i *IptablesManager) ensureTProxyInfra(f ipFamily) error {
	if i.tproxyInfraReady {
		return nil
	}

	socketRule := fmt.Sprintf("-A %s -p tcp -m socket -j %s", chainPrerouting, chainDivert)
	if !listPreroutingRules(f.iptablesCmd, tableMangle)[socketRule] {
		b := newBatch(f.iptablesCmd, tableMangle)
		b.Add(fmt.Sprintf(":%s - [0:0]", chainDivert))
		b.Add(fmt.Sprintf("-A %s -j MARK --set-mark %s", chainDivert, tproxyMark))
		b.Add(fmt.Sprintf("-A %s -j ACCEPT", chainDivert))
		b.Add(fmt.Sprintf("-A %s -p tcp -m socket -j %s", chainPrerouting, chainDivert))
		if err := b.Commit(); err != nil {
			return err
		}
	}

	i.ensureTProxyLocalRouting(f)
	i.tproxyInfraReady = true
	return nil
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
		_ = run("ip", delArgs...)
	}
	flushArgs := append(f.ipFlags, "route", "flush", "table", tbl)
	_ = run("ip", flushArgs...)
}

func (i *IptablesManager) cleanupTProxyInfraForFamily(f ipFamily) {
	_ = run(f.iptablesCmd, "-t", tableMangle, "-D", chainPrerouting, "-p", "tcp", "-m", "socket", "-j", chainDivert)
	_ = run(f.iptablesCmd, "-t", tableMangle, "-F", chainDivert)
	_ = run(f.iptablesCmd, "-t", tableMangle, "-X", chainDivert)
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
