package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
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

// EnsureTProxySupport loads required kernel modules (xt_TPROXY, xt_socket)
// and verifies that the userspace tooling accepts the rule shapes our TPROXY
// recipe needs. Returns nil only if all probes pass.
//
// Note: this catches missing modules, old iptables that don't know
// `--transparent`, and kernels without IP_TRANSPARENT. It does NOT catch
// runtime regressions in dst handling — those pass the probe but may still
// drop traffic mid-flight; force `enable-tproxy: false` on such firmware.
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
	if err := probeTProxyUserspace(); err != nil {
		return err
	}
	return nil
}

const tproxyProbeChain = "VPN_TPROXY_PROBE"

func probeTProxyUserspace() error {
	_ = run("iptables", "-t", tableMangle, "-F", tproxyProbeChain)
	_ = run("iptables", "-t", tableMangle, "-X", tproxyProbeChain)

	if err := run("iptables", "-t", tableMangle, "-N", tproxyProbeChain); err != nil {
		return fmt.Errorf("create probe chain: %w", err)
	}
	defer func() {
		_ = run("iptables", "-t", tableMangle, "-F", tproxyProbeChain)
		_ = run("iptables", "-t", tableMangle, "-X", tproxyProbeChain)
	}()

	if err := run("iptables", "-t", tableMangle, "-A", tproxyProbeChain,
		"-p", "tcp", "-m", "socket", "--transparent", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("xt_socket --transparent not supported by iptables/kernel: %w", err)
	}

	if err := run("iptables", "-t", tableMangle, "-A", tproxyProbeChain,
		"-p", "tcp", "-j", "TPROXY", "--on-port", "1", "--tproxy-mark", tproxyMark); err != nil {
		return fmt.Errorf("xt_TPROXY target not supported: %w", err)
	}

	if err := probeTransparentBind(); err != nil {
		return fmt.Errorf("IP_TRANSPARENT socket bind not supported: %w", err)
	}
	return nil
}

func probeTransparentBind() error {
	cfg := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			ctlErr := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			})
			if ctlErr != nil {
				return ctlErr
			}
			return sockErr
		},
	}
	ln, err := cfg.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return ln.Close()
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

	socketRule := fmt.Sprintf("-A %s -p tcp -m socket --transparent -j %s", chainPrerouting, chainDivert)
	if !listPreroutingRules(f.iptablesCmd, tableMangle)[socketRule] {
		b := newBatch(f.iptablesCmd, tableMangle)
		b.Add(fmt.Sprintf(":%s - [0:0]", chainDivert))
		b.Add(fmt.Sprintf("-A %s -j MARK --set-mark %s", chainDivert, tproxyMark))
		b.Add(fmt.Sprintf("-A %s -j ACCEPT", chainDivert))
		b.Add(fmt.Sprintf("-A %s -p tcp -m socket --transparent -j %s", chainPrerouting, chainDivert))
		if err := b.Commit(); err != nil {
			return err
		}
	}

	if err := i.ensureMangleInputBypass(f); err != nil {
		return fmt.Errorf("mangle INPUT bypass: %w", err)
	}

	i.ensureTProxyLocalRouting(f)
	i.tproxyInfraReady = true
	return nil
}

// ensureMangleInputBypass inserts a high-priority ACCEPT in mangle INPUT for
// packets carrying our tproxy fwmark. Vendor firmware (e.g. Keenetic NDM)
// can hook a TLS-SNI DROP filter on dport 443 in mangle INPUT — TPROXY
// preserves the original port, so without this bypass every hijacked HTTPS
// connection would be dropped before reaching the local xray socket. The
// ACCEPT terminates only mangle-INPUT processing; the packet still traverses
// filter INPUT, which is where local delivery is normally accepted.
func (i *IptablesManager) ensureMangleInputBypass(f ipFamily) error {
	check := []string{"-t", tableMangle, "-C", chainInput,
		"-m", "mark", "--mark", tproxyMark, "-j", "ACCEPT"}
	if run(f.iptablesCmd, check...) == nil {
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
	i.cleanupMangleInputBypass(f)
	_ = run(f.iptablesCmd, "-t", tableMangle, "-D", chainPrerouting,
		"-p", "tcp", "-m", "socket", "--transparent", "-j", chainDivert)
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
