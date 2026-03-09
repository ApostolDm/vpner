package network

import (
	"bufio"
	"fmt"
	"hash/adler32"
	"os/exec"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logging"
)

func ensureChain(iptablesCmd, table, chain string) error {
	logging.Infof("ensure chain %s (table=%s)", chain, table)

	err := run(iptablesCmd, "-t", table, "-N", chain)
	if err != nil {
		if strings.Contains(err.Error(), "exists") || strings.Contains(err.Error(), "File exists") {
			logging.Debugf("chain %s already exists", chain)
			return nil
		}
		return err
	}

	return nil
}

func preroutingJumpSpec(chain, iface string) string {
	return fmt.Sprintf("-A %s -i %s -j %s", chainPrerouting, iface, chain)
}

func newJumpRule(iptablesCmd, table, chain, iface string) jumpRule {
	return jumpRule{
		Cmd:  iptablesCmd,
		Args: []string{"-t", table, "-A", chainPrerouting, "-i", iface, "-j", chain},
	}
}

func addJumpRuleIfMissing(b *iptablesBatch, existing map[string]bool, chainName, iface string) {
	jump := preroutingJumpSpec(chainName, iface)
	if !existing[jump] {
		b.Add(jump)
	}
}

func linkChain(iptablesCmd, table, chain, iface string) (jumpRule, error) {
	logging.Infof(
		"link PREROUTING -> %s (table=%s iface=%s)",
		chain,
		table,
		iface,
	)

	jmp := newJumpRule(iptablesCmd, table, chain, iface)
	needle := preroutingJumpSpec(chain, iface)
	if listPreroutingRules(iptablesCmd, table)[needle] {
		logging.Debugf("PREROUTING jump already exists: %s -i %s -j %s", table, iface, chain)
		return jmp, nil
	}

	if err := run(iptablesCmd, jmp.Args...); err != nil {
		if strings.Contains(err.Error(), "exists") {
			return jmp, nil
		}
		return jmp, err
	}

	return jmp, nil
}

func checksumIPSetName(ipsetName string) uint32 {
	return adler32.Checksum([]byte(ipsetName))
}

func buildChainName(ipsetName string) string {
	return fmt.Sprintf("VPN_%08x", checksumIPSetName(ipsetName))
}

func appendJumpRule(rules []jumpRule, rule jumpRule) []jumpRule {
	for _, existing := range rules {
		if existing.Cmd == rule.Cmd && strings.Join(existing.Args, " ") == strings.Join(rule.Args, " ") {
			return rules
		}
	}
	return append(rules, rule)
}

func listPreroutingRules(iptablesCmd, table string) map[string]bool {
	out, err := exec.Command(iptablesSaveCmd(iptablesCmd), "-t", table).Output()
	if err != nil {
		return nil
	}

	result := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-A "+chainPrerouting) {
			result[line] = true
		}
	}
	return result
}

func iptablesSaveCmd(iptablesCmd string) string {
	if iptablesCmd == "ip6tables" {
		return "ip6tables-save"
	}
	return "iptables-save"
}
