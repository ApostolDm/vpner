package network

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logging"
)

func (i *IptablesManager) cleanupFamily(f ipFamily) {
	i.cleanupOldChainsInTable(f, tableNat)
	i.cleanupOldChainsInTable(f, tableMangle)
	i.cleanupOldIPRulesAndRoutes(f)
	i.cleanupTProxyIPRule(f)
}

func (i *IptablesManager) cleanupOldIPRulesAndRoutes(f ipFamily) {
	args := append(f.ipFlags, "rule")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		logging.Warnf("failed to list ip rules: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "fwmark") || !strings.Contains(line, "lookup") {
			continue
		}
		parts := strings.Fields(line)
		var fwmark, tableID int
		for idx, p := range parts {
			if p == "fwmark" && idx+1 < len(parts) {
				fmt.Sscanf(parts[idx+1], "%d", &fwmark)
			}
			if p == "lookup" && idx+1 < len(parts) {
				fmt.Sscanf(parts[idx+1], "%d", &tableID)
			}
		}
		if fwmark == tableID && fwmark >= 100 && fwmark <= 0xFFF+100 {
			logging.Infof("cleanup ip rule fwmark=%d table=%d", fwmark, tableID)
			delArgs := append(f.ipFlags, "rule", "del", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID))
			_ = run("ip", delArgs...)
			logging.Infof("flush route table %d", tableID)
			flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", tableID))
			_ = run("ip", flushArgs...)
		}
	}
}

func (i *IptablesManager) cleanupOldChainsInTable(f ipFamily, table string) {
	out, err := exec.Command(f.iptablesSaveCmd, "-t", table).Output()
	if err != nil {
		logging.Warnf("failed to run %s -t %s: %v", f.iptablesSaveCmd, table, err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var chains []string
	var jumps []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ":VPN_") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				chain := strings.TrimPrefix(parts[0], ":")
				chains = append(chains, chain)
			}
		}
		if strings.HasPrefix(line, "-A PREROUTING") && strings.Contains(line, "-j VPN_") {
			jumps = append(jumps, line)
		}
	}

	for _, rule := range jumps {
		delRule := strings.Replace(rule, "-A", "-D", 1)
		args := append([]string{"-t", table}, strings.Fields(delRule)...)
		logging.Infof(
			"cleanup %s PREROUTING jump: %s %s",
			table,
			f.iptablesCmd,
			strings.Join(args, " "),
		)
		_ = run(f.iptablesCmd, args...)
	}

	for _, chain := range chains {
		logging.Infof("cleaning old %s chain: %s", table, chain)
		_ = run(f.iptablesCmd, "-t", table, "-F", chain)
		_ = run(f.iptablesCmd, "-t", table, "-X", chain)
	}
}
