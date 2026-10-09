package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

func (i *IptablesManager) cleanupFamily(f ipFamily) {
	i.cleanupOldChainsInTable(f, tableNat)
	i.cleanupOldChainsInTable(f, tableMangle)
	i.cleanupOldIPRulesAndRoutes(f)
	i.cleanupTProxyIPRule(f)
	i.cleanupMangleInputBypass(f)
}

func (i *IptablesManager) cleanupOldIPRulesAndRoutes(f ipFamily) {
	args := append(f.ipFlags, "rule")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		logx.Warnf("failed to list ip rules: %v", err)
		return
	}

	seen := make(map[int]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fwmark, tableID, ok := parseFwmarkRule(scanner.Text())
		if !ok || fwmark != tableID || fwmark < 100 || fwmark > 0xFFF+100 || seen[fwmark] {
			continue
		}
		seen[fwmark] = true
		logx.Infof("cleanup ip rule fwmark=%d table=%d", fwmark, tableID)
		deleteIPRule(f, fwmark, tableID)
		logx.Infof("flush route table %d", tableID)
		flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", tableID))
		tryRun("ip", flushArgs...)
	}
}

func parseFwmarkRule(line string) (fwmark, tableID int, ok bool) {
	parts := strings.Fields(line)
	for idx, p := range parts {
		if idx+1 >= len(parts) {
			break
		}
		switch p {
		case "fwmark":
			value, _, _ := strings.Cut(parts[idx+1], "/")
			n, err := strconv.ParseInt(value, 0, 32)
			if err != nil {
				return 0, 0, false
			}
			fwmark = int(n)
		case "lookup", "table":
			n, err := strconv.Atoi(parts[idx+1])
			if err != nil {
				return 0, 0, false
			}
			tableID = int(n)
		}
	}
	return fwmark, tableID, fwmark != 0 && tableID != 0
}

func deleteIPRule(f ipFamily, mark, tableID int) {
	markStr, tableStr := fmt.Sprintf("%d", mark), fmt.Sprintf("%d", tableID)
	delArgs := append(f.ipFlags, "rule", "del", "fwmark", markStr, "table", tableStr)
	for attempt := 0; attempt < 32 && ipRuleExists(f, markStr, tableStr); attempt++ {
		if err := run("ip", delArgs...); err != nil {
			logx.Debugf("network: ip rule del: %v", err)
			return
		}
	}
}

func (i *IptablesManager) cleanupOldChainsInTable(f ipFamily, table string) {
	out, err := exec.Command(f.iptablesSaveCmd, "-t", table).Output()
	if err != nil {
		logx.Warnf("failed to run %s -t %s: %v", f.iptablesSaveCmd, table, err)
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
		logx.Infof(
			"cleanup %s PREROUTING jump: %s %s",
			table,
			f.iptablesCmd,
			strings.Join(args, " "),
		)
		tryRun(f.iptablesCmd, args...)
	}

	for _, chain := range chains {
		logx.Infof("cleaning old %s chain: %s", table, chain)
		tryRun(f.iptablesCmd, "-t", table, "-F", chain)
		tryRun(f.iptablesCmd, "-t", table, "-X", chain)
	}
}
