package network

import (
	"fmt"
	"log"
	"os/exec"
)

type VPNType string

const (
	OpenVPN     VPNType = "OpenVPN"
	Wireguard   VPNType = "Wireguard"
	IKE         VPNType = "IKE"
	SSTP        VPNType = "SSTP"
	PPPOE       VPNType = "PPPOE"
	L2TP        VPNType = "L2TP"
	PPTP        VPNType = "PPTP"
	Shadowsocks VPNType = "Shadowsocks"
)

const (
	tableMangle    = "mangle"
	tableNat       = "nat"
	chainPrerouting = "PREROUTING"
	chainOutput     = "OUTPUT"
)

var localExceptions = []string{"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

func generateChainName(vpnType VPNType, uniqueID string) string {
	return fmt.Sprintf("CHAIN_%s_%s", vpnType, uniqueID)
}

func generateMark(vpnType VPNType, uniqueID string) string {
	return fmt.Sprintf("0x%s", uniqueID)
}

func generateRoutingTable(vpnType VPNType, uniqueID string) string {
	return fmt.Sprintf("vpn-%s-%s", vpnType, uniqueID)
}

func AddRules(vpnType VPNType, interfaceName, setName, uniqueID string, shadowsocksPort int, shadowsocksServerIP string) error {
	mark := generateMark(vpnType, uniqueID)
	routeTable := generateRoutingTable(vpnType, uniqueID)
	chainName := generateChainName(vpnType, uniqueID)

	if err := removeOldRules(vpnType, setName, uniqueID); err != nil {
		return err
	}

	if vpnType == Shadowsocks {
		return addRedirectRules(setName, shadowsocksPort, "br0")
	}

	if err := addMarkingRules(setName, mark); err != nil {
		return err
	}

	if err := addRoutingRules(routeTable, mark, interfaceName); err != nil {
		return err
	}

	return addLocalExceptions(chainName)
}

func RemoveRules(vpnType VPNType, setName, uniqueID string, shadowsocksServerIP string) error {
	mark := generateMark(vpnType, uniqueID)
	routeTable := generateRoutingTable(vpnType, uniqueID)
	chainName := generateChainName(vpnType, uniqueID)

	if vpnType == Shadowsocks {
		return removeRedirectRules(setName, "br0")
	}

	if err := removeRoutingRules(routeTable, mark); err != nil {
		return err
	}

	if err := removeMarkingRules(setName, mark); err != nil {
		return err
	}

	return removeLocalExceptions(chainName)
}

func addMarkingRules(setName, mark string) error {
	rules := []struct {
		table string
		chain string
		rule  string
	}{
		{tableMangle, chainPrerouting, fmt.Sprintf("-m set --match-set %s src -j MARK --set-mark %s", setName, mark)},
		{tableMangle, chainOutput,     fmt.Sprintf("-m set --match-set %s dst -j MARK --set-mark %s", setName, mark)},
	}

	for _, r := range rules {
		if err := executeIptablesCommand(r.table, r.chain, r.rule); err != nil {
			return err
		}
	}
	return nil
}

func removeMarkingRules(setName, mark string) error {
	rules := []struct {
		table string
		chain string
		rule  string
	}{
		{tableMangle, chainPrerouting, fmt.Sprintf("-m set --match-set %s src -j MARK --set-mark %s", setName, mark)},
		{tableMangle, chainOutput,     fmt.Sprintf("-m set --match-set %s dst -j MARK --set-mark %s", setName, mark)},
	}

	for _, r := range rules {
		if err := deleteIptablesCommand(r.table, r.chain, r.rule); err != nil {
			return err
		}
	}
	return nil
}

func addRoutingRules(routeTable, mark, interfaceName string) error {
	cmds := []string{
		fmt.Sprintf("ip rule add fwmark %s table %s", mark, routeTable),
		fmt.Sprintf("ip route add default dev %s table %s", interfaceName, routeTable),
	}
	return executeCommands(cmds)
}

func removeRoutingRules(routeTable, mark string) error {
	cmds := []string{
		fmt.Sprintf("ip rule del fwmark %s table %s", mark, routeTable),
	}
	return executeCommands(cmds)
}

func addRedirectRules(setName string, port int, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, setName, port),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, setName, port),
	}
	return applyIptablesRules(tableNat, chainPrerouting, rules, true)
}

func removeRedirectRules(setName, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT", iface, setName),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT", iface, setName),
	}
	return applyIptablesRules(tableNat, chainPrerouting, rules, false)
}

func addLocalExceptions(chainName string) error {
	rules := make([]string, len(localExceptions))
	for i, ip := range localExceptions {
		rules[i] = fmt.Sprintf("-d %s -j RETURN", ip)
	}
	return applyIptablesRules(tableMangle, chainName, rules, true)
}

func removeLocalExceptions(chainName string) error {
	rules := make([]string, len(localExceptions))
	for i, ip := range localExceptions {
		rules[i] = fmt.Sprintf("-d %s -j RETURN", ip)
	}
	return applyIptablesRules(tableMangle, chainName, rules, false)
}

func removeOldRules(vpnType VPNType, setName, uniqueID string) error {
	mark := generateMark(vpnType, uniqueID)
	routeTable := generateRoutingTable(vpnType, uniqueID)
	return removeRoutingRules(routeTable, mark)
}

func executeCommands(commands []string) error {
	for _, cmd := range commands {
		log.Printf("Processing command: %s", cmd)
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return fmt.Errorf("ошибка при выполнении команды %s: %v", cmd, err)
		}
	}
	return nil
}

func executeCommand(cmd string) error {
	log.Printf("Processing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		return fmt.Errorf("ошибка при выполнении команды %s: %v", cmd, err)
	}
	return nil
}

func ruleExists(cmd string) (bool, error) {
	checkCmd := fmt.Sprintf("iptables-save | grep -q -- '%s'", cmd)
	err := exec.Command("sh", "-c", checkCmd).Run()
	if err == nil {
		return true, nil
	}
	if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("ошибка при проверке правила: %v", err)
}

func executeIptablesCommand(table, chain, rule string) error {
	cmd := fmt.Sprintf("iptables -t %s -A %s %s", table, chain, rule)
	exists, err := ruleExists(cmd)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return executeCommand(cmd)
}

func deleteIptablesCommand(table, chain, rule string) error {
	cmd := fmt.Sprintf("iptables -t %s -D %s %s", table, chain, rule)
	exists, err := ruleExists(cmd)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return executeCommand(cmd)
}

func applyIptablesRules(table, chain string, rules []string, append bool) error {
	for _, rule := range rules {
		var cmd string
		if append {
			cmd = fmt.Sprintf("iptables -t %s -A %s %s", table, chain, rule)
		} else {
			cmd = fmt.Sprintf("iptables -t %s -D %s %s", table, chain, rule)
		}
		exists, err := ruleExists(cmd)
		if err != nil {
			return err
		}
		if append && exists {
			continue
		}
		if !append && !exists {
			continue
		}
		if err := executeCommand(cmd); err != nil {
			return err
		}
	}
	return nil
}
