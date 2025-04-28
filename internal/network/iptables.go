package network

import (
	"bufio"
	"fmt"
	"hash/adler32"
	"log"
	"os/exec"
	"strings"
)

type vpnRoutingInfo struct {
	Mark    int
	TableID int
	Dev     string
}

type IptablesManager struct {
	addedRules map[string]struct{}
	routing    map[string]vpnRoutingInfo
}

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

var validVPNTypes = map[VPNType]struct{}{
	OpenVPN:     {},
	Wireguard:   {},
	IKE:         {},
	SSTP:        {},
	PPPOE:       {},
	L2TP:        {},
	PPTP:        {},
	Shadowsocks: {},
}

const (
	tableMangle     = "mangle"
	tableNat        = "nat"
	chainPrerouting = "PREROUTING"
	chainOutput     = "OUTPUT"
)

var localExceptions = [...]string{
	"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

func NewIptablesManager() *IptablesManager {
	return &IptablesManager{
		addedRules: make(map[string]struct{}),
		routing:    make(map[string]vpnRoutingInfo),
	}
}

func (v VPNType) IsValid() bool {
	_, ok := validVPNTypes[v]
	return ok
}

func (i *IptablesManager) AddRules(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if !vpnType.IsValid() {
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}

	switch vpnType {
	case Shadowsocks:
		return i.addRedirectRules(ipsetName, param, iface)
	case OpenVPN, Wireguard, IKE, SSTP, PPPOE, L2TP, PPTP:
		mark, tableID := i.markAndTableFromIPSet(ipsetName)
		if err := i.addMarkRules(ipsetName, mark, iface); err != nil {
			return err
		}
		if err := i.addIPRule(mark, tableID); err != nil {
			return err
		}
		if err := i.addIPRoute(tableID, vpnIface); err != nil {
			return err
		}
		i.routing[ipsetName] = vpnRoutingInfo{Mark: mark, TableID: tableID, Dev: vpnIface}
		return nil
	default:
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

func (i *IptablesManager) RemoveRules(ipsetName string) error {
	info, ok := i.routing[ipsetName]
	if !ok {
		return fmt.Errorf("no routing info found for ipset: %s", ipsetName)
	}

	var rulesToDelete []string
	for cmd := range i.addedRules {
		if strings.Contains(cmd, fmt.Sprintf("--match-set %s", ipsetName)) {
			rule := i.extractRule(cmd)
			rulesToDelete = append(rulesToDelete, rule)
		}
	}

	_ = i.applyIptablesRules(tableMangle, chainPrerouting, rulesToDelete, false)
	_ = i.applyIptablesRules(tableNat, chainPrerouting, rulesToDelete, false)

	delRuleCmd := fmt.Sprintf("ip rule del fwmark %d table %d", info.Mark, info.TableID)
	_ = i.executeCommand(delRuleCmd)

	delRouteCmd := fmt.Sprintf("ip route flush table %d", info.TableID)
	_ = i.executeCommand(delRouteCmd)

	delete(i.routing, ipsetName)
	return nil
}

func (i *IptablesManager) RestoreRules() error {
	for cmd := range i.addedRules {
		exists, err := i.ruleExistsStrict(cmd)
		if err != nil {
			return err
		}
		if !exists {
			log.Printf("Restoring missing iptables rule: %s", cmd)
			if err := i.executeCommand(cmd); err != nil {
				return err
			}
		}
	}

	for ipset, info := range i.routing {
		found := false
		rulesOutput, err := exec.Command("ip", "rule").Output()
		if err != nil {
			return fmt.Errorf("failed to list ip rules: %w", err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(rulesOutput)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, fmt.Sprintf("fwmark %d lookup %d", info.Mark, info.TableID)) {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Restoring missing ip rule for %s", ipset)
			cmd := fmt.Sprintf("ip rule add fwmark %d table %d", info.Mark, info.TableID)
			if err := i.executeCommand(cmd); err != nil {
				return err
			}
		}

		found = false
		routeOutput, err := exec.Command("ip", "route", "show", "table", fmt.Sprintf("%d", info.TableID)).Output()
		if err != nil {
			return fmt.Errorf("failed to list ip routes: %w", err)
		}
		scanner = bufio.NewScanner(strings.NewReader(string(routeOutput)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "default") {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Restoring missing ip route for %s", ipset)
			cmd := fmt.Sprintf("ip route add default dev %s table %d", info.Dev, info.TableID)
			if err := i.executeCommand(cmd); err != nil {
				return err
			}
		}
	}

	return nil
}

func (i *IptablesManager) applyIptablesRules(table, chain string, rules []string, append bool) error {
	for _, rule := range rules {
		baseCmd := fmt.Sprintf("iptables -t %s -A %s %s", table, chain, rule)

		if append {
			exists, err := i.ruleExistsStrict(baseCmd)
			if err != nil {
				return err
			}
			if exists {
				i.addedRules[baseCmd] = struct{}{}
				continue
			}
			if err := i.executeCommand(baseCmd); err != nil {
				return err
			}
			i.addedRules[baseCmd] = struct{}{}
		} else {
			exists, err := i.ruleExistsStrict(baseCmd)
			if err != nil {
				return err
			}
			if !exists {
				delete(i.addedRules, baseCmd)
				continue
			}
			delCmd := fmt.Sprintf("iptables -t %s -D %s %s", table, chain, rule)
			if err := i.executeCommand(delCmd); err != nil {
				return err
			}
			delete(i.addedRules, baseCmd)
		}
	}
	return nil
}

func (i *IptablesManager) ruleExistsStrict(cmd string) (bool, error) {
	cmd = strings.TrimPrefix(cmd, "iptables ")

	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return false, fmt.Errorf("failed to run iptables-save: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == strings.TrimSpace(cmd) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading iptables-save output: %w", err)
	}

	return false, nil
}

func (i *IptablesManager) executeCommand(cmd string) error {
	log.Printf("Executing command: %s", cmd)
	err := exec.Command("sh", "-c", cmd).Run()
	if err != nil {
		return fmt.Errorf("error execute command %s: %v", cmd, err)
	}
	return nil
}

func (i *IptablesManager) addRedirectRules(ipsetName string, port int, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
	}
	return i.applyIptablesRules(tableNat, chainPrerouting, rules, true)
}

func (i *IptablesManager) addMarkRules(ipsetName string, mark int, iface string) error {
	var rules []string

	for _, cidr := range localExceptions {
		rules = append(rules, fmt.Sprintf("-i %s -d %s -j RETURN", iface, cidr))
	}

	rules = append(rules,
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
	)
	return i.applyIptablesRules(tableMangle, chainPrerouting, rules, true)
}

func (i *IptablesManager) addIPRule(mark, tableID int) error {
	cmd := fmt.Sprintf("ip rule add fwmark %d table %d", mark, tableID)
	return i.executeCommand(cmd)
}

func (i *IptablesManager) addIPRoute(tableID int, iface string) error {
	cmd := fmt.Sprintf("ip route add default dev %s table %d", iface, tableID)
	return i.executeCommand(cmd)
}

func (i *IptablesManager) markAndTableFromIPSet(ipsetName string) (mark int, tableID int) {
	h := adler32.Checksum([]byte(ipsetName))
	mark = int(h&0xFFF) + 100
	tableID = int(h&0xFFF) + 100
	return
}

func (i *IptablesManager) extractRule(fullCmd string) string {
	parts := strings.SplitN(fullCmd, " ", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}