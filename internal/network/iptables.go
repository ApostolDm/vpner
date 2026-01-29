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
	Mark      int
	TableID   int
	Dev       string
	ChainName string
	JumpRules []string
}

type IptablesManager struct {
	routingV4   map[string]vpnRoutingInfo
	routingV6   map[string]vpnRoutingInfo
	ipv6Enabled bool
}

type VPNType string

const (
	OpenVPN   VPNType = "OpenVPN"
	Wireguard VPNType = "Wireguard"
	IKE       VPNType = "IKE"
	SSTP      VPNType = "SSTP"
	PPPOE     VPNType = "PPPOE"
	L2TP      VPNType = "L2TP"
	PPTP      VPNType = "PPTP"
	Xray      VPNType = "Xray"
)

var validVPNTypes = map[VPNType]struct{}{
	OpenVPN: {}, Wireguard: {}, IKE: {}, SSTP: {}, PPPOE: {}, L2TP: {}, PPTP: {}, Xray: {},
}

const (
	tableNat        = "nat"
	chainPrerouting = "PREROUTING"
)

var localExceptions = [...]string{
	"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

var localExceptionsV6 = [...]string{
	"::1/128", "fe80::/10", "fc00::/7",
	"ff00::/8", "2001:db8::/32",
}

func NewIptablesManager(ipv6Enabled bool) *IptablesManager {
	mgr := &IptablesManager{
		routingV4:   make(map[string]vpnRoutingInfo),
		routingV6:   make(map[string]vpnRoutingInfo),
		ipv6Enabled: ipv6Enabled,
	}
	mgr.cleanupOldChains("iptables-save", "iptables")
	mgr.cleanupOldIPRulesAndRoutes(false)
	if ipv6Enabled || commandExists("ip6tables-save") {
		mgr.cleanupOldChains("ip6tables-save", "ip6tables")
		mgr.cleanupOldIPRulesAndRoutes(true)
	}
	return mgr
}

func (i *IptablesManager) cleanupOldIPRulesAndRoutes(ipv6 bool) {
	args := []string{"rule"}
	if ipv6 {
		args = []string{"-6", "rule"}
	}
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		log.Printf("Failed to list ip rules: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "fwmark") && strings.Contains(line, "lookup") {
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
				log.Printf("Cleaning old ip rule: fwmark %d table %d", fwmark, tableID)
				if ipv6 {
					_ = i.executeCommand(fmt.Sprintf("ip -6 rule del fwmark %d table %d", fwmark, tableID))
				} else {
					_ = i.executeCommand(fmt.Sprintf("ip rule del fwmark %d table %d", fwmark, tableID))
				}
				log.Printf("Flushing old route table: %d", tableID)
				if ipv6 {
					_ = i.executeCommand(fmt.Sprintf("ip -6 route flush table %d", tableID))
				} else {
					_ = i.executeCommand(fmt.Sprintf("ip route flush table %d", tableID))
				}
			}
		}
	}
}

func (i *IptablesManager) cleanupOldChains(iptablesSaveCmd, iptablesCmd string) {
	out, err := exec.Command(iptablesSaveCmd, "-t", "nat").Output()
	if err != nil {
		log.Printf("Failed to run %s: %v", iptablesSaveCmd, err)
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
		cmd := fmt.Sprintf("%s -t nat %s", iptablesCmd, strings.Replace(rule, "-A", "-D", 1))
		log.Printf("Cleaning PREROUTING jump: %s", cmd)
		_ = i.executeCommand(cmd)
	}

	// Потом удаляем сами цепочки
	for _, chain := range chains {
		log.Printf("Cleaning old chain: %s", chain)
		_ = i.executeCommand(fmt.Sprintf("%s -t nat -F %s", iptablesCmd, chain))
		_ = i.executeCommand(fmt.Sprintf("%s -t nat -X %s", iptablesCmd, chain))
	}
}

func (v VPNType) IsValid() bool {
	_, ok := validVPNTypes[v]
	return ok
}

func (i *IptablesManager) AddRules(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if err := i.AddRulesV4(vpnType, ipsetName, param, iface, vpnIface); err != nil {
		return err
	}
	if err := i.AddRulesV6(vpnType, ipsetName, param, iface, vpnIface); err != nil {
		return err
	}
	return nil
}

func (i *IptablesManager) AddRulesV4(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	return i.addRulesV4(vpnType, ipsetName, param, iface, vpnIface)
}

func (i *IptablesManager) AddRulesV6(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if !i.ipv6Enabled {
		return nil
	}
	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	if err := i.addRulesV6(vpnType, ipsetName6, param, iface, vpnIface); err != nil {
		return err
	}
	return nil
}

func (i *IptablesManager) addRulesV4(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if !vpnType.IsValid() {
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}

	chainName := i.buildChainName(ipsetName)

	switch vpnType {
	case Xray:
		info, ok := i.routingV4[ipsetName]
		if !ok {
			if err := i.ensureChain(tableNat, chainName); err != nil {
				return err
			}
			info.ChainName = chainName
		}
		jumpCmd, err := i.linkChainToPrerouting(chainName, iface)
		if err != nil {
			return err
		}
		if err := i.addRedirectRules(chainName, ipsetName, param, iface); err != nil {
			return err
		}
		info.JumpRules = appendJumpRule(info.JumpRules, jumpCmd)
		i.routingV4[ipsetName] = info
		return nil
	case OpenVPN, Wireguard, IKE, SSTP, PPPOE, L2TP, PPTP:
		if err := i.ensureChain(tableNat, chainName); err != nil {
			return err
		}
		jumpCmd, err := i.linkChainToPrerouting(chainName, iface)
		if err != nil {
			return err
		}
		mark, tableID := i.markAndTableFromIPSet(ipsetName)
		if err := i.addMarkRules(chainName, ipsetName, mark, iface); err != nil {
			return err
		}
		if err := i.addIPRule(mark, tableID); err != nil {
			return err
		}
		if err := i.addIPRoute(tableID, vpnIface); err != nil {
			return err
		}
		i.routingV4[ipsetName] = vpnRoutingInfo{
			Mark:      mark,
			TableID:   tableID,
			Dev:       vpnIface,
			ChainName: chainName,
			JumpRules: []string{jumpCmd},
		}
		return nil
	default:
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

func (i *IptablesManager) addRulesV6(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if !vpnType.IsValid() {
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}

	chainName := i.buildChainName(ipsetName)

	switch vpnType {
	case Xray:
		info, ok := i.routingV6[ipsetName]
		if !ok {
			if err := i.ensureChainV6(tableNat, chainName); err != nil {
				return err
			}
			info.ChainName = chainName
		}
		jumpCmd, err := i.linkChainToPreroutingV6(chainName, iface)
		if err != nil {
			return err
		}
		if err := i.addRedirectRulesV6(chainName, ipsetName, param, iface); err != nil {
			return err
		}
		info.JumpRules = appendJumpRule(info.JumpRules, jumpCmd)
		i.routingV6[ipsetName] = info
		return nil
	case OpenVPN, Wireguard, IKE, SSTP, PPPOE, L2TP, PPTP:
		if err := i.ensureChainV6(tableNat, chainName); err != nil {
			return err
		}
		jumpCmd, err := i.linkChainToPreroutingV6(chainName, iface)
		if err != nil {
			return err
		}
		mark, tableID := i.markAndTableFromIPSet(ipsetName)
		if err := i.addMarkRulesV6(chainName, ipsetName, mark, iface); err != nil {
			return err
		}
		if err := i.addIPRuleV6(mark, tableID); err != nil {
			return err
		}
		if err := i.addIPRouteV6(tableID, vpnIface); err != nil {
			return err
		}
		i.routingV6[ipsetName] = vpnRoutingInfo{
			Mark:      mark,
			TableID:   tableID,
			Dev:       vpnIface,
			ChainName: chainName,
			JumpRules: []string{jumpCmd},
		}
		return nil
	default:
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

func (i *IptablesManager) RemoveRules(ipsetName string) error {
	if err := i.RemoveRulesV4(ipsetName); err != nil {
		return err
	}
	if err := i.RemoveRulesV6(ipsetName); err != nil {
		return err
	}
	return nil
}

func (i *IptablesManager) RemoveRulesV4(ipsetName string) error {
	info, ok := i.routingV4[ipsetName]
	if !ok {
		return fmt.Errorf("no routing info found for ipset: %s", ipsetName)
	}

	for _, rule := range info.JumpRules {
		if rule == "" {
			continue
		}
		delCmd := strings.Replace(rule, "-A ", "-D ", 1)
		_ = i.executeCommand(delCmd)
	}

	_ = i.executeCommand(fmt.Sprintf("iptables -t nat -F %s", info.ChainName))
	_ = i.executeCommand(fmt.Sprintf("iptables -t nat -X %s", info.ChainName))

	if info.Mark != 0 && info.TableID != 0 {
		_ = i.executeCommand(fmt.Sprintf("ip rule del fwmark %d table %d", info.Mark, info.TableID))
		_ = i.executeCommand(fmt.Sprintf("ip route flush table %d", info.TableID))
	}

	delete(i.routingV4, ipsetName)
	return nil
}

func (i *IptablesManager) RemoveRulesV6(ipsetName string) error {
	if !i.ipv6Enabled {
		return nil
	}
	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.removeRulesV6(ipsetName6)
}

func (i *IptablesManager) createChain(table, chain string) error {
	return i.executeCommand(fmt.Sprintf("iptables -t %s -N %s", table, chain))
}

func (i *IptablesManager) createChainV6(table, chain string) error {
	return i.executeCommand(fmt.Sprintf("ip6tables -t %s -N %s", table, chain))
}

func (i *IptablesManager) linkChainToPrerouting(chain, iface string) (string, error) {
	if err := i.ensureChain(tableNat, chain); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("iptables -t nat -A %s -i %s -j %s", chainPrerouting, iface, chain)
	if err := i.ensureJumpRule(cmd); err != nil {
		return cmd, err
	}
	return cmd, nil
}

func (i *IptablesManager) linkChainToPreroutingV6(chain, iface string) (string, error) {
	if err := i.ensureChainV6(tableNat, chain); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("ip6tables -t nat -A %s -i %s -j %s", chainPrerouting, iface, chain)
	if err := i.ensureJumpRule(cmd); err != nil {
		return cmd, err
	}
	return cmd, nil
}

func (i *IptablesManager) addRedirectRules(chainName, ipsetName string, port int, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
	}
	for _, rule := range rules {
		cmd := fmt.Sprintf("iptables -t nat -A %s %s", chainName, rule)
		if err := i.ensureJumpRule(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (i *IptablesManager) addRedirectRulesV6(chainName, ipsetName string, port int, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
	}
	for _, rule := range rules {
		cmd := fmt.Sprintf("ip6tables -t nat -A %s %s", chainName, rule)
		if err := i.ensureJumpRule(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (i *IptablesManager) addMarkRules(chainName, ipsetName string, mark int, iface string) error {
	for _, cidr := range localExceptions {
		if err := i.executeCommand(fmt.Sprintf("iptables -t mangle -A %s -i %s -d %s -j RETURN", chainName, iface, cidr)); err != nil {
			return err
		}
	}
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
	}
	for _, rule := range rules {
		if err := i.executeCommand(fmt.Sprintf("iptables -t mangle -A %s %s", chainName, rule)); err != nil {
			return err
		}
	}
	return nil
}

func (i *IptablesManager) addMarkRulesV6(chainName, ipsetName string, mark int, iface string) error {
	for _, cidr := range localExceptionsV6 {
		if err := i.executeCommand(fmt.Sprintf("ip6tables -t mangle -A %s -i %s -d %s -j RETURN", chainName, iface, cidr)); err != nil {
			return err
		}
	}
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j MARK --set-mark %d", iface, ipsetName, mark),
	}
	for _, rule := range rules {
		if err := i.executeCommand(fmt.Sprintf("ip6tables -t mangle -A %s %s", chainName, rule)); err != nil {
			return err
		}
	}
	return nil
}

func (i *IptablesManager) addIPRule(mark, tableID int) error {
	return i.executeCommand(fmt.Sprintf("ip rule add fwmark %d table %d", mark, tableID))
}

func (i *IptablesManager) addIPRuleV6(mark, tableID int) error {
	return i.executeCommand(fmt.Sprintf("ip -6 rule add fwmark %d table %d", mark, tableID))
}

func (i *IptablesManager) addIPRoute(tableID int, iface string) error {
	return i.executeCommand(fmt.Sprintf("ip route add default dev %s table %d", iface, tableID))
}

func (i *IptablesManager) addIPRouteV6(tableID int, iface string) error {
	return i.executeCommand(fmt.Sprintf("ip -6 route add default dev %s table %d", iface, tableID))
}

func (i *IptablesManager) buildChainName(ipsetName string) string {
	hash := adler32.Checksum([]byte(ipsetName))
	return fmt.Sprintf("VPN_%08x", hash)
}

func (i *IptablesManager) markAndTableFromIPSet(ipsetName string) (mark int, tableID int) {
	h := adler32.Checksum([]byte(ipsetName))
	mark = int(h&0xFFF) + 100
	tableID = int(h&0xFFF) + 100
	return
}

func appendJumpRule(rules []string, rule string) []string {
	for _, existing := range rules {
		if existing == rule {
			return rules
		}
	}
	return append(rules, rule)
}

func (i *IptablesManager) ensureChain(table, chain string) error {
	cmd := fmt.Sprintf("iptables -t %s -N %s", table, chain)
	if err := i.executeCommand(cmd); err != nil {
		if isChainExistsError(err) {
			return nil
		}
		return err
	}
	return nil
}

func (i *IptablesManager) ensureChainV6(table, chain string) error {
	cmd := fmt.Sprintf("ip6tables -t %s -N %s", table, chain)
	if err := i.executeCommand(cmd); err != nil {
		if isChainExistsError(err) {
			return nil
		}
		return err
	}
	return nil
}

func (i *IptablesManager) ensureJumpRule(addCmd string) error {
	checkCmd := strings.Replace(addCmd, "-A ", "-C ", 1)
	if err := i.executeCommand(checkCmd); err == nil {
		return nil
	}
	return i.executeCommand(addCmd)
}

func isChainExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Chain already exists") || strings.Contains(msg, "File exists")
}

func (i *IptablesManager) executeCommand(cmd string) error {
	log.Printf("Executing: %s", cmd)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s: %w (%s)", cmd, err, msg)
		}
		return err
	}
	return nil
}

func (i *IptablesManager) removeRulesV6(ipsetName string) error {
	info, ok := i.routingV6[ipsetName]
	if !ok {
		return nil
	}

	for _, rule := range info.JumpRules {
		if rule == "" {
			continue
		}
		delCmd := strings.Replace(rule, "-A ", "-D ", 1)
		_ = i.executeCommand(delCmd)
	}

	_ = i.executeCommand(fmt.Sprintf("ip6tables -t nat -F %s", info.ChainName))
	_ = i.executeCommand(fmt.Sprintf("ip6tables -t nat -X %s", info.ChainName))

	if info.Mark != 0 && info.TableID != 0 {
		_ = i.executeCommand(fmt.Sprintf("ip -6 rule del fwmark %d table %d", info.Mark, info.TableID))
		_ = i.executeCommand(fmt.Sprintf("ip -6 route flush table %d", info.TableID))
	}

	delete(i.routingV6, ipsetName)
	return nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
