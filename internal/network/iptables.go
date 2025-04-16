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
	JumpRule  string
}

type IptablesManager struct {
	routing map[string]vpnRoutingInfo
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
	tableMangle     = "mangle"
	tableNat        = "nat"
	chainPrerouting = "PREROUTING"
)

var localExceptions = [...]string{
	"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

func NewIptablesManager() *IptablesManager {
	mgr := &IptablesManager{
		routing: make(map[string]vpnRoutingInfo),
	}
	mgr.cleanupOldChains()
	mgr.cleanupOldIPRulesAndRoutes()
	return mgr
}

func (i *IptablesManager) cleanupOldIPRulesAndRoutes() {
	out, err := exec.Command("ip", "rule").Output()
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
				_ = i.executeCommand(fmt.Sprintf("ip rule del fwmark %d table %d", fwmark, tableID))
				log.Printf("Flushing old route table: %d", tableID)
				_ = i.executeCommand(fmt.Sprintf("ip route flush table %d", tableID))
			}
		}
	}
}

func (i *IptablesManager) cleanupOldChains() {
	out, err := exec.Command("iptables-save", "-t", "nat").Output()
	if err != nil {
		log.Printf("Failed to run iptables-save: %v", err)
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
		cmd := fmt.Sprintf("iptables -t nat %s", strings.Replace(rule, "-A", "-D", 1))
		log.Printf("Cleaning PREROUTING jump: %s", cmd)
		_ = i.executeCommand(cmd)
	}

	// Потом удаляем сами цепочки
	for _, chain := range chains {
		log.Printf("Cleaning old chain: %s", chain)
		_ = i.executeCommand(fmt.Sprintf("iptables -t nat -F %s", chain))
		_ = i.executeCommand(fmt.Sprintf("iptables -t nat -X %s", chain))
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

	chainName := i.buildChainName(ipsetName)

	if err := i.createChain(tableNat, chainName); err != nil {
		return err
	}
	jumpCmd, err := i.linkChainToPrerouting(chainName, iface)
	if err != nil {
		return err
	}

	switch vpnType {
	case Xray:
		if err := i.addRedirectRules(chainName, ipsetName, param, iface); err != nil {
			return err
		}
		i.routing[ipsetName] = vpnRoutingInfo{
			ChainName: chainName,
			JumpRule:  jumpCmd,
		}
		return nil
	case OpenVPN, Wireguard, IKE, SSTP, PPPOE, L2TP, PPTP:
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
		i.routing[ipsetName] = vpnRoutingInfo{
			Mark:      mark,
			TableID:   tableID,
			Dev:       vpnIface,
			ChainName: chainName,
			JumpRule:  jumpCmd,
		}
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

	if info.JumpRule != "" {
		delCmd := strings.Replace(info.JumpRule, "-A ", "-D ", 1)
		_ = i.executeCommand(delCmd)
	}

	_ = i.executeCommand(fmt.Sprintf("iptables -t nat -F %s", info.ChainName))
	_ = i.executeCommand(fmt.Sprintf("iptables -t nat -X %s", info.ChainName))

	if info.Mark != 0 && info.TableID != 0 {
		_ = i.executeCommand(fmt.Sprintf("ip rule del fwmark %d table %d", info.Mark, info.TableID))
		_ = i.executeCommand(fmt.Sprintf("ip route flush table %d", info.TableID))
	}

	delete(i.routing, ipsetName)
	return nil
}

func (i *IptablesManager) createChain(table, chain string) error {
	return i.executeCommand(fmt.Sprintf("iptables -t %s -N %s", table, chain))
}

func (i *IptablesManager) linkChainToPrerouting(chain, iface string) (string, error) {
	cmd := fmt.Sprintf("iptables -t nat -A %s -i %s -j %s", chainPrerouting, iface, chain)
	return cmd, i.executeCommand(cmd)
}

func (i *IptablesManager) addRedirectRules(chainName, ipsetName string, port int, iface string) error {
	rules := []string{
		fmt.Sprintf("-i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
		fmt.Sprintf("-i %s -p udp -m set --match-set %s dst -j REDIRECT --to-ports %d", iface, ipsetName, port),
	}
	for _, rule := range rules {
		if err := i.executeCommand(fmt.Sprintf("iptables -t nat -A %s %s", chainName, rule)); err != nil {
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

func (i *IptablesManager) addIPRule(mark, tableID int) error {
	return i.executeCommand(fmt.Sprintf("ip rule add fwmark %d table %d", mark, tableID))
}

func (i *IptablesManager) addIPRoute(tableID int, iface string) error {
	return i.executeCommand(fmt.Sprintf("ip route add default dev %s table %d", iface, tableID))
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

func (i *IptablesManager) executeCommand(cmd string) error {
	log.Printf("Executing: %s", cmd)
	return exec.Command("sh", "-c", cmd).Run()
}
