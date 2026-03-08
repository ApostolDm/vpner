package network

import (
	"bufio"
	"fmt"
	"hash/adler32"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

type vpnRoutingInfo struct {
	Mark      int
	TableID   int
	Dev       string
	ChainName string
	Table     string // "nat" or "mangle"
	JumpRules []jumpRule
}

type jumpRule struct {
	Cmd  string   // e.g. "iptables"
	Args []string // e.g. ["-t", "nat", "-A", "PREROUTING", "-i", "br0", "-j", "VPN_xxx"]
}

func (j jumpRule) deleteArgs() []string {
	args := make([]string, len(j.Args))
	copy(args, j.Args)
	for idx, a := range args {
		if a == "-A" {
			args[idx] = "-D"
			break
		}
	}
	return args
}

type ipFamily struct {
	iptablesCmd     string
	iptablesSaveCmd string
	ipFlags         []string // [] for v4, ["-6"] for v6
	localExceptions []string
}

var (
	familyV4 = ipFamily{
		iptablesCmd:     "iptables",
		iptablesSaveCmd: "iptables-save",
		ipFlags:         nil,
		localExceptions: localExceptionsV4[:],
	}
	familyV6 = ipFamily{
		iptablesCmd:     "ip6tables",
		iptablesSaveCmd: "ip6tables-save",
		ipFlags:         []string{"-6"},
		localExceptions: localExceptionsIPv6[:],
	}
)

type IptablesManager struct {
	mu          sync.Mutex
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
	tableMangle     = "mangle"
	chainPrerouting = "PREROUTING"
)

var localExceptionsV4 = [...]string{
	"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

var localExceptionsIPv6 = [...]string{
	"::1/128", "fe80::/10", "fc00::/7",
	"ff00::/8", "2001:db8::/32",
}

var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func validateIface(iface string) error {
	if iface == "" {
		return nil
	}
	if !validIfaceRe.MatchString(iface) {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	return nil
}

func (v VPNType) IsValid() bool {
	_, ok := validVPNTypes[v]
	return ok
}

// --- command execution ---

func run(name string, args ...string) error {
	log.Printf("Executing: %s %s", name, strings.Join(args, " "))
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, msg)
		}
		return err
	}
	return nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func isChainExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Chain already exists") || strings.Contains(msg, "File exists")
}

// --- constructor & cleanup ---

func NewIptablesManager(ipv6Enabled bool) *IptablesManager {
	mgr := &IptablesManager{
		routingV4:   make(map[string]vpnRoutingInfo),
		routingV6:   make(map[string]vpnRoutingInfo),
		ipv6Enabled: ipv6Enabled,
	}
	mgr.cleanupFamily(familyV4)
	if ipv6Enabled || commandExists(familyV6.iptablesSaveCmd) {
		mgr.cleanupFamily(familyV6)
	}
	return mgr
}

func (i *IptablesManager) cleanupFamily(f ipFamily) {
	i.cleanupOldChainsInTable(f, tableNat)
	i.cleanupOldChainsInTable(f, tableMangle)
	i.cleanupOldIPRulesAndRoutes(f)
}

func (i *IptablesManager) cleanupOldIPRulesAndRoutes(f ipFamily) {
	args := append(f.ipFlags, "rule")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		log.Printf("Failed to list ip rules: %v", err)
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
			log.Printf("Cleaning old ip rule: fwmark %d table %d", fwmark, tableID)
			delArgs := append(f.ipFlags, "rule", "del", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID))
			_ = run("ip", delArgs...)
			log.Printf("Flushing old route table: %d", tableID)
			flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", tableID))
			_ = run("ip", flushArgs...)
		}
	}
}

func (i *IptablesManager) cleanupOldChainsInTable(f ipFamily, table string) {
	out, err := exec.Command(f.iptablesSaveCmd, "-t", table).Output()
	if err != nil {
		log.Printf("Failed to run %s -t %s: %v", f.iptablesSaveCmd, table, err)
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
		log.Printf("Cleaning %s PREROUTING jump: %s %s", table, f.iptablesCmd, strings.Join(args, " "))
		_ = run(f.iptablesCmd, args...)
	}

	for _, chain := range chains {
		log.Printf("Cleaning old %s chain: %s", table, chain)
		_ = run(f.iptablesCmd, "-t", table, "-F", chain)
		_ = run(f.iptablesCmd, "-t", table, "-X", chain)
	}
}

// --- public API (unchanged signatures) ---

func (i *IptablesManager) AddRules(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.addRulesForFamily(familyV4, i.routingV4, vpnType, ipsetName, param, iface, vpnIface); err != nil {
		return err
	}
	if i.ipv6Enabled {
		ipsetName6, err := IpsetName6FromBase(ipsetName)
		if err != nil {
			return err
		}
		if err := i.addRulesForFamily(familyV6, i.routingV6, vpnType, ipsetName6, param, iface, vpnIface); err != nil {
			return err
		}
	}
	return nil
}

func (i *IptablesManager) AddRulesV4(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.addRulesForFamily(familyV4, i.routingV4, vpnType, ipsetName, param, iface, vpnIface)
}

func (i *IptablesManager) AddRulesV6(vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.ipv6Enabled {
		return nil
	}
	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.addRulesForFamily(familyV6, i.routingV6, vpnType, ipsetName6, param, iface, vpnIface)
}

func (i *IptablesManager) RemoveRules(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.removeRulesForFamily(familyV4, i.routingV4, ipsetName); err != nil {
		return err
	}
	if !i.ipv6Enabled {
		return nil
	}
	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.removeRulesForFamily(familyV6, i.routingV6, ipsetName6)
}

func (i *IptablesManager) RemoveRulesV4(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.removeRulesForFamily(familyV4, i.routingV4, ipsetName)
}

func (i *IptablesManager) RemoveRulesV6(ipsetName string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.ipv6Enabled {
		return nil
	}
	ipsetName6, err := IpsetName6FromBase(ipsetName)
	if err != nil {
		return err
	}
	return i.removeRulesForFamily(familyV6, i.routingV6, ipsetName6)
}

// --- unified add/remove per family ---

func (i *IptablesManager) addRulesForFamily(f ipFamily, routing map[string]vpnRoutingInfo, vpnType VPNType, ipsetName string, param int, iface, vpnIface string) error {
	if !vpnType.IsValid() {
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
	if err := validateIface(iface); err != nil {
		return err
	}
	if err := validateIface(vpnIface); err != nil {
		return err
	}

	chainName := buildChainName(ipsetName)

	switch vpnType {
	case Xray:
		info := routing[ipsetName]

		if err := ensureChain(f.iptablesCmd, tableNat, chainName); err != nil {
			return err
		}

		info.ChainName = chainName
		info.Table = tableNat
		
		jmp, err := linkChain(f.iptablesCmd, tableNat, chainName, iface)
		if err != nil {
			return err
		}
		if err := addRedirectRules(f.iptablesCmd, chainName, ipsetName, param, iface); err != nil {
			return err
		}
		info.JumpRules = appendJumpRule(info.JumpRules, jmp)
		routing[ipsetName] = info
		return nil

	case OpenVPN, Wireguard, IKE, SSTP, PPPOE, L2TP, PPTP:
		if err := ensureChain(f.iptablesCmd, tableMangle, chainName); err != nil {
			return err
		}
		jmp, err := linkChain(f.iptablesCmd, tableMangle, chainName, iface)
		if err != nil {
			return err
		}
		mark, tableID := markAndTableFromIPSet(ipsetName)
		if err := addMarkRules(f, chainName, ipsetName, mark, iface); err != nil {
			return err
		}
		if err := addIPRule(f, mark, tableID); err != nil {
			return err
		}
		if err := addIPRoute(f, tableID, vpnIface); err != nil {
			return err
		}
		routing[ipsetName] = vpnRoutingInfo{
			Mark:      mark,
			TableID:   tableID,
			Dev:       vpnIface,
			ChainName: chainName,
			Table:     tableMangle,
			JumpRules: []jumpRule{jmp},
		}
		return nil

	default:
		return fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

func (i *IptablesManager) removeRulesForFamily(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName string) error {
	info, ok := routing[ipsetName]
	if !ok {
		if f.iptablesCmd == "iptables" {
			return fmt.Errorf("no routing info found for ipset: %s", ipsetName)
		}
		return nil // v6: silently ignore missing
	}

	for _, jmp := range info.JumpRules {
		_ = run(jmp.Cmd, jmp.deleteArgs()...)
	}

	table := info.Table
	if table == "" {
		table = tableNat
	}
	_ = run(f.iptablesCmd, "-t", table, "-F", info.ChainName)
	_ = run(f.iptablesCmd, "-t", table, "-X", info.ChainName)

	if info.Mark != 0 && info.TableID != 0 {
		delArgs := append(f.ipFlags, "rule", "del", "fwmark", fmt.Sprintf("%d", info.Mark), "table", fmt.Sprintf("%d", info.TableID))
		_ = run("ip", delArgs...)
		flushArgs := append(f.ipFlags, "route", "flush", "table", fmt.Sprintf("%d", info.TableID))
		_ = run("ip", flushArgs...)
	}

	delete(routing, ipsetName)
	return nil
}

// --- iptables helpers ---

func ensureChain(iptablesCmd, table, chain string) error {
	if err := run(iptablesCmd, "-t", table, "-N", chain); err != nil {
		if isChainExistsError(err) {
			return nil
		}
		return err
	}
	return nil
}

func linkChain(iptablesCmd, table, chain, iface string) (jumpRule, error) {
	jmp := jumpRule{
		Cmd:  iptablesCmd,
		Args: []string{"-t", table, "-A", chainPrerouting, "-i", iface, "-j", chain},
	}
	checkArgs := make([]string, len(jmp.Args))
	copy(checkArgs, jmp.Args)
	for idx, a := range checkArgs {
		if a == "-A" {
			checkArgs[idx] = "-C"
			break
		}
	}
	if err := run(iptablesCmd, checkArgs...); err == nil {
		return jmp, nil
	}
	if err := run(iptablesCmd, jmp.Args...); err != nil {
		return jmp, err
	}
	return jmp, nil
}

func addRedirectRules(iptablesCmd, chainName, ipsetName string, port int, iface string) error {
	for _, proto := range []string{"tcp", "udp"} {
		args := []string{"-t", "nat", "-A", chainName,
			"-i", iface, "-p", proto,
			"-m", "set", "--match-set", ipsetName, "dst",
			"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)}
		checkArgs := make([]string, len(args))
		copy(checkArgs, args)
		for idx, a := range checkArgs {
			if a == "-A" {
				checkArgs[idx] = "-C"
				break
			}
		}
		if err := run(iptablesCmd, checkArgs...); err == nil {
			continue
		}
		if err := run(iptablesCmd, args...); err != nil {
			return err
		}
	}
	return nil
}

func addMarkRules(f ipFamily, chainName, ipsetName string, mark int, iface string) error {
	for _, cidr := range f.localExceptions {
		if err := run(f.iptablesCmd, "-t", "mangle", "-A", chainName, "-i", iface, "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		args := []string{"-t", "mangle", "-A", chainName,
			"-i", iface, "-p", proto,
			"-m", "set", "--match-set", ipsetName, "dst",
			"-j", "MARK", "--set-mark", fmt.Sprintf("%d", mark)}
		if err := run(f.iptablesCmd, args...); err != nil {
			return err
		}
	}
	return nil
}

func addIPRule(f ipFamily, mark, tableID int) error {
	args := append(f.ipFlags, "rule", "add", "fwmark", fmt.Sprintf("%d", mark), "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

func addIPRoute(f ipFamily, tableID int, iface string) error {
	args := append(f.ipFlags, "route", "add", "default", "dev", iface, "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

// --- utilities ---

func buildChainName(ipsetName string) string {
	hash := adler32.Checksum([]byte(ipsetName))
	return fmt.Sprintf("VPN_%08x", hash)
}

func markAndTableFromIPSet(ipsetName string) (mark int, tableID int) {
	h := adler32.Checksum([]byte(ipsetName))
	id := int(h&0xFFF) + 100
	return id, id
}

func appendJumpRule(rules []jumpRule, rule jumpRule) []jumpRule {
	for _, existing := range rules {
		if existing.Cmd == rule.Cmd && strings.Join(existing.Args, " ") == strings.Join(rule.Args, " ") {
			return rules
		}
	}
	return append(rules, rule)
}
