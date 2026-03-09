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

	"github.com/ApostolDmitry/vpner/internal/common/logging"
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
	mu            sync.Mutex
	routingV4     map[string]vpnRoutingInfo
	routingV6     map[string]vpnRoutingInfo
	ipv6Enabled   bool
	tproxyEnabled bool
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

	tproxyMark    = "200"
	tproxyMarkVal = "200"
	tproxyTableID = 200
	chainDivert   = "VPN_DIVERT"
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

func NewIptablesManager(ipv6Enabled, tproxyEnabled bool) *IptablesManager {
	mgr := &IptablesManager{
		routingV4:     make(map[string]vpnRoutingInfo),
		routingV6:     make(map[string]vpnRoutingInfo),
		ipv6Enabled:   ipv6Enabled,
		tproxyEnabled: tproxyEnabled,
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
	logging.Infof(
		"add routing ipset=%s vpn=%s iface=%s",
		ipsetName,
		vpnType,
		iface,
	)
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
		if i.tproxyEnabled {
			return i.addXrayTProxyRules(f, routing, ipsetName, chainName, param, iface)
		}
		return i.addXrayRedirectRules(f, routing, ipsetName, chainName, param, iface)

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

	logging.Infof("ensure chain %s (table=%s)", chain, table)

	err := run(iptablesCmd, "-t", table, "-N", chain)

	if err != nil {
		if strings.Contains(err.Error(), "exists") ||
			strings.Contains(err.Error(), "File exists") {

			logging.Debugf("chain %s already exists", chain)
			return nil
		}

		return err
	}

	return nil
}

func linkChain(iptablesCmd, table, chain, iface string) (jumpRule, error) {

	logging.Infof(
		"link PREROUTING -> %s (table=%s iface=%s)",
		chain,
		table,
		iface,
	)

	jmp := jumpRule{
		Cmd:  iptablesCmd,
		Args: []string{"-t", table, "-A", chainPrerouting, "-i", iface, "-j", chain},
	}

	err := run(iptablesCmd, jmp.Args...)

	if err != nil {
		if strings.Contains(err.Error(), "exists") {
			return jmp, nil
		}
		return jmp, err
	}

	return jmp, nil
}

func addRedirectRules(iptablesCmd, chainName, ipsetName string, port int, iface string) error {

	b := newBatch(iptablesCmd, tableNat)

	b.Add(fmt.Sprintf(
		"-A %s -i %s -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %d",
		chainName,
		iface,
		ipsetName,
		port,
	))

	return b.Commit()
}

func addMarkRules(f ipFamily, chainName, ipsetName string, mark int, iface string) error {

	b := newBatch(f.iptablesCmd, "mangle")

	for _, cidr := range f.localExceptions {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -d %s -j RETURN",
			chainName, iface, cidr,
		))
	}

	for _, proto := range []string{"tcp", "udp"} {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -p %s -m set --match-set %s dst -j MARK --set-mark %d",
			chainName, iface, proto, ipsetName, mark,
		))
	}

	return b.Commit()
}

func addIPRule(f ipFamily, mark, tableID int) error {
	args := append(f.ipFlags, "rule", "add", "fwmark", fmt.Sprintf("%d", mark), "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

func addIPRoute(f ipFamily, tableID int, iface string) error {
	args := append(f.ipFlags, "route", "add", "default", "dev", iface, "table", fmt.Sprintf("%d", tableID))
	return run("ip", args...)
}

// --- kernel modules ---

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
		// "File exists" means module is already loaded — that's fine.
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
// Returns nil if both are available (or already loaded).
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

// --- TPROXY ---

func (i *IptablesManager) addXrayRedirectRules(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName, chainName string, port int, iface string) error {
	logging.Infof(
		"configure Xray REDIRECT chain=%s ipset=%s port=%d",
		chainName,
		ipsetName,
		port,
	)
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
	if err := addRedirectRules(f.iptablesCmd, chainName, ipsetName, port, iface); err != nil {
		return err
	}
	info.JumpRules = appendJumpRule(info.JumpRules, jmp)
	routing[ipsetName] = info
	return nil
}

func (i *IptablesManager) addXrayTProxyRules(f ipFamily, routing map[string]vpnRoutingInfo, ipsetName, chainName string, port int, iface string) error {
	logging.Infof(
		"configure Xray TPROXY chain=%s ipset=%s port=%d",
		chainName,
		ipsetName,
		port,
	)
	if err := i.ensureTProxyInfra(f); err != nil {
		return fmt.Errorf("tproxy infra: %w", err)
	}
	info := routing[ipsetName]
	if err := ensureChain(f.iptablesCmd, tableMangle, chainName); err != nil {
		return err
	}
	info.ChainName = chainName
	info.Table = tableMangle
	jmp, err := linkChain(f.iptablesCmd, tableMangle, chainName, iface)
	if err != nil {
		return err
	}
	if err := addTProxyRules(f, chainName, ipsetName, port, iface); err != nil {
		return err
	}
	info.JumpRules = appendJumpRule(info.JumpRules, jmp)
	routing[ipsetName] = info
	return nil
}

func (i *IptablesManager) ensureTProxyInfra(f ipFamily) error {

	b := newBatch(f.iptablesCmd, tableMangle)

	b.Add(fmt.Sprintf(":%s - [0:0]", chainDivert))

	b.Add(fmt.Sprintf(
		"-A %s -j MARK --set-mark %s",
		chainDivert,
		tproxyMark,
	))

	b.Add(fmt.Sprintf(
		"-A %s -j ACCEPT",
		chainDivert,
	))

	b.Add(fmt.Sprintf(
		"-A %s -p tcp -m socket -j %s",
		chainPrerouting,
		chainDivert,
	))

	if err := b.Commit(); err != nil {
		return err
	}

	tbl := fmt.Sprintf("%d", tproxyTableID)

	if !ipRuleExists(f, tproxyMarkVal, tbl) {
		addRule := append(f.ipFlags, "rule", "add", "fwmark", tproxyMarkVal, "lookup", tbl)
		_ = run("ip", addRule...)
	}

	addRoute := append(f.ipFlags, "route", "replace", "local", "default", "dev", "lo", "table", tbl)
	_ = run("ip", addRoute...)

	return nil
}

func addTProxyRules(f ipFamily, chainName, ipsetName string, port int, iface string) error {

	b := newBatch(f.iptablesCmd, tableMangle)

	b.Add(fmt.Sprintf(
		"-A %s -m mark --mark %s -j RETURN",
		chainName, tproxyMark,
	))

	for _, cidr := range f.localExceptions {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -d %s -j RETURN",
			chainName, iface, cidr,
		))
	}

	for _, proto := range []string{"tcp", "udp"} {
		b.Add(fmt.Sprintf(
			"-A %s -i %s -p %s -m set --match-set %s dst -j TPROXY --on-port %d --tproxy-mark %s",
			chainName, iface, proto, ipsetName, port, tproxyMark,
		))
	}

	return b.Commit()
}

func ensureRule(iptablesCmd, table, chain string, ruleArgs ...string) {
	checkArgs := append([]string{"-t", table, "-C", chain}, ruleArgs...)
	if run(iptablesCmd, checkArgs...) == nil {
		return
	}
	addArgs := append([]string{"-t", table, "-A", chain}, ruleArgs...)
	_ = run(iptablesCmd, addArgs...)
}

func ipRuleExists(f ipFamily, fwmark, table string) bool {
	args := append(f.ipFlags, "rule", "show")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		return false
	}
	// busybox outputs fwmark as hex (0xc8), iproute2 as decimal (200).
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
	delArgs := append(f.ipFlags, "rule", "del", "fwmark", tproxyMarkVal, "lookup", tbl)
	// Delete all duplicates (ip rule add creates duplicates).
	for ipRuleExists(f, tproxyMarkVal, tbl) {
		_ = run("ip", delArgs...)
	}
	flushArgs := append(f.ipFlags, "route", "flush", "table", tbl)
	_ = run("ip", flushArgs...)
}

func (i *IptablesManager) cleanupTProxyInfraForFamily(f ipFamily) {
	for _, proto := range []string{"tcp", "udp"} {
		_ = run(f.iptablesCmd, "-t", tableMangle, "-D", chainPrerouting,
			"-p", proto, "-m", "socket", "-j", chainDivert)
	}
	_ = run(f.iptablesCmd, "-t", tableMangle, "-F", chainDivert)
	_ = run(f.iptablesCmd, "-t", tableMangle, "-X", chainDivert)
	i.cleanupTProxyIPRule(f)
}

func (i *IptablesManager) Shutdown() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.tproxyEnabled {
		i.cleanupTProxyInfraForFamily(familyV4)
		if i.ipv6Enabled {
			i.cleanupTProxyInfraForFamily(familyV6)
		}
	}
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
