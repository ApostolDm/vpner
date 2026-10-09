package firewall

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

const (
	chainDefault      = "VPN_DEFAULT"
	defaultProbeChain = "VPN_DEFAULT_PROBE"
)

var ErrDefaultRoutePending = errors.New("default route pending")

var defaultOnlyExceptionsV4 = [...]string{"100.64.0.0/10"}

type defaultTarget struct {
	kind      vpnkind.Kind
	ipsetName string
}

type defaultApplied struct {
	table string
	key   string
}

type defaultSpec struct {
	table string
	key   string
	rules []string
}

type defaultFamily struct {
	f       ipFamily
	routing map[string]vpnRoutingInfo
	applied *defaultApplied
}

func (i *IptablesManager) defaultFamilies() []defaultFamily {
	out := []defaultFamily{{familyV4, i.routingV4, &i.defaultV4}}
	if i.ipv6Enabled {
		out = append(out, defaultFamily{familyV6, i.routingV6, &i.defaultV6})
	}
	return out
}

func (i *IptablesManager) SetDefaultRouteObserver(fn func(applied bool)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.defaultObserver = fn
}

func (i *IptablesManager) SetDefaultTarget(kind vpnkind.Kind, ipsetName string) ([]string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.defaultTarget = &defaultTarget{kind: kind, ipsetName: ipsetName}
	i.ensureDefaultLocked()

	var warnings []string
	if ctdir, conclusive := i.ctdirSupportedLocked(familyV4); conclusive && !ctdir {
		warnings = append(warnings, "conntrack --ctdir match unavailable on this kernel: replies to inbound port-forwards will also be tunnelled")
	}
	return warnings, i.defaultErr
}

func (i *IptablesManager) ClearDefaultTarget() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.defaultTarget = nil
	i.ensureDefaultLocked()
}

func (i *IptablesManager) DefaultRouteApplied() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.defaultV4.key != ""
}

func (i *IptablesManager) DefaultRouteError() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.defaultErr == nil {
		return ""
	}
	return i.defaultErr.Error()
}

func (i *IptablesManager) RefreshDefaultRoute() {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.defaultTarget == nil && i.defaultV4.table == "" && i.defaultV6.table == "" {
		return
	}
	for _, fam := range i.defaultFamilies() {
		spec, ok, _ := i.defaultSpecLocked(fam.f, fam.routing)
		dirty := (ok && spec.key != fam.applied.key) || (!ok && fam.applied.table != "")
		if fam.f.iptablesCmd == familyV4.iptablesCmd && i.defaultErr != nil {
			dirty = true
		}
		if dirty {
			i.ensureDefaultFamilyLocked(fam)
		}
	}
}

func (i *IptablesManager) ensureDefaultLocked() {
	for _, fam := range i.defaultFamilies() {
		i.ensureDefaultFamilyLocked(fam)
	}
}

func (i *IptablesManager) ensureDefaultFamilyLocked(fam defaultFamily) {
	spec, ok, err := i.defaultSpecLocked(fam.f, fam.routing)
	if !ok {
		i.removeDefaultLocked(fam)
		i.setDefaultErrLocked(fam.f, err)
		return
	}
	if fam.applied.key != spec.key {
		if fam.applied.table != "" && fam.applied.table != spec.table {
			i.removeDefaultLocked(fam)
		}
		if err := i.buildDefaultChain(fam.f, spec); err != nil {
			i.setAppliedLocked(fam, spec.table, "")
			i.setDefaultErrLocked(fam.f, err)
			return
		}
		i.setAppliedLocked(fam, spec.table, spec.key)
		logx.Infof("default route applied (%s table=%s)", fam.f.iptablesCmd, spec.table)
	}
	i.placeDefaultJump(fam.f, spec.table)
	i.setDefaultErrLocked(fam.f, nil)
}

func (i *IptablesManager) setAppliedLocked(fam defaultFamily, table, key string) {
	was := fam.applied.key != ""
	*fam.applied = defaultApplied{table: table, key: key}
	if fam.f.iptablesCmd == familyV4.iptablesCmd && i.defaultObserver != nil && was != (key != "") {
		i.defaultObserver(key != "")
	}
}

func (i *IptablesManager) setDefaultErrLocked(f ipFamily, err error) {
	if f.iptablesCmd != familyV4.iptablesCmd {
		if err != nil {
			logx.Warnf("default route %s: %v", f.iptablesCmd, err)
		}
		return
	}
	if err != nil && (i.defaultErr == nil || i.defaultErr.Error() != err.Error()) {
		logx.Errorf("default route: %v", err)
	}
	i.defaultErr = err
}

func (i *IptablesManager) defaultSpecLocked(f ipFamily, routing map[string]vpnRoutingInfo) (defaultSpec, bool, error) {
	if i.defaultTarget == nil {
		return defaultSpec{}, false, nil
	}
	name := i.defaultTarget.ipsetName
	if f.iptablesCmd == familyV6.iptablesCmd {
		name6, err := IpsetName6FromBase(name)
		if err != nil {
			return defaultSpec{}, false, nil
		}
		name = name6
	}
	info, ok := routing[name]
	if !ok {
		return defaultSpec{}, false, nil
	}

	xray := i.defaultTarget.kind == vpnkind.Xray
	switch {
	case xray && info.VPNType == vpnkind.Xray && info.Port != 0:
	case !xray && info.VPNType != vpnkind.Xray && info.Mark != 0:
	default:
		return defaultSpec{}, false, nil
	}

	ctdir, conclusive := i.ctdirSupportedLocked(f)
	if !conclusive {
		return defaultSpec{}, false, fmt.Errorf("%w: %s conntrack probe inconclusive (xtables busy?), retrying", ErrDefaultRoutePending, f.iptablesCmd)
	}
	exceptions := unionCIDRs(i.defaultExceptionsFor(f), localNetworks(f))
	tail := fmt.Sprintf("%s|%v|%s", strings.Join(i.lanIfaces, ","), ctdir, strings.Join(exceptions, ","))

	switch {
	case xray && info.Table == tableNat:
		return defaultSpec{
			table: tableNat,
			key:   fmt.Sprintf("redirect|%d|%s", info.Port, tail),
			rules: defaultRedirectRules(i.lanIfaces, exceptions, info.Port),
		}, true, nil
	case xray:
		connmark := i.connmarkSupported(f)
		return defaultSpec{
			table: tableMangle,
			key:   fmt.Sprintf("tproxy|%d|%v|%s", info.Port, connmark, tail),
			rules: defaultTProxyRules(i.lanIfaces, exceptions, info.Port, connmark, ctdir),
		}, true, nil
	default:
		connmark := i.connmarkSupported(f)
		return defaultSpec{
			table: tableMangle,
			key:   fmt.Sprintf("mark|%d|%v|%s", info.Mark, connmark, tail),
			rules: defaultMarkRules(i.lanIfaces, exceptions, info.Mark, connmark, ctdir),
		}, true, nil
	}
}

func (i *IptablesManager) defaultExceptionsFor(f ipFamily) []string {
	var base []string
	if f.iptablesCmd == familyV6.iptablesCmd {
		base = localExceptionsIPv6[:]
	} else {
		base = append(append([]string(nil), localExceptionsV4[:]...), defaultOnlyExceptionsV4[:]...)
	}
	return unionCIDRs(base, i.exceptionsFor(f))
}

func localNetworks(f ipFamily) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	wantV6 := f.iptablesCmd == familyV6.iptablesCmd
	seen := make(map[string]struct{})
	var out []string
	add := func(n *net.IPNet) {
		s := n.String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			ip := ipnet.IP.To4()
			bits := 32
			if ip == nil {
				ip = ipnet.IP.To16()
				bits = 128
			}
			if ip == nil || wantV6 == (bits == 32) {
				continue
			}
			add(&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			add(&net.IPNet{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask})
		}
	}
	sort.Strings(out)
	return out
}

func unionCIDRs(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, list := range [][]string{base, extra} {
		for _, cidr := range list {
			if _, ok := seen[cidr]; ok {
				continue
			}
			seen[cidr] = struct{}{}
			out = append(out, cidr)
		}
	}
	return out
}

func ctdirMatch(ctdir bool) string {
	if ctdir {
		return " -m conntrack --ctdir ORIGINAL"
	}
	return ""
}

func defaultMarkRules(ifaces, exceptions []string, mark int, connmark, ctdir bool) []string {
	var rules []string
	for _, iface := range ifaces {
		if connmark {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s",
				chainDefault, iface, vpnerMarkMask, vpnerMarkMask))
		}
		rules = append(rules, fmt.Sprintf("-A %s -i %s -m mark ! --mark 0/%s -j RETURN", chainDefault, iface, vpnerMarkMask))
		for _, cidr := range exceptions {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -d %s -j RETURN", chainDefault, iface, cidr))
		}
		rules = append(rules, fmt.Sprintf("-A %s -i %s%s -j MARK --set-mark %d", chainDefault, iface, ctdirMatch(ctdir), mark))
		if connmark {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -m mark --mark %d -j CONNMARK --save-mark --nfmask %s --ctmask %s",
				chainDefault, iface, mark, vpnerMarkMask, vpnerMarkMask))
		}
	}
	return rules
}

func defaultTProxyRules(ifaces, exceptions []string, port int, connmark, ctdir bool) []string {
	var rules []string
	for _, iface := range ifaces {
		if connmark {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -j CONNMARK --restore-mark --nfmask %s --ctmask %s",
				chainDefault, iface, vpnerMarkMask, vpnerMarkMask))
		}
		rules = append(rules, fmt.Sprintf("-A %s -i %s -m mark ! --mark 0/%s -j RETURN", chainDefault, iface, vpnerMarkMask))
		for _, cidr := range exceptions {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -d %s -j RETURN", chainDefault, iface, cidr))
		}
		for _, proto := range []string{"tcp", "udp"} {
			rules = append(rules, fmt.Sprintf(
				"-A %s -i %s -p %s%s -j TPROXY --on-port %d --tproxy-mark %s",
				chainDefault, iface, proto, ctdirMatch(ctdir), port, tproxyMark,
			))
		}
	}
	return rules
}

func defaultRedirectRules(ifaces, exceptions []string, port int) []string {
	var rules []string
	for _, iface := range ifaces {
		rules = append(rules, fmt.Sprintf("-A %s -i %s -m mark ! --mark 0/%s -j RETURN", chainDefault, iface, vpnerMarkMask))
		for _, cidr := range exceptions {
			rules = append(rules, fmt.Sprintf("-A %s -i %s -d %s -j RETURN", chainDefault, iface, cidr))
		}
		rules = append(rules, fmt.Sprintf("-A %s -i %s -p tcp -j REDIRECT --to-ports %d", chainDefault, iface, port))
	}
	return rules
}

func (i *IptablesManager) buildDefaultChain(f ipFamily, spec defaultSpec) error {
	if err := ensureChain(f.iptablesCmd, spec.table, chainDefault); err != nil {
		return err
	}
	var err error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < runRetryAttempts; attempt++ {
		tryRun(f.iptablesCmd, "-t", spec.table, "-F", chainDefault)
		b := newBatch(f.iptablesCmd, spec.table)
		for _, rule := range spec.rules {
			b.Add(rule)
		}
		if err = b.Commit(); err == nil {
			return nil
		}
		if attempt < runRetryAttempts-1 {
			time.Sleep(delay)
			delay *= 3
		}
	}
	return err
}

func (i *IptablesManager) placeDefaultJump(f ipFamily, table string) {
	counts := chainRuleCounts(f.iptablesCmd, table, chainPrerouting)
	for _, iface := range i.lanIfaces {
		had := counts[preroutingJumpSpec(chainDefault, iface)]
		if err := runWithRetry(f.iptablesCmd, "-t", table, "-A", chainPrerouting, "-i", iface, "-j", chainDefault); err != nil {
			logx.Warnf("default route jump on %s: %v", iface, err)
			continue
		}
		for n := 0; n < had; n++ {
			if err := runWithRetry(f.iptablesCmd, "-t", table, "-D", chainPrerouting, "-i", iface, "-j", chainDefault); err != nil {
				logx.Warnf("default route jump reorder on %s (duplicate left in place): %v", iface, err)
				break
			}
		}
	}
	if table != tableMangle || !i.tproxyEnabled {
		return
	}
	existing := make(map[string]bool, len(counts))
	for rule, n := range counts {
		existing[rule] = n > 0
	}
	var udpIfaces []string
	for _, iface := range i.collectRoutedIfaces() {
		if existing[tproxySocketRuleSpecUDP(iface)] {
			udpIfaces = append(udpIfaces, iface)
		}
	}
	ensureUDPSocketDivert(f, existing, udpIfaces)
}

func (i *IptablesManager) removeDefaultLocked(fam defaultFamily) {
	table := fam.applied.table
	if table == "" {
		return
	}
	counts := chainRuleCounts(fam.f.iptablesCmd, table, chainPrerouting)
	for _, iface := range i.lanIfaces {
		for n := counts[preroutingJumpSpec(chainDefault, iface)]; n > 0; n-- {
			if err := runWithRetry(fam.f.iptablesCmd, "-t", table, "-D", chainPrerouting, "-i", iface, "-j", chainDefault); err != nil {
				logx.Errorf("default route jump removal on %s failed, retrying later: %v", iface, err)
				i.setAppliedLocked(fam, table, "")
				return
			}
		}
	}
	tryRun(fam.f.iptablesCmd, "-t", table, "-F", chainDefault)
	tryRun(fam.f.iptablesCmd, "-t", table, "-X", chainDefault)
	logx.Infof("default route removed (%s table=%s)", fam.f.iptablesCmd, table)
	i.setAppliedLocked(fam, "", "")
}

func (i *IptablesManager) resetDefaultLocked(table string, resetV4, resetV6 bool) {
	if resetV4 && (table == "" || i.defaultV4.table == table) {
		i.setAppliedLocked(defaultFamily{familyV4, i.routingV4, &i.defaultV4}, i.defaultV4.table, "")
	}
	if resetV6 && (table == "" || i.defaultV6.table == table) {
		i.setAppliedLocked(defaultFamily{familyV6, i.routingV6, &i.defaultV6}, i.defaultV6.table, "")
	}
}

func (i *IptablesManager) defaultIntact(f ipFamily, table string) bool {
	if !chainExists(f.iptablesCmd, table, chainDefault) {
		return false
	}
	existing := listPreroutingRules(f.iptablesCmd, table)
	for _, iface := range i.lanIfaces {
		if !existing[preroutingJumpSpec(chainDefault, iface)] {
			return false
		}
	}
	return true
}

func probeCtdirSupport(f ipFamily) (supported, conclusive bool) {
	tryRun(f.iptablesCmd, "-t", tableMangle, "-F", defaultProbeChain)
	tryRun(f.iptablesCmd, "-t", tableMangle, "-X", defaultProbeChain)

	if err := runWithRetry(f.iptablesCmd, "-t", tableMangle, "-N", defaultProbeChain); err != nil {
		return false, false
	}
	defer func() {
		tryRun(f.iptablesCmd, "-t", tableMangle, "-F", defaultProbeChain)
		tryRun(f.iptablesCmd, "-t", tableMangle, "-X", defaultProbeChain)
	}()

	if err := runWithRetry(f.iptablesCmd, "-t", tableMangle, "-A", defaultProbeChain,
		"-m", "conntrack", "--ctdir", "ORIGINAL", "-j", "RETURN"); err != nil {
		logx.Warnf("conntrack --ctdir unavailable (%s): replies to inbound port-forwards will also follow the default route: %v", f.iptablesCmd, err)
		return false, true
	}
	return true, true
}

func (i *IptablesManager) ctdirSupportedLocked(f ipFamily) (supported, conclusive bool) {
	cached := &i.ctdirV4
	if f.iptablesCmd == familyV6.iptablesCmd {
		cached = &i.ctdirV6
	}
	if *cached != nil {
		return **cached, true
	}
	supported, conclusive = probeCtdirSupport(f)
	if conclusive {
		*cached = &supported
	}
	return supported, conclusive
}
