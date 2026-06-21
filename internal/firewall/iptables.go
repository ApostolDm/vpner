package firewall

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

type vpnRoutingInfo struct {
	VPNType   vpnkind.Kind
	Mark      int
	TableID   int
	Dev       string
	ChainName string
	Table     string
	Port      int
	Ifaces    []string
	JumpRules []jumpRule
}

type jumpRule struct {
	Cmd  string
	Args []string
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
	ipFlags         []string
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
	ipInfraReady  bool
}

type ChainSpec struct {
	IPSetName string
	Port      int
	Ifaces    []string
}

const (
	tableNat        = "nat"
	tableMangle     = "mangle"
	chainPrerouting = "PREROUTING"

	tproxyMark    = "200"
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

func tryRun(name string, args ...string) {
	if err := run(name, args...); err != nil {
		logx.Debugf("network: best-effort cleanup failed: %v", err)
	}
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func NewIptablesManager(ipv6Enabled, tproxyEnabled bool) *IptablesManager {
	return &IptablesManager{
		routingV4:     make(map[string]vpnRoutingInfo),
		routingV6:     make(map[string]vpnRoutingInfo),
		ipv6Enabled:   ipv6Enabled,
		tproxyEnabled: tproxyEnabled,
	}
}

func (i *IptablesManager) CleanupStaleState() {
	i.cleanupFamily(familyV4)
	if i.ipv6Enabled || commandExists(familyV6.iptablesSaveCmd) {
		i.cleanupFamily(familyV6)
	}
}

func isSupportedVPNType(vpnType vpnkind.Kind) bool {
	return vpnkind.IsKnown(vpnType.String())
}
