package network

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/logging"
	"github.com/ApostolDmitry/vpner/internal/patterns"
	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
	"gopkg.in/yaml.v3"
)

const defaultRulesFile = "/opt/etc/vpner/vpner_unblock.yaml"

type VPNRuleSet map[string][]string

type VPNRulesConfig struct {
	Rules map[string]VPNRuleSet `yaml:",inline"`
}

func newVPNRulesConfig() *VPNRulesConfig {
	return &VPNRulesConfig{Rules: make(map[string]VPNRuleSet)}
}

func (v *VPNRulesConfig) ensure() {
	if v == nil {
		return
	}
	if v.Rules == nil {
		v.Rules = make(map[string]VPNRuleSet)
	}
}

func (v *VPNRulesConfig) ensureSet(vpnType string) (VPNRuleSet, bool) {
	if !vpntypes.IsKnown(vpnType) {
		return nil, false
	}
	v.ensure()
	set, ok := v.Rules[vpnType]
	if !ok || set == nil {
		set = make(VPNRuleSet)
		v.Rules[vpnType] = set
	}
	return set, true
}

func (v *VPNRulesConfig) lookupSet(vpnType string) (VPNRuleSet, bool) {
	if v == nil {
		return nil, false
	}
	v.ensure()
	set, ok := v.Rules[vpnType]
	if !ok || set == nil {
		return nil, false
	}
	return set, true
}

func (v *VPNRulesConfig) Clone() *VPNRulesConfig {
	if v == nil {
		return newVPNRulesConfig()
	}
	v.ensure()
	out := newVPNRulesConfig()
	for vpnType, set := range v.Rules {
		cloneSet := make(VPNRuleSet, len(set))
		for chainName, rules := range set {
			cloneSet[chainName] = append([]string(nil), rules...)
		}
		out.Rules[vpnType] = cloneSet
	}
	return out
}

type UnblockManager struct {
	FilePath          string
	cachedConf        *VPNRulesConfig
	registry          *IPSetRegistry
	mu                sync.RWMutex
	ipv6Enabled       bool
	ipsetDebug        bool
	ipsetStaleQueries int
}

func NewUnblockManager(path string, ipv6Enabled bool, ipsetDebug bool, ipsetStaleQueries int, registry *IPSetRegistry) *UnblockManager {
	if path == "" {
		path = defaultRulesFile
	}
	if registry == nil {
		registry = NewIPSetRegistry()
	}
	return &UnblockManager{
		FilePath:          path,
		cachedConf:        newVPNRulesConfig(),
		registry:          registry,
		ipv6Enabled:       ipv6Enabled,
		ipsetDebug:        ipsetDebug,
		ipsetStaleQueries: ipsetStaleQueries,
	}
}

func (m *UnblockManager) Init() error {
	data, err := m.loadFromFile()
	if err != nil {
		return err
	}
	if data != nil {
		m.mu.Lock()
		m.cachedConf = data
		m.mu.Unlock()
	}
	return m.restoreStaticRules()
}

func (m *UnblockManager) loadFromFile() (*VPNRulesConfig, error) {
	file, err := os.Open(m.FilePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	config := newVPNRulesConfig()
	if err := yaml.NewDecoder(file).Decode(config); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	config.ensure()
	return config, nil
}

func (m *UnblockManager) writeConfig() error {
	file, err := os.OpenFile(m.FilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if err := yaml.NewEncoder(file).Encode(m.cachedConf); err != nil {
		return fmt.Errorf("failed to write YAML: %w", err)
	}
	return nil
}

func (m *UnblockManager) AddRule(vpnType, chainName, pattern string) error {
	if isStaticPattern(pattern) && isIPv6Pattern(pattern) && !m.ipv6Enabled {
		return fmt.Errorf("ipv6 support is disabled")
	}

	m.mu.Lock()
	set, ok := m.cachedConf.ensureSet(vpnType)
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown VPN type: %s", vpnType)
	}
	set[chainName] = append(set[chainName], pattern)
	err := m.writeConfig()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if isStaticPattern(pattern) {
		return m.applyStaticEntry(vpnType, chainName, pattern, true)
	}
	return nil
}

func (m *UnblockManager) DelRule(vpnType, chainName, pattern string) error {
	m.mu.Lock()
	set, ok := m.cachedConf.lookupSet(vpnType)
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown or empty VPN type: %s", vpnType)
	}

	ruleList, exists := set[chainName]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("no rules found for chain: %s", chainName)
	}

	isStatic := isStaticPattern(pattern)
	newList := ruleList[:0]
	removed := false
	for _, r := range ruleList {
		if r == pattern {
			removed = true
			continue
		}
		newList = append(newList, r)
	}

	if !removed {
		m.mu.Unlock()
		return fmt.Errorf("pattern not found in chain: %s", chainName)
	}

	if len(newList) == 0 {
		delete(set, chainName)
	} else {
		set[chainName] = newList
	}
	if len(set) == 0 {
		delete(m.cachedConf.Rules, vpnType)
	}

	err := m.writeConfig()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if isStatic {
		return m.applyStaticEntry(vpnType, chainName, pattern, false)
	}
	if err := cleanupDomainEntries(m.registry, vpnType, chainName, pattern, m.ipv6Enabled, m.ipsetDebug); err != nil {
		logging.Warnf("cleanup ipset entries for %s/%s failed: %v", vpnType, chainName, err)
	}
	return nil
}

func (m *UnblockManager) DelChain(vpnType, chainName string) error {
	m.mu.Lock()
	set, ok := m.cachedConf.lookupSet(vpnType)
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown or empty VPN type: %s", vpnType)
	}
	entries, exists := set[chainName]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("chain not found: %s", chainName)
	}
	delete(set, chainName)
	if len(set) == 0 {
		delete(m.cachedConf.Rules, vpnType)
	}
	entries = append([]string(nil), entries...)
	err := m.writeConfig()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if isStaticPattern(entry) {
			if err := m.applyStaticEntry(vpnType, chainName, entry, false); err != nil {
				return err
			}
		} else {
			if err := cleanupDomainEntries(m.registry, vpnType, chainName, entry, m.ipv6Enabled, m.ipsetDebug); err != nil {
				logging.Warnf("cleanup ipset entries for %s/%s failed: %v", vpnType, chainName, err)
			}
		}
	}
	return nil
}

func (m *UnblockManager) GetRules(vpnType, chainName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	set, ok := m.cachedConf.lookupSet(vpnType)
	if !ok {
		return nil, fmt.Errorf("unknown VPN type: %s", vpnType)
	}
	return append([]string(nil), set[chainName]...), nil
}

func (m *UnblockManager) GetAllRules() (*VPNRulesConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedConf.Clone(), nil
}

func (m *UnblockManager) MatchDomain(domain string) (string, string, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for vpnType, set := range m.cachedConf.Rules {
		for chain, rules := range set {
			for _, pattern := range rules {
				if patterns.Match(pattern, domain) {
					return vpnType, chain, pattern, true
				}
			}
		}
	}
	return "", "", "", false
}

func (m *UnblockManager) IPv6Enabled() bool {
	return m != nil && m.ipv6Enabled
}

func (m *UnblockManager) IPSetDebug() bool {
	return m != nil && m.ipsetDebug
}

func (m *UnblockManager) IPSetStaleQueries() int {
	if m == nil {
		return 0
	}
	return m.ipsetStaleQueries
}

func (m *UnblockManager) restoreStaticRules() error {
	entries := m.staticRulesSnapshot()
	for _, entry := range entries {
		if err := m.applyStaticEntry(entry.vpnType, entry.chain, entry.value, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *UnblockManager) staticRulesSnapshot() []ruleRef {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []ruleRef
	for vpnType, set := range m.cachedConf.Rules {
		for chain, rules := range set {
			for _, pattern := range rules {
				if isStaticPattern(pattern) {
					out = append(out, ruleRef{vpnType: vpnType, chain: chain, value: pattern})
				}
			}
		}
	}
	return out
}

func (m *UnblockManager) applyStaticEntry(vpnType, chainName, pattern string, add bool) error {
	if !isStaticPattern(pattern) {
		return nil
	}
	isV6 := isIPv6Pattern(pattern)
	if isV6 && !m.ipv6Enabled {
		if add {
			logging.Warnf("skip ipv6 rule %s/%s: ipv6 disabled", vpnType, chainName)
		}
		return nil
	}

	var (
		ipsetName string
		set       *IPSet
		err       error
	)
	if isV6 {
		ipsetName, err = IpsetName6(vpnType, chainName)
		if err != nil {
			return err
		}
		set, err = m.registry.ObtainOrCreateFamily(ipsetName, "inet6")
	} else {
		ipsetName, err = IpsetName(vpnType, chainName)
		if err != nil {
			return err
		}
		set, err = m.registry.ObtainOrCreateFamily(ipsetName, "inet")
	}
	if err != nil {
		return err
	}
	if add {
		if m.ipsetDebug {
			logging.Infof("ipset add: set=%s entry=%s reason=static-rule vpn=%s chain=%s", ipsetName, pattern, vpnType, chainName)
		}
		return set.Add(pattern, 0)
	}
	if m.ipsetDebug {
		logging.Infof("ipset del: set=%s entry=%s reason=static-rule-delete vpn=%s chain=%s", ipsetName, pattern, vpnType, chainName)
	}
	return set.Del(pattern)
}

type ruleRef struct {
	vpnType string
	chain   string
	value   string
}

func isStaticPattern(value string) bool {
	return patterns.IsIP(value) || patterns.IsCIDR(value)
}

func isIPv6Pattern(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.To4() == nil
	}
	if _, netw, err := net.ParseCIDR(value); err == nil {
		return netw.IP.To4() == nil
	}
	return false
}
