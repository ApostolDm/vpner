package network

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/common/patterns"
	"gopkg.in/yaml.v3"
)

const defaultRulesFile = "/opt/etc/vpner/vpner_unblock.yaml"

type VPNRuleSet map[string][]string

type VPNRulesConfig struct {
	Xray      VPNRuleSet `yaml:"Xray"`
	OpenVPN   VPNRuleSet `yaml:"OpenVPN"`
	Wireguard VPNRuleSet `yaml:"Wireguard"`
	IKE       VPNRuleSet `yaml:"IKE"`
	SSTP      VPNRuleSet `yaml:"SSTP"`
	PPPOE     VPNRuleSet `yaml:"PPPOE"`
	L2TP      VPNRuleSet `yaml:"L2TP"`
	PPTP      VPNRuleSet `yaml:"PPTP"`
}

func (v *VPNRulesConfig) RuleMap() map[string]*VPNRuleSet {
	ensure := func(set *VPNRuleSet) *VPNRuleSet {
		if *set == nil {
			*set = make(VPNRuleSet)
		}
		return set
	}

	return map[string]*VPNRuleSet{
		"Xray":      ensure(&v.Xray),
		"OpenVPN":   ensure(&v.OpenVPN),
		"Wireguard": ensure(&v.Wireguard),
		"IKE":       ensure(&v.IKE),
		"SSTP":      ensure(&v.SSTP),
		"PPPOE":     ensure(&v.PPPOE),
		"L2TP":      ensure(&v.L2TP),
		"PPTP":      ensure(&v.PPTP),
	}
}

type UnblockManager struct {
	FilePath   string
	cachedConf *VPNRulesConfig
	mu         sync.RWMutex
}

func NewUnblockManager(path string) *UnblockManager {
	if path == "" {
		path = defaultRulesFile
	}
	return &UnblockManager{
		FilePath:   path,
		cachedConf: &VPNRulesConfig{},
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

	var config VPNRulesConfig
	if err := yaml.NewDecoder(file).Decode(&config); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return &config, nil
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
	m.mu.Lock()
	rules := m.cachedConf.RuleMap()
	set, ok := rules[vpnType]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown VPN type: %s", vpnType)
	}
	(*set)[chainName] = append((*set)[chainName], pattern)
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
	rules := m.cachedConf.RuleMap()
	set, ok := rules[vpnType]
	if !ok || *set == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown or empty VPN type: %s", vpnType)
	}

	ruleList, exists := (*set)[chainName]
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
		delete(*set, chainName)
	} else {
		(*set)[chainName] = newList
	}

	err := m.writeConfig()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if isStatic {
		return m.applyStaticEntry(vpnType, chainName, pattern, false)
	}
	if err := cleanupDomainEntries(vpnType, chainName, pattern); err != nil {
		logging.Warnf("cleanup ipset entries for %s/%s failed: %v", vpnType, chainName, err)
	}
	return nil
}

func (m *UnblockManager) DelChain(vpnType, chainName string) error {
	m.mu.Lock()
	rules := m.cachedConf.RuleMap()
	set, ok := rules[vpnType]
	if !ok || *set == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown or empty VPN type: %s", vpnType)
	}
	entries, exists := (*set)[chainName]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("chain not found: %s", chainName)
	}
	delete(*set, chainName)
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
			if err := cleanupDomainEntries(vpnType, chainName, entry); err != nil {
				logging.Warnf("cleanup ipset entries for %s/%s failed: %v", vpnType, chainName, err)
			}
		}
	}
	return nil
}

func (m *UnblockManager) GetRules(vpnType, chainName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data := m.cachedConf
	rules := data.RuleMap()
	set, ok := rules[vpnType]
	if !ok || *set == nil {
		return nil, fmt.Errorf("unknown VPN type: %s", vpnType)
	}
	return (*set)[chainName], nil
}

func (m *UnblockManager) GetAllRules() (*VPNRulesConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedConf, nil
}

func (m *UnblockManager) MatchDomain(domain string) (string, string, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for vpnType, set := range m.cachedConf.RuleMap() {
		if *set == nil {
			continue
		}
		for chain, rules := range *set {
			for _, pattern := range rules {
				if patterns.Match(pattern, domain) {
					return vpnType, chain, pattern, true
				}
			}
		}
	}
	return "", "", "", false
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
	for vpnType, set := range m.cachedConf.RuleMap() {
		if *set == nil {
			continue
		}
		for chain, rules := range *set {
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
	ipsetName, err := IpsetName(vpnType, chainName)
	if err != nil {
		return err
	}
	set, err := obtainOrCreateIPSet(ipsetName)
	if err != nil {
		return err
	}
	if add {
		return set.Add(pattern, 0)
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
