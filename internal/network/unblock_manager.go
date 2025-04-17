package network

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const defaultRulesFile = "/opt/etc/vpner/vpner_unblock.yaml"

type VPNRuleSet map[string][]string

type VPNRulesConfig struct {
	Shadowsocks VPNRuleSet `yaml:"Shadowsocks"`
	OpenVPN     VPNRuleSet `yaml:"OpenVPN"`
	Wireguard   VPNRuleSet `yaml:"Wireguard"`
	IKE         VPNRuleSet `yaml:"IKE"`
	SSTP        VPNRuleSet `yaml:"SSTP"`
	PPPOE       VPNRuleSet `yaml:"PPPOE"`
	L2TP        VPNRuleSet `yaml:"L2TP"`
	PPTP        VPNRuleSet `yaml:"PPTP"`
}

func (v *VPNRulesConfig) RuleMap() map[string]*VPNRuleSet {
	ensure := func(set *VPNRuleSet) *VPNRuleSet {
		if *set == nil {
			*set = make(VPNRuleSet)
		}
		return set
	}

	return map[string]*VPNRuleSet{
		"Shadowsocks": ensure(&v.Shadowsocks),
		"OpenVPN":     ensure(&v.OpenVPN),
		"Wireguard":   ensure(&v.Wireguard),
		"IKE":         ensure(&v.IKE),
		"SSTP":        ensure(&v.SSTP),
		"PPPOE":       ensure(&v.PPPOE),
		"L2TP":        ensure(&v.L2TP),
		"PPTP":        ensure(&v.PPTP),
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
	return &UnblockManager{FilePath: path}
}

func (m *UnblockManager) Init() error {
	data, err := m.loadFromFile()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedConf = data
	return nil
}

func (m *UnblockManager) loadFromFile() (*VPNRulesConfig, error) {
	file, err := os.Open(m.FilePath)
	if os.IsNotExist(err) {
		return &VPNRulesConfig{}, nil
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

func (m *UnblockManager) writeConfig(data *VPNRulesConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.OpenFile(m.FilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %v", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()

	if err := encoder.Encode(data); err != nil {
		return err
	}

	m.cachedConf = data
	return nil
}

func (m *UnblockManager) AddRule(vpnType, chainName, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data := m.cachedConf
	rules := data.RuleMap()
	set, ok := rules[vpnType]
	if !ok {
		return fmt.Errorf("unknown VPN type: %s", vpnType)
	}
	(*set)[chainName] = append((*set)[chainName], pattern)

	return m.writeConfig(data)
}

func (m *UnblockManager) DelRule(vpnType, chainName, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data := m.cachedConf
	rules := data.RuleMap()
	set, ok := rules[vpnType]
	if !ok || *set == nil {
		return fmt.Errorf("unknown or empty VPN type: %s", vpnType)
	}

	ruleList, exists := (*set)[chainName]
	if !exists {
		return fmt.Errorf("no rules found for chain: %s", chainName)
	}

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
		return fmt.Errorf("pattern not found in chain: %s", chainName)
	}

	if len(newList) == 0 {
		delete(*set, chainName)
	} else {
		(*set)[chainName] = newList
	}

	return m.writeConfig(data)
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

func (m *UnblockManager) MatchDomain(domain string) (string, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for vpnType, set := range m.cachedConf.RuleMap() {
		if *set == nil {
			continue
		}
		for chain, patterns := range *set {
			for _, pattern := range patterns {
				if matchWildcard(pattern, domain) {
					return vpnType, chain, true
				}
			}
		}
	}
	return "", "", false
}

func matchWildcard(pattern, domain string) bool {
	if !strings.Contains(pattern, "*") {
		return domain == pattern
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(domain, strings.Trim(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(domain, strings.TrimPrefix(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(domain, strings.TrimSuffix(pattern, "*"))
	}
	return false
}