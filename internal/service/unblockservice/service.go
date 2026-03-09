package unblockservice

import (
	"fmt"
	"sort"

	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/patterns"
	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
)

type InterfaceLookup interface {
	LookupTrackedType(name string) (string, bool)
}

type XrayLookup interface {
	IsChain(name string) bool
}

type RuleGroup struct {
	TypeName  string
	ChainName string
	Rules     []string
}

type Service struct {
	manager    *network.UnblockManager
	interfaces InterfaceLookup
	xrays      XrayLookup
}

func New(manager *network.UnblockManager, interfaces InterfaceLookup, xrays XrayLookup) *Service {
	return &Service{
		manager:    manager,
		interfaces: interfaces,
		xrays:      xrays,
	}
}

func (s *Service) Init() error {
	if s == nil || s.manager == nil {
		return fmt.Errorf("unblock service is not initialized")
	}
	return s.manager.Init()
}

func (s *Service) List() ([]RuleGroup, error) {
	conf, err := s.manager.GetAllRules()
	if err != nil {
		return nil, err
	}

	var result []RuleGroup
	for vpnType, set := range conf.Rules {
		for chainName, rules := range set {
			result = append(result, RuleGroup{
				TypeName:  vpnType,
				ChainName: chainName,
				Rules:     append([]string(nil), rules...),
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].TypeName == result[j].TypeName {
			return result[i].ChainName < result[j].ChainName
		}
		return result[i].TypeName < result[j].TypeName
	})

	return result, nil
}

func (s *Service) AddRule(chainName, pattern string) error {
	if chainName == "" {
		return fmt.Errorf("chain name is required")
	}
	if err := patterns.Validate(pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	vpnType, exists := s.resolveChainType(chainName)
	if !exists {
		return fmt.Errorf("chain name %q does not exist", chainName)
	}

	allRules, err := s.manager.GetAllRules()
	if err != nil {
		return fmt.Errorf("failed to load existing rules: %w", err)
	}
	for typ, set := range allRules.Rules {
		for existingChain, rules := range set {
			for _, existing := range rules {
				if patterns.Overlap(existing, pattern) {
					return fmt.Errorf(
						"new rule %q overlaps with existing rule %q in [%s/%s]",
						pattern,
						existing,
						typ,
						existingChain,
					)
				}
			}
		}
	}

	if err := s.manager.AddRule(vpnType, chainName, pattern); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	return nil
}

func (s *Service) DeleteRule(pattern string) error {
	if err := patterns.Validate(pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	vpnType, chainName, _, exists := s.manager.MatchDomain(pattern)
	if !exists {
		return fmt.Errorf("rule does not exist")
	}
	if err := s.manager.DelRule(vpnType, chainName, pattern); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}
	return nil
}

func (s *Service) DeleteChain(vpnType, chainName string) error {
	if err := s.manager.DelChain(vpnType, chainName); err != nil {
		return fmt.Errorf("failed to delete chain rules: %w", err)
	}
	return nil
}

func (s *Service) MatchDomain(domain string) (string, string, string, bool) {
	return s.manager.MatchDomain(domain)
}

func (s *Service) RuntimeOptions() network.RuleRuntimeOptions {
	return network.RuleRuntimeOptions{
		IPv6Enabled:       s.manager.IPv6Enabled(),
		IPSetDebug:        s.manager.IPSetDebug(),
		IPSetStaleQueries: s.manager.IPSetStaleQueries(),
	}
}

func (s *Service) resolveChainType(chainName string) (string, bool) {
	if s.xrays != nil && s.xrays.IsChain(chainName) {
		return vpntypes.Xray.String(), true
	}
	if s.interfaces == nil {
		return "", false
	}
	return s.interfaces.LookupTrackedType(chainName)
}
