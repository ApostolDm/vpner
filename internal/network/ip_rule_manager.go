package network

import (
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/miekg/dns"
)


type ipRuleManager struct {
	unblockManager *UnblockManager
	resolver       *dohclient.Resolver
}

func NewIpRuleManager(unblockManager *UnblockManager, resolver *dohclient.Resolver) *ipRuleManager {
	return &ipRuleManager{
		unblockManager: unblockManager,
		resolver:       resolver,
	}
}

func (m *ipRuleManager) CheckIPsInIpset(domain string) error {
	vpnType, chainName, ok := m.unblockManager.MatchDomain(domain)
	if !ok {
		return nil
	}
	ips, err := m.resolver.ResolveDomain(domain, dns.TypeA)
	if err != nil {
		return fmt.Errorf("failed to resolve domain %q: %w", domain, err)
	}
	if len(ips) == 0 {
		return nil
	}
	ipsetName, err := utils.GetIpsetName(vpnType, chainName)
	if err != nil {
		return fmt.Errorf("failed to get ipset name for %q: %w", domain, err)
	}
	set, err := NewIPset(ipsetName, "hash:ip", &Params{})
	if err != nil {
		return fmt.Errorf("failed to create ipset %q: %w", ipsetName, err)
	}

	for _, ip := range ips {
		if err := set.Add(ip.String(), 20000); err != nil {
			return fmt.Errorf("failed to add IP %s with comment to ipset: %w", ip, err)
		}
	}

	return nil
}
