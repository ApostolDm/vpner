package network

import (
	"fmt"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/miekg/dns"
)

var (
	ipsetCache   = make(map[string]*IPSet)
	ipsetCacheMu sync.Mutex
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
	ipsetName, err := IpsetName(vpnType, chainName)
	if err != nil {
		return fmt.Errorf("failed to get ipset name for %q: %w", domain, err)
	}
	set, err := obtainOrCreateIPSet(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to prepare ipset %q: %w", ipsetName, err)
	}

	for _, ip := range ips {
		if err := set.AddComment(ip.String(), domain, 20000); err != nil {
			return fmt.Errorf("failed to add IP %s with comment to ipset: %w", ip, err)
		}
	}

	return nil
}

func obtainOrCreateIPSet(name string) (*IPSet, error) {
	ipsetCacheMu.Lock()
	defer ipsetCacheMu.Unlock()

	if set, ok := ipsetCache[name]; ok {
		return set, nil
	}
	set, err := NewIPset(name, "hash:net", &Params{Timeout: DefaultIPSetTimeout, WithComments: true})
	if err != nil {
		return nil, err
	}
	ipsetCache[name] = set
	return set, nil
}

func cleanupDomainEntries(vpnType, chainName, domain string) error {
	if domain == "" {
		return nil
	}
	ipsetName, err := IpsetName(vpnType, chainName)
	if err != nil {
		return err
	}
	return removeEntriesByComment(ipsetName, domain)
}
