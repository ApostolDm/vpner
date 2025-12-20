package network

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/common/patterns"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/miekg/dns"
)

var (
	ipsetCache   = make(map[string]*IPSet)
	ipsetCacheMu sync.Mutex
)

const (
	ipsetCommentPrefix     = "vpner|rule="
	ipsetCommentDomainPart = "|domain="
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
	vpnType, chainName, rule, ok := m.unblockManager.MatchDomain(domain)
	if !ok {
		return nil
	}
	ips, err := m.resolver.ResolveDomain(domain, dns.TypeA)
	if err != nil {
		if !isNoRecordsError(err) {
			return fmt.Errorf("failed to resolve domain %q: %w", domain, err)
		}
		ips = nil
	}
	ipsetName, err := IpsetName(vpnType, chainName)
	if err != nil {
		return fmt.Errorf("failed to get ipset name for %q: %w", domain, err)
	}
	set, err := obtainOrCreateIPSet(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to prepare ipset %q: %w", ipsetName, err)
	}

	comment := buildRuleComment(rule, domain)
	entries, err := listEntriesWithComments(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to list ipset entries for %q: %w", domain, err)
	}
	var existing []string
	var legacy []string
	for _, entry := range entries {
		switch entry.Comment {
		case comment:
			existing = append(existing, entry.Entry)
		case domain:
			legacy = append(legacy, entry.Entry)
		}
	}
	if err := removeEntries(ipsetName, legacy); err != nil {
		return fmt.Errorf("failed to cleanup legacy ipset entries for %q: %w", domain, err)
	}

	resolved := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		resolved[ip.String()] = struct{}{}
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, entry := range existing {
		existingSet[entry] = struct{}{}
	}

	for ip := range resolved {
		if _, ok := existingSet[ip]; ok {
			continue
		}
		if err := set.AddComment(ip, comment, 0); err != nil {
			return fmt.Errorf("failed to add IP %s with comment to ipset: %w", ip, err)
		}
	}
	for _, entry := range existing {
		if _, ok := resolved[entry]; ok {
			continue
		}
		if err := set.Del(entry); err != nil {
			return fmt.Errorf("failed to delete stale IP %s from ipset: %w", entry, err)
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

func cleanupDomainEntries(vpnType, chainName, pattern string) error {
	if pattern == "" {
		return nil
	}
	ipsetName, err := IpsetName(vpnType, chainName)
	if err != nil {
		return err
	}
	if err := removeEntriesByCommentPrefix(ipsetName, ruleCommentPrefix(pattern)); err != nil {
		return err
	}
	entries, err := listEntriesWithComments(ipsetName)
	if err != nil {
		return err
	}
	var stale []string
	for _, entry := range entries {
		if entry.Comment == "" || strings.HasPrefix(entry.Comment, ipsetCommentPrefix) {
			continue
		}
		if patterns.Match(pattern, entry.Comment) {
			stale = append(stale, entry.Entry)
		}
	}
	return removeEntries(ipsetName, stale)
}

func buildRuleComment(rule, domain string) string {
	return ipsetCommentPrefix + rule + ipsetCommentDomainPart + domain
}

func ruleCommentPrefix(rule string) string {
	return ipsetCommentPrefix + rule + ipsetCommentDomainPart
}

func isNoRecordsError(err error) bool {
	return strings.Contains(err.Error(), "no A/AAAA records found")
}
