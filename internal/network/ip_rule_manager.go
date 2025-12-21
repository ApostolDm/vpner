package network

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
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
	ipv6Enabled    bool
	ipsetDebug     bool
}

func NewIpRuleManager(unblockManager *UnblockManager, resolver *dohclient.Resolver) *ipRuleManager {
	return &ipRuleManager{
		unblockManager: unblockManager,
		resolver:       resolver,
		ipv6Enabled:    unblockManager != nil && unblockManager.ipv6Enabled,
		ipsetDebug:     unblockManager != nil && unblockManager.ipsetDebug,
	}
}

func (m *ipRuleManager) CheckIPsInIpset(domain string) error {
	vpnType, chainName, rule, ok := m.unblockManager.MatchDomain(domain)
	if !ok {
		return nil
	}
	if err := m.syncDomainIPs(vpnType, chainName, rule, domain, dns.TypeA, false); err != nil {
		return err
	}
	if m.ipv6Enabled {
		if err := m.syncDomainIPs(vpnType, chainName, rule, domain, dns.TypeAAAA, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *ipRuleManager) SyncFromAnswers(domain string, ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}
	vpnType, chainName, rule, ok := m.unblockManager.MatchDomain(domain)
	if !ok {
		return nil
	}
	v4 := filterIPs(ips, false)
	if len(v4) > 0 {
		if err := m.syncResolvedIPs(vpnType, chainName, rule, domain, v4, false); err != nil {
			return err
		}
	}
	if m.ipv6Enabled {
		v6 := filterIPs(ips, true)
		if len(v6) > 0 {
			if err := m.syncResolvedIPs(vpnType, chainName, rule, domain, v6, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func obtainOrCreateIPSetFamily(name, family string) (*IPSet, error) {
	ipsetCacheMu.Lock()
	defer ipsetCacheMu.Unlock()

	if set, ok := ipsetCache[name]; ok {
		return set, nil
	}
	params := &Params{Timeout: DefaultIPSetTimeout, WithComments: true, HashFamily: family}
	set, err := NewIPset(name, "hash:net", params)
	if err != nil {
		return nil, err
	}
	ipsetCache[name] = set
	return set, nil
}

func cleanupDomainEntries(vpnType, chainName, pattern string, ipv6Enabled bool, ipsetDebug bool) error {
	if pattern == "" {
		return nil
	}
	if err := cleanupDomainEntriesForSet(vpnType, chainName, pattern, false, ipsetDebug); err != nil {
		return err
	}
	if err := cleanupDomainEntriesForSet(vpnType, chainName, pattern, true, ipsetDebug); err != nil {
		if ipv6Enabled {
			return err
		}
	}
	return nil
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

func (m *ipRuleManager) syncDomainIPs(vpnType, chainName, rule, domain string, qtype uint16, ipv6 bool) error {
	ips, err := m.resolver.ResolveDomain(domain, qtype)
	if err != nil {
		if !isNoRecordsError(err) {
			return fmt.Errorf("failed to resolve domain %q: %w", domain, err)
		}
		ips = nil
	}
	resolved := filterIPs(ips, ipv6)
	if len(resolved) == 0 {
		return nil
	}
	return m.syncResolvedIPs(vpnType, chainName, rule, domain, resolved, ipv6)
}

func (m *ipRuleManager) syncResolvedIPs(vpnType, chainName, rule, domain string, resolved []string, ipv6 bool) error {
	var (
		ipsetName string
		family    string
	)
	if ipv6 {
		var err error
		ipsetName, err = IpsetName6(vpnType, chainName)
		if err != nil {
			return fmt.Errorf("failed to get ipv6 ipset name for %q: %w", domain, err)
		}
		family = "inet6"
	} else {
		var err error
		ipsetName, err = IpsetName(vpnType, chainName)
		if err != nil {
			return fmt.Errorf("failed to get ipset name for %q: %w", domain, err)
		}
		family = "inet"
	}

	set, err := obtainOrCreateIPSetFamily(ipsetName, family)
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
	for _, entry := range legacy {
		if m.ipsetDebug {
			logging.Infof("ipset del: set=%s entry=%s reason=legacy-comment domain=%s rule=%s", ipsetName, entry, domain, rule)
		}
	}
	if err := removeEntries(ipsetName, legacy); err != nil {
		return fmt.Errorf("failed to cleanup legacy ipset entries for %q: %w", domain, err)
	}

	resolvedSet := make(map[string]struct{}, len(resolved))
	for _, ip := range resolved {
		resolvedSet[ip] = struct{}{}
	}
	existingSet := make(map[string]struct{}, len(existing))
	for _, entry := range existing {
		existingSet[entry] = struct{}{}
	}

	for ip := range resolvedSet {
		if _, ok := existingSet[ip]; ok {
			continue
		}
		if m.ipsetDebug {
			logging.Infof("ipset add: set=%s entry=%s reason=resolved domain=%s rule=%s", ipsetName, ip, domain, rule)
		}
		if err := set.AddComment(ip, comment, 0); err != nil {
			return fmt.Errorf("failed to add IP %s with comment to ipset: %w", ip, err)
		}
	}
	for _, entry := range existing {
		if _, ok := resolvedSet[entry]; ok {
			continue
		}
		if m.ipsetDebug {
			logging.Infof("ipset del: set=%s entry=%s reason=stale-resolve domain=%s rule=%s", ipsetName, entry, domain, rule)
		}
		if err := set.Del(entry); err != nil {
			return fmt.Errorf("failed to delete stale IP %s from ipset: %w", entry, err)
		}
	}

	return nil
}

func cleanupDomainEntriesForSet(vpnType, chainName, pattern string, ipv6 bool, ipsetDebug bool) error {
	var ipsetName string
	var err error
	if ipv6 {
		ipsetName, err = IpsetName6(vpnType, chainName)
	} else {
		ipsetName, err = IpsetName(vpnType, chainName)
	}
	if err != nil {
		return err
	}
	prefixed, err := entriesByCommentPrefix(ipsetName, ruleCommentPrefix(pattern))
	if err != nil {
		return err
	}
	for _, entry := range prefixed {
		if ipsetDebug {
			logging.Infof("ipset del: set=%s entry=%s reason=rule-delete rule=%s", ipsetName, entry, pattern)
		}
	}
	if err := removeEntries(ipsetName, prefixed); err != nil {
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
	for _, entry := range stale {
		if ipsetDebug {
			logging.Infof("ipset del: set=%s entry=%s reason=rule-delete-legacy rule=%s", ipsetName, entry, pattern)
		}
	}
	return removeEntries(ipsetName, stale)
}

func filterIPs(ips []net.IP, ipv6 bool) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ipv6 {
			if ip.To4() != nil {
				continue
			}
		} else if ip.To4() == nil {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}
