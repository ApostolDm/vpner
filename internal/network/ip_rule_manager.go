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
	ipsetCache       = make(map[string]*IPSet)
	ipsetCacheMu     sync.Mutex
	ipsetStaleCounts = make(map[string]map[string]int)
	ipsetStaleMu     sync.Mutex
)

const (
	ipsetCommentPrefix     = "vpner|rule="
	ipsetCommentDomainPart = "|domain="
)

type ipRuleManager struct {
	unblockManager    *UnblockManager
	resolver          *dohclient.Resolver
	ipv6Enabled       bool
	ipsetDebug        bool
	ipsetStaleQueries int
}

func NewIpRuleManager(unblockManager *UnblockManager, resolver *dohclient.Resolver) *ipRuleManager {
	return &ipRuleManager{
		unblockManager: unblockManager,
		resolver:       resolver,
		ipv6Enabled:    unblockManager != nil && unblockManager.ipv6Enabled,
		ipsetDebug:     unblockManager != nil && unblockManager.ipsetDebug,
		ipsetStaleQueries: func() int {
			if unblockManager != nil {
				return unblockManager.ipsetStaleQueries
			}
			return 0
		}(),
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

type staleEntry struct {
	entry  string
	misses int
}

func buildStaleKey(ipsetName, comment string) string {
	return ipsetName + "|" + comment
}

func clearStaleCountsForRule(ipsetName, pattern string) {
	prefix := buildStaleKey(ipsetName, ruleCommentPrefix(pattern))
	ipsetStaleMu.Lock()
	defer ipsetStaleMu.Unlock()

	for key := range ipsetStaleCounts {
		if strings.HasPrefix(key, prefix) {
			delete(ipsetStaleCounts, key)
		}
	}
}

func collectStaleEntries(key string, existing []string, resolved map[string]struct{}, threshold int) []staleEntry {
	if threshold <= 0 {
		return nil
	}

	ipsetStaleMu.Lock()
	defer ipsetStaleMu.Unlock()

	counts, ok := ipsetStaleCounts[key]
	if !ok {
		counts = make(map[string]int)
		ipsetStaleCounts[key] = counts
	}

	for ip := range resolved {
		counts[ip] = 0
	}

	existingSet := make(map[string]struct{}, len(existing))
	var stale []staleEntry
	for _, entry := range existing {
		existingSet[entry] = struct{}{}
		if _, ok := resolved[entry]; ok {
			counts[entry] = 0
			continue
		}
		counts[entry]++
		if counts[entry] >= threshold {
			stale = append(stale, staleEntry{entry: entry, misses: counts[entry]})
			delete(counts, entry)
		}
	}

	for ip := range counts {
		if _, ok := existingSet[ip]; ok {
			continue
		}
		if _, ok := resolved[ip]; ok {
			continue
		}
		delete(counts, ip)
	}
	if len(counts) == 0 {
		delete(ipsetStaleCounts, key)
	}

	return stale
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
	if m.ipsetStaleQueries > 0 {
		stale := collectStaleEntries(buildStaleKey(ipsetName, comment), existing, resolvedSet, m.ipsetStaleQueries)
		for _, entry := range stale {
			if m.ipsetDebug {
				logging.Infof("ipset del: set=%s entry=%s reason=stale-miss misses=%d threshold=%d domain=%s rule=%s", ipsetName, entry.entry, entry.misses, m.ipsetStaleQueries, domain, rule)
			}
			if err := set.Del(entry.entry); err != nil {
				return fmt.Errorf("failed to delete stale IP %s from ipset: %w", entry.entry, err)
			}
		}
	} else {
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
	clearStaleCountsForRule(ipsetName, pattern)
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
