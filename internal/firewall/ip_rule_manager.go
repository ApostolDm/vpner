package firewall

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/matcher"
	"github.com/ApostolDmitry/vpner/internal/resolver"
	"github.com/miekg/dns"
)

const (
	ipsetCommentPrefix     = "vpner|rule="
	ipsetCommentDomainPart = "|domain="
)

type DomainRuleMatcher interface {
	MatchDomain(domain string) (vpnType string, chainName string, rule string, ok bool)
}

type RuleRuntimeOptions struct {
	IPv6Enabled       bool
	IPSetDebug        bool
	IPSetStaleQueries int
}

type IpRuleManager struct {
	matcher           DomainRuleMatcher
	resolver          *resolver.Upstream
	registry          *IPSetRegistry
	ipv6Enabled       bool
	ipsetDebug        bool
	ipsetStaleQueries int
}

func NewIpRuleManager(matcher DomainRuleMatcher, opts RuleRuntimeOptions, resolver *resolver.Upstream, registry *IPSetRegistry) *IpRuleManager {
	if registry == nil {
		registry = NewIPSetRegistry()
	}
	return &IpRuleManager{
		matcher:           matcher,
		resolver:          resolver,
		registry:          registry,
		ipv6Enabled:       opts.IPv6Enabled,
		ipsetDebug:        opts.IPSetDebug,
		ipsetStaleQueries: opts.IPSetStaleQueries,
	}
}

func (m *IpRuleManager) CheckIPsInIpset(domain string) error {
	if m.matcher == nil {
		return nil
	}
	vpnType, chainName, rule, ok := m.matcher.MatchDomain(domain)
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

func (m *IpRuleManager) SyncFromAnswers(domain string, ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}
	if m.matcher == nil {
		return nil
	}
	vpnType, chainName, rule, ok := m.matcher.MatchDomain(domain)
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

func cleanupDomainEntries(registry *IPSetRegistry, vpnType, chainName, pattern string, ipv6Enabled bool, ipsetDebug bool) error {
	if pattern == "" {
		return nil
	}
	if err := cleanupDomainEntriesForSet(registry, vpnType, chainName, pattern, false, ipsetDebug); err != nil {
		return err
	}
	if err := cleanupDomainEntriesForSet(registry, vpnType, chainName, pattern, true, ipsetDebug); err != nil {
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

func (m *IpRuleManager) syncDomainIPs(vpnType, chainName, rule, domain string, qtype uint16, ipv6 bool) error {
	ips, err := m.resolver.ResolveDomain(domain, qtype)
	if err != nil {
		if !errors.Is(err, resolver.ErrNoRecords) {
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

func ipsetNameForFamily(vpnType, chainName string, ipv6 bool) (name, family string, err error) {
	if ipv6 {
		name, err = IpsetName6(vpnType, chainName)
		return name, "inet6", err
	}
	name, err = IpsetName(vpnType, chainName)
	return name, "inet", err
}

func (m *IpRuleManager) syncResolvedIPs(vpnType, chainName, rule, domain string, resolved []string, ipv6 bool) error {
	ipsetName, family, err := ipsetNameForFamily(vpnType, chainName, ipv6)
	if err != nil {
		return fmt.Errorf("failed to get ipset name for %q: %w", domain, err)
	}

	unlock := m.registry.LockSet(ipsetName)
	defer unlock()

	set, err := m.registry.ObtainOrCreateFamily(ipsetName, family)
	if err != nil {
		return fmt.Errorf("failed to prepare ipset %q: %w", ipsetName, err)
	}

	comment := buildRuleComment(rule, domain)
	entries, err := listEntriesWithComments(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to list ipset entries for %q: %w", domain, err)
	}
	var existing, legacy []string
	for _, entry := range entries {
		switch entry.Comment {
		case comment:
			existing = append(existing, entry.Entry)
		case domain:
			legacy = append(legacy, entry.Entry)
		}
	}

	var errs []error

	if m.ipsetDebug {
		for _, entry := range legacy {
			logx.Infof("ipset del: set=%s entry=%s reason=legacy-comment domain=%s rule=%s", ipsetName, entry, domain, rule)
		}
	}
	if err := removeEntries(ipsetName, legacy); err != nil {
		errs = append(errs, fmt.Errorf("cleanup legacy entries: %w", err))
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
			logx.Infof("ipset add: set=%s entry=%s reason=resolved domain=%s rule=%s", ipsetName, ip, domain, rule)
		}
		if err := set.AddComment(ip, comment, 0); err != nil {
			errs = append(errs, fmt.Errorf("add %s: %w", ip, err))
		}
	}

	if m.ipsetStaleQueries > 0 {
		key := buildStaleKey(ipsetName, comment)
		stale := m.registry.CollectStaleEntries(key, existing, resolvedSet, m.ipsetStaleQueries)
		var deleted []string
		for _, entry := range stale {
			if m.ipsetDebug {
				logx.Infof("ipset del: set=%s entry=%s reason=stale-miss misses=%d threshold=%d domain=%s rule=%s", ipsetName, entry.entry, entry.misses, m.ipsetStaleQueries, domain, rule)
			}
			if err := set.Del(entry.entry); err != nil {
				errs = append(errs, fmt.Errorf("del %s: %w", entry.entry, err))
				continue
			}
			deleted = append(deleted, entry.entry)
		}

		m.registry.ConfirmStaleDeleted(key, deleted)
	} else {
		for _, entry := range existing {
			if _, ok := resolvedSet[entry]; ok {
				continue
			}
			if m.ipsetDebug {
				logx.Infof("ipset del: set=%s entry=%s reason=stale-resolve domain=%s rule=%s", ipsetName, entry, domain, rule)
			}
			if err := set.Del(entry); err != nil {
				errs = append(errs, fmt.Errorf("del %s: %w", entry, err))
			}
		}
	}

	return errors.Join(errs...)
}

func cleanupDomainEntriesForSet(registry *IPSetRegistry, vpnType, chainName, pattern string, ipv6 bool, ipsetDebug bool) error {
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

	unlock := registry.LockSet(ipsetName)
	defer unlock()
	registry.ClearStaleCountsForRule(ipsetName, pattern)
	prefixed, err := entriesByCommentPrefix(ipsetName, ruleCommentPrefix(pattern))
	if err != nil {
		return err
	}
	for _, entry := range prefixed {
		if ipsetDebug {
			logx.Infof("ipset del: set=%s entry=%s reason=rule-delete rule=%s", ipsetName, entry, pattern)
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
		if matcher.Match(pattern, entry.Comment) {
			stale = append(stale, entry.Entry)
		}
	}
	for _, entry := range stale {
		if ipsetDebug {
			logx.Infof("ipset del: set=%s entry=%s reason=rule-delete-legacy rule=%s", ipsetName, entry, pattern)
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
