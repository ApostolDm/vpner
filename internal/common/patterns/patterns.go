package patterns

import (
	"fmt"
	"net"
	"strings"
)

type RuleKind int

const (
	RuleDomain RuleKind = iota
	RuleIP
	RuleCIDR
)

func kindOf(pattern string) RuleKind {
	if _, _, err := net.ParseCIDR(pattern); err == nil {
		return RuleCIDR
	}
	if ip := net.ParseIP(pattern); ip != nil {
		return RuleIP
	}
	return RuleDomain
}

func IsIP(pattern string) bool {
	return kindOf(pattern) == RuleIP
}

func IsCIDR(pattern string) bool {
	return kindOf(pattern) == RuleCIDR
}

func IsNetwork(pattern string) bool {
	k := kindOf(pattern)
	return k == RuleIP || k == RuleCIDR
}

func Validate(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("pattern cannot be empty")
	}
	switch kindOf(pattern) {
	case RuleIP:
		return nil
	case RuleCIDR:
		return nil
	}
	if strings.Contains(pattern, "/") {
		return fmt.Errorf("invalid domain pattern: contains '/'")
	}
	if strings.ContainsAny(pattern, "?[]") {
		return fmt.Errorf("invalid characters: only '*' allowed")
	}
	if strings.Count(pattern, "*") > 2 {
		return fmt.Errorf("maximum two '*' allowed")
	}
	if strings.Count(pattern, "*") == 2 && !(strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("two '*' must be only at start and end")
	}
	if strings.Count(pattern, "*") == 1 && !(strings.HasPrefix(pattern, "*") || strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("single '*' can be only at start or end")
	}
	return nil
}

func Overlap(a, b string) bool {
	kindA := kindOf(a)
	kindB := kindOf(b)

	if kindA != RuleDomain || kindB != RuleDomain {
		return networkOverlap(a, kindA, b, kindB)
	}

	hasWildcard1 := strings.Contains(a, "*")
	hasWildcard2 := strings.Contains(b, "*")

	switch {
	case !hasWildcard1 && !hasWildcard2:
		return a == b
	case !hasWildcard1 && hasWildcard2:
		return Match(b, a)
	case hasWildcard1 && !hasWildcard2:
		return Match(a, b)
	default:
		core1 := strings.ReplaceAll(a, "*", "")
		core2 := strings.ReplaceAll(b, "*", "")
		return strings.Contains(core1, core2) || strings.Contains(core2, core1)
	}
}

func Match(pattern, domain string) bool {
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

func networkOverlap(a string, kindA RuleKind, b string, kindB RuleKind) bool {
	switch kindA {
	case RuleIP:
		ipA := net.ParseIP(a)
		if ipA == nil {
			return false
		}
		switch kindB {
		case RuleIP:
			ipB := net.ParseIP(b)
			return ipB != nil && ipA.Equal(ipB)
		case RuleCIDR:
			_, netB, err := net.ParseCIDR(b)
			return err == nil && netB.Contains(ipA)
		}
	case RuleCIDR:
		_, netA, err := net.ParseCIDR(a)
		if err != nil {
			return false
		}
		switch kindB {
		case RuleIP:
			ipB := net.ParseIP(b)
			return ipB != nil && netA.Contains(ipB)
		case RuleCIDR:
			_, netB, err := net.ParseCIDR(b)
			if err != nil {
				return false
			}
			return netA.Contains(netB.IP) || netB.Contains(netA.IP)
		}
	}
	return false
}
