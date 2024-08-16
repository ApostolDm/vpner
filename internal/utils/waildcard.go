package utils

import (
	"fmt"
	"strings"
)

func ValidatePattern(pattern string) error {
	if strings.ContainsAny(pattern, "?[]") {
		return fmt.Errorf("недопустимые символы в шаблоне: разрешён только '*'")
	}
	if strings.Count(pattern, "*") > 2 {
		return fmt.Errorf("разрешено не более двух '*'")
	}
	if strings.Count(pattern, "*") == 2 && !(strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("если два '*', то они должны быть только в начале и в конце")
	}
	if strings.Count(pattern, "*") == 1 && !(strings.HasPrefix(pattern, "*") || strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("символ '*' может быть только в начале или в конце")
	}
	return nil
}

func PatternsOverlap(p1, p2 string) bool {
	hasWildcard1 := strings.Contains(p1, "*")
	hasWildcard2 := strings.Contains(p2, "*")

	switch {
	case !hasWildcard1 && !hasWildcard2:
		return p1 == p2

	case !hasWildcard1 && hasWildcard2:
		return MatchWildcard(p2, p1)

	case hasWildcard1 && !hasWildcard2:
		return MatchWildcard(p1, p2)

	case hasWildcard1 && hasWildcard2:
		core1 := strings.ReplaceAll(p1, "*", "")
		core2 := strings.ReplaceAll(p2, "*", "")
		return strings.Contains(core1, core2) || strings.Contains(core2, core1)
	}

	return false
}

func MatchWildcard(pattern, domain string) bool {
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
