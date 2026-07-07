package resolver

import (
	"net"
)

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		cp := make(net.IP, len(ip))
		copy(cp, ip)
		out = append(out, cp)
	}
	return out
}

func dedupeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func isIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}
