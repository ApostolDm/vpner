package resolver

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

var ErrNoRecords = errors.New("no records in DoH response")

func (r *Upstream) ResolveDomain(domain string, qtype uint16) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	respData, err := r.ForwardQuery(packed)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, rr.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, rr.AAAA)
			}
		}
	}
	if ips = dedupeIPs(ips); len(ips) == 0 {
		return nil, ErrNoRecords
	}
	return ips, nil
}

func (r *Upstream) ResolveA(domain string) ([]net.IP, error) {
	return r.ResolveDomain(domain, dns.TypeA)
}

func (r *Upstream) ResolveAAAA(domain string) ([]net.IP, error) {
	return r.ResolveDomain(domain, dns.TypeAAAA)
}

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
