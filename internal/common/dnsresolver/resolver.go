package dnsresolver

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func Query(resolver, host string) ([]net.IP, error) {

	resolver = strings.TrimSpace(resolver)

	if resolver == "" {
		return nil, fmt.Errorf("resolver is empty")
	}

	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP

	for _, ans := range resp.Answer {

		switch rr := ans.(type) {

		case *dns.A:
			ips = append(ips, rr.A)

		case *dns.AAAA:
			ips = append(ips, rr.AAAA)

		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A/AAAA records")
	}

	return ips, nil
}