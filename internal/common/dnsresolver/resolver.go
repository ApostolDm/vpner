package dnsresolver

import (
	"net"

	"github.com/miekg/dns"
)

func Query(resolver, host string) ([]net.IP, error) {
	client := &dns.Client{}
	msg := &dns.Msg{
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(host),
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	return ips, nil
}
