package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/miekg/dns"
)

func (r *Upstream) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: secs(r.config.DialTimeout)}

	if net.ParseIP(host) != nil {
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := r.resolveHost(host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range r.sortIPsForDial(ips) {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no bootstrap IPs available")
	}
	return nil, fmt.Errorf("all bootstrap IPs failed for %s: %w", host, lastErr)
}

func (r *Upstream) sortIPsForDial(ips []net.IP) []net.IP {
	out := cloneIPs(ips)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })

	sort.SliceStable(out, func(i, j int) bool {
		i6, j6 := isIPv6(out[i]), isIPv6(out[j])
		if i6 == j6 {
			return false
		}
		if r.config.PreferIPv6 {
			return i6
		}
		return !i6
	})
	return out
}

func (r *Upstream) resolveHost(host string) ([]net.IP, error) {
	if ips, ok := r.cachedFresh(host); ok {
		return ips, nil
	}

	v, err, _ := r.sf.Do(host, func() (any, error) {
		if ips, ok := r.cachedFresh(host); ok {
			return ips, nil
		}
		ips, ttl, err := r.resolveHostUncached(host)
		if err != nil {
			if stale, ok := r.cachedStale(host); ok {
				logx.Warnf("bootstrap resolve failed for %s, serving stale cache: %v", host, err)
				return stale, nil
			}
			return nil, err
		}
		r.storeCache(host, ips, ttl)
		return cloneIPs(ips), nil
	})
	if err != nil {
		return nil, err
	}
	ips, ok := v.([]net.IP)
	if !ok {
		return nil, errors.New("invalid singleflight result")
	}
	return ips, nil
}

func (r *Upstream) resolveHostUncached(host string) ([]net.IP, time.Duration, error) {
	var errs []string
	for _, resolver := range r.config.Resolvers {
		ips, ttl, err := r.queryBootstrap(resolver, host)
		if err == nil && len(ips) > 0 {
			if ttl <= 0 {
				ttl = secs(r.config.CacheTTL)
			}
			return ips, ttl, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", resolver, err))
		}
	}
	if len(errs) == 0 {
		return nil, 0, errors.New("bootstrap resolvers failed")
	}
	return nil, 0, fmt.Errorf("bootstrap resolvers failed: %s", strings.Join(errs, "; "))
}

func (r *Upstream) queryBootstrap(resolver, host string) ([]net.IP, time.Duration, error) {
	type answer struct {
		ips []net.IP
		ttl time.Duration
		err error
	}
	ask := func(qtype uint16) <-chan answer {
		ch := make(chan answer, 1)
		go func() {
			ips, ttl, err := r.queryType(resolver, host, qtype)
			ch <- answer{ips, ttl, err}
		}()
		return ch
	}
	aCh, aaaaCh := ask(dns.TypeA), ask(dns.TypeAAAA)
	a, aaaa := <-aCh, <-aaaaCh

	var ips []net.IP
	var ttl time.Duration
	if a.err == nil {
		ips = append(ips, a.ips...)
		ttl = pickTTL(ttl, a.ttl)
	}
	if aaaa.err == nil {
		ips = append(ips, aaaa.ips...)
		ttl = pickTTL(ttl, aaaa.ttl)
	}

	if ips = dedupeIPs(ips); len(ips) > 0 {
		if ttl <= 0 {
			ttl = secs(r.config.CacheTTL)
		}
		return ips, ttl, nil
	}
	if a.err != nil && aaaa.err != nil {
		return nil, 0, fmt.Errorf("A failed: %v; AAAA failed: %v", a.err, aaaa.err)
	}
	return nil, 0, errors.New("no A/AAAA records")
}

func (r *Upstream) queryType(resolver, host string, qtype uint16) ([]net.IP, time.Duration, error) {
	if resolver = strings.TrimSpace(resolver); resolver == "" {
		return nil, 0, errors.New("resolver is empty")
	}
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true
	timeout := secs(r.config.BootstrapTimeout)

	resp, err := exchangeDNS("udp", resolver, msg, timeout)
	if err != nil {
		if resp, err = exchangeDNS("tcp", resolver, msg, timeout); err != nil {
			return nil, 0, err
		}
	}
	if resp == nil {
		return nil, 0, errors.New("nil dns response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("dns error: %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	var minTTL uint32
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, rr.A)
				minTTL = minTTL32(minTTL, rr.Hdr.Ttl)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, rr.AAAA)
				minTTL = minTTL32(minTTL, rr.Hdr.Ttl)
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, errors.New("no records")
	}
	return dedupeIPs(ips), normalizeTTL(minTTL, r.config.CacheTTL), nil
}

func exchangeDNS(network, resolver string, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{Net: network, Timeout: timeout}
	resp, _, err := client.Exchange(msg, resolver)
	return resp, err
}

func pickTTL(current, next time.Duration) time.Duration {
	switch {
	case next <= 0:
		return current
	case current <= 0 || next < current:
		return next
	default:
		return current
	}
}

func normalizeTTL(ttl uint32, fallbackSeconds int) time.Duration {
	if ttl == 0 {
		return secs(fallbackSeconds)
	}
	d := secs(int(ttl))
	min, max := 30*time.Second, secs(fallbackSeconds)
	if max < min {
		max = min
	}
	if d < min {
		return min
	}
	if d > max {
		return max
	}
	return d
}

func minTTL32(current, next uint32) uint32 {
	if next == 0 {
		return current
	}
	if current == 0 || next < current {
		return next
	}
	return current
}
