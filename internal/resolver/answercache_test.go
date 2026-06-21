package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func positiveA(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP("1.2.3.4"),
	})
	return m
}

func TestAnswerCacheHitMirrorsIdAndDecrementsTTL(t *testing.T) {
	c := newAnswerCache(16)
	c.put(positiveA("example.com", 100))

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 4242

	got := c.get(q)
	if got == nil {
		t.Fatal("expected a cache hit")
	}
	if got.Id != 4242 {
		t.Fatalf("Id not mirrored: got %d", got.Id)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl == 0 || ttl > 100 {
		t.Fatalf("ttl should be decremented and within (0,100]: %d", ttl)
	}

	ci := new(dns.Msg)
	ci.SetQuestion("EXAMPLE.COM.", dns.TypeA)
	if c.get(ci) == nil {
		t.Fatal("expected case-insensitive hit")
	}

	aaaa := new(dns.Msg)
	aaaa.SetQuestion("example.com.", dns.TypeAAAA)
	if c.get(aaaa) != nil {
		t.Fatal("different qtype must miss")
	}
}

func TestAnswerCacheSkipsNonPositive(t *testing.T) {
	c := newAnswerCache(16)

	nx := new(dns.Msg)
	nx.SetQuestion("nope.com.", dns.TypeA)
	nx.Response, nx.Rcode = true, dns.RcodeNameError
	c.put(nx)

	empty := new(dns.Msg)
	empty.SetQuestion("empty.com.", dns.TypeA)
	empty.Response = true
	c.put(empty)

	for _, name := range []string{"nope.com.", "empty.com."} {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		if c.get(q) != nil {
			t.Fatalf("%s should not be cached (non-positive)", name)
		}
	}
}

func TestAnswerCachePreservesEDNSOPT(t *testing.T) {
	c := newAnswerCache(16)
	resp := positiveA("edns.com", 100)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.SetDo()
	resp.Extra = append(resp.Extra, opt)
	origTTLWord := opt.Hdr.Ttl
	c.put(resp)

	c.mu.Lock()
	for _, e := range c.entries {
		e.storedAt = time.Now().Add(-5 * time.Second)
	}
	c.mu.Unlock()

	q := new(dns.Msg)
	q.SetQuestion("edns.com.", dns.TypeA)
	got := c.get(q)
	if got == nil {
		t.Fatal("expected hit")
	}
	var gotOpt *dns.OPT
	for _, rr := range got.Extra {
		if o, ok := rr.(*dns.OPT); ok {
			gotOpt = o
		}
	}
	if gotOpt == nil {
		t.Fatal("OPT record dropped from cached response")
	}
	if gotOpt.Hdr.Ttl != origTTLWord || !gotOpt.Do() {
		t.Fatalf("EDNS word corrupted by cache: %#x -> %#x (DO=%v)", origTTLWord, gotOpt.Hdr.Ttl, gotOpt.Do())
	}
	if got.Answer[0].Header().Ttl >= 100 {
		t.Fatal("A record TTL was not decremented")
	}
}

func TestAnswerCacheExpires(t *testing.T) {
	c := newAnswerCache(16)
	c.put(positiveA("x.com", 1))

	c.mu.Lock()
	for _, e := range c.entries {
		e.storedAt = time.Now().Add(-2 * time.Second)
	}
	c.mu.Unlock()

	q := new(dns.Msg)
	q.SetQuestion("x.com.", dns.TypeA)
	if c.get(q) != nil {
		t.Fatal("expired entry must miss")
	}
}

func TestRateLimiterBurstThenLimit(t *testing.T) {
	l := newRateLimiter(5)
	allowed := 0
	for i := 0; i < 30; i++ {
		if l.allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed < 5 || allowed > 12 {
		t.Fatalf("expected ~burst(10) allowances, got %d", allowed)
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("a fresh source IP must start with a full bucket")
	}
}
