package resolver

import (
	"net"
	"sync"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/miekg/dns"
)

type recordingSyncer struct {
	mu       sync.Mutex
	prepared []string
	synced   chan string
}

func (r *recordingSyncer) PrepareAnswers(domain string, ips []net.IP) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ip := range ips {
		r.prepared = append(r.prepared, domain+"/"+ip.String())
	}
	return nil
}

func (r *recordingSyncer) SyncFromAnswers(domain string, ips []net.IP) error {
	if r.synced != nil {
		r.synced <- domain
	}
	return nil
}

type recordingWriter struct {
	dns.ResponseWriter
	mu      sync.Mutex
	written []*dns.Msg

	syncer          *recordingSyncer
	preparedAtWrite int
}

func (w *recordingWriter) WriteMsg(m *dns.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncer.mu.Lock()
	w.preparedAtWrite = len(w.syncer.prepared)
	w.syncer.mu.Unlock()
	w.written = append(w.written, m)
	return nil
}

func (w *recordingWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5353}
}

func (w *recordingWriter) Close() error { return nil }

func newTestServer(syncer IPSyncer) *Server {
	cache := true
	return NewServer(conf.ServerConfig{
		Port:              5300,
		MaxConcurrentConn: 4,
		Cache:             &cache,
	}, syncer, nil)
}

func buildCachedAnswer(domain string, ip string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.Response = true
	rr, _ := dns.NewRR(domain + ". 300 IN A " + ip)
	msg.Answer = []dns.RR{rr}
	return msg
}

func TestCacheHitProgramsRouteBeforeReply(t *testing.T) {
	t.Parallel()

	syncer := &recordingSyncer{synced: make(chan string, 1)}
	s := newTestServer(syncer)

	answer := buildCachedAnswer("blocked.example.com", "203.0.113.9")
	s.cache.put(answer)

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.com.", dns.TypeA)
	w := &recordingWriter{syncer: syncer}

	s.handleDNSRequest(w, req)

	if len(w.written) != 1 {
		t.Fatalf("expected one reply, got %d", len(w.written))
	}
	if w.preparedAtWrite == 0 {
		t.Fatal("route was not programmed before the DNS reply was written")
	}
	syncer.mu.Lock()
	got := append([]string(nil), syncer.prepared...)
	syncer.mu.Unlock()
	if len(got) != 1 || got[0] != "blocked.example.com/203.0.113.9" {
		t.Fatalf("unexpected prepared routes: %v", got)
	}

	select {
	case domain := <-syncer.synced:
		if domain != "blocked.example.com" {
			t.Fatalf("unexpected synced domain: %s", domain)
		}
	default:
		if domain := <-syncer.synced; domain != "blocked.example.com" {
			t.Fatalf("unexpected synced domain: %s", domain)
		}
	}
}

func TestCacheStoresUnstrippedAnswer(t *testing.T) {
	t.Parallel()

	cache := newAnswerCache(16)
	msg := new(dns.Msg)
	msg.SetQuestion("v6.example.com.", dns.TypeAAAA)
	msg.Response = true
	rr, _ := dns.NewRR("v6.example.com. 300 IN AAAA 2001:db8::1")
	msg.Answer = []dns.RR{rr}

	cache.put(msg)

	msg.Answer = msg.Answer[:0]

	req := new(dns.Msg)
	req.SetQuestion("v6.example.com.", dns.TypeAAAA)
	cached := cache.get(req)
	if cached == nil {
		t.Fatal("expected cached answer")
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("cache lost the answer after caller-side mutation: %v", cached.Answer)
	}
}
