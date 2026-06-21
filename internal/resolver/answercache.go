package resolver

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	answerCacheDefaultMax = 4096
	answerCacheTTLCap     = 3600
)

type answerCache struct {
	mu      sync.Mutex
	entries map[string]*cachedAnswer
	max     int
}

type cachedAnswer struct {
	msg      *dns.Msg
	storedAt time.Time
	ttl      time.Duration
}

func newAnswerCache(max int) *answerCache {
	if max <= 0 {
		max = answerCacheDefaultMax
	}
	return &answerCache{entries: make(map[string]*cachedAnswer), max: max}
}

func cacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "|" + dns.Type(q.Qtype).String() + "|" + dns.Class(q.Qclass).String()
}

func (c *answerCache) get(req *dns.Msg) *dns.Msg {
	if len(req.Question) != 1 {
		return nil
	}
	key := cacheKey(req.Question[0])

	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	elapsed := time.Since(e.storedAt)
	if elapsed >= e.ttl {
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	resp := e.msg.Copy()
	c.mu.Unlock()

	decrementTTL(resp, uint32(elapsed.Seconds()))
	resp.Id = req.Id
	resp.Question = req.Question
	return resp
}

func (c *answerCache) put(resp *dns.Msg) {
	if len(resp.Question) != 1 || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return
	}
	ttl := minAnswerTTL(resp)
	if ttl == 0 {
		return
	}
	stored := resp.Copy()
	stored.Id = 0

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[cacheKey(resp.Question[0])] = &cachedAnswer{
		msg:      stored,
		storedAt: time.Now(),
		ttl:      time.Duration(ttl) * time.Second,
	}
}

func (c *answerCache) evictLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.Sub(e.storedAt) >= e.ttl {
			delete(c.entries, k)
			return
		}
	}
	for k := range c.entries {
		delete(c.entries, k)
		return
	}
}

func minAnswerTTL(m *dns.Msg) uint32 {
	var min uint32
	for _, rr := range m.Answer {
		t := rr.Header().Ttl
		if min == 0 || t < min {
			min = t
		}
	}
	if min > answerCacheTTLCap {
		min = answerCacheTTLCap
	}
	return min
}

func decrementTTL(m *dns.Msg, by uint32) {
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			h := rr.Header()

			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > by {
				h.Ttl -= by
			} else {
				h.Ttl = 1
			}
		}
	}
}
