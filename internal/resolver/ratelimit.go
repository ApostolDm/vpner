package resolver

import (
	"sync"
	"time"
)

const rateLimiterMaxClients = 8192

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	qps     float64
	burst   float64
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(qps int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		qps:     float64(qps),
		burst:   float64(qps) * 2,
	}
}

func (l *rateLimiter) allow(ip string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= rateLimiterMaxClients {
			l.evictLocked(now)
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}

	b.tokens += l.qps * now.Sub(b.last).Seconds()
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (l *rateLimiter) evictLocked(now time.Time) {
	freed := false
	var lruIP string
	var lruLast time.Time
	for ip, b := range l.buckets {
		if b.tokens+l.qps*now.Sub(b.last).Seconds() >= l.burst {
			delete(l.buckets, ip)
			freed = true
			continue
		}
		if lruIP == "" || b.last.Before(lruLast) {
			lruIP, lruLast = ip, b.last
		}
	}
	if !freed && lruIP != "" {
		delete(l.buckets, lruIP)
	}
}
