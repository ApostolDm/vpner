package resolver

import (
	"net"
	"time"
)

type cachedEntry struct {
	IPs       []net.IP
	ExpiresAt time.Time
	StaleAt   time.Time
}

func (r *Upstream) cleanupLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(secs(r.config.CleanupInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.cleanupCache()
		case <-r.stopCh:
			return
		}
	}
}

func (r *Upstream) cleanupCache() {
	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	for host, entry := range r.cache {
		if now.After(entry.StaleAt) {
			delete(r.cache, host)
		}
	}
}

func (r *Upstream) cachedFresh(host string) ([]net.IP, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.ExpiresAt) {
		return cloneIPs(e.IPs), true
	}
	return nil, false
}

func (r *Upstream) cachedStale(host string) ([]net.IP, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	if e, ok := r.cache[host]; ok && len(e.IPs) > 0 && time.Now().Before(e.StaleAt) {
		return cloneIPs(e.IPs), true
	}
	return nil, false
}

func (r *Upstream) storeCache(host string, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		ttl = secs(r.config.CacheTTL)
	}
	now := time.Now()

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if len(r.cache) >= r.config.MaxCacheEntries {
		r.evictExpiredLocked(now)
	}
	if len(r.cache) >= r.config.MaxCacheEntries {
		r.evictOneLocked()
	}
	r.cache[host] = cachedEntry{
		IPs:       cloneIPs(ips),
		ExpiresAt: now.Add(ttl),
		StaleAt:   now.Add(ttl + secs(r.config.StaleTTL)),
	}
}

func (r *Upstream) evictExpiredLocked(now time.Time) {
	for host, entry := range r.cache {
		if now.After(entry.StaleAt) {
			delete(r.cache, host)
		}
	}
}

func (r *Upstream) evictOneLocked() {
	for host := range r.cache {
		delete(r.cache, host)
		return
	}
}
