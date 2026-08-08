package firewall

import (
	"strings"
	"sync"
	"time"
)

type refreshRecord struct {
	ips string
	at  time.Time
}

const refreshSeenMax = 8192

type IPSetRegistry struct {
	mu           sync.Mutex
	sets         map[string]*IPSet
	entryTimeout int
	legacySwept  map[string]bool

	staleMu     sync.Mutex
	staleCounts map[string]map[string]int

	refreshMu   sync.Mutex
	refreshSeen map[string]refreshRecord

	staticMu      sync.Mutex
	staticEntries map[string]map[string]struct{}

	opMu    sync.Mutex
	opLocks map[string]*sync.Mutex
}

func NewIPSetRegistry() *IPSetRegistry {
	return &IPSetRegistry{
		sets:          make(map[string]*IPSet),
		legacySwept:   make(map[string]bool),
		staleCounts:   make(map[string]map[string]int),
		refreshSeen:   make(map[string]refreshRecord),
		staticEntries: make(map[string]map[string]struct{}),
		opLocks:       make(map[string]*sync.Mutex),
	}
}

func (r *IPSetRegistry) SetEntryTimeout(seconds int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seconds < 0 {
		seconds = 0
	}
	r.entryTimeout = seconds
}

func (r *IPSetRegistry) ObtainOrCreateFamily(name, family string) (*IPSet, error) {
	r.mu.Lock()
	if set, ok := r.sets[name]; ok {
		r.mu.Unlock()
		return set, nil
	}
	timeout := r.entryTimeout
	r.mu.Unlock()

	params := &Params{Timeout: timeout, WithComments: true, HashFamily: family}
	set, err := NewIPset(name, "hash:net", params)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.sets[name]; ok {
		return existing, nil
	}
	r.sets[name] = set
	return set, nil
}

func (r *IPSetRegistry) EnsureKernelFamily(name, family string) (*IPSet, error) {
	r.mu.Lock()
	set, cached := r.sets[name]
	r.mu.Unlock()

	if !cached {
		return r.ObtainOrCreateFamily(name, family)
	}
	if IPSetExists(name) {
		return set, nil
	}

	r.mu.Lock()
	delete(r.sets, name)
	r.mu.Unlock()
	return r.ObtainOrCreateFamily(name, family)
}

func (r *IPSetRegistry) IsLegacySwept(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.legacySwept[name]
}

func (r *IPSetRegistry) MarkLegacySwept(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.legacySwept[name] = true
}

func (r *IPSetRegistry) RecentlyRefreshed(key, fingerprint string, window time.Duration) bool {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	rec, ok := r.refreshSeen[key]
	return ok && rec.ips == fingerprint && time.Since(rec.at) < window
}

func (r *IPSetRegistry) MarkRefreshed(key, fingerprint string, window time.Duration) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if len(r.refreshSeen) >= refreshSeenMax {
		for k, rec := range r.refreshSeen {
			if time.Since(rec.at) >= window {
				delete(r.refreshSeen, k)
			}
		}
		if len(r.refreshSeen) >= refreshSeenMax {
			r.refreshSeen = make(map[string]refreshRecord)
		}
	}
	r.refreshSeen[key] = refreshRecord{ips: fingerprint, at: time.Now()}
}

func (r *IPSetRegistry) ClearRefreshKey(key string) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	delete(r.refreshSeen, key)
}

func (r *IPSetRegistry) ClearRefreshByPrefix(prefix string) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	for key := range r.refreshSeen {
		if strings.HasPrefix(key, prefix) {
			delete(r.refreshSeen, key)
		}
	}
}

func (r *IPSetRegistry) RegisterStaticEntry(set, entry string) {
	r.staticMu.Lock()
	defer r.staticMu.Unlock()
	entries, ok := r.staticEntries[set]
	if !ok {
		entries = make(map[string]struct{})
		r.staticEntries[set] = entries
	}
	entries[entry] = struct{}{}
}

func (r *IPSetRegistry) UnregisterStaticEntry(set, entry string) {
	r.staticMu.Lock()
	defer r.staticMu.Unlock()
	if entries, ok := r.staticEntries[set]; ok {
		delete(entries, entry)
		if len(entries) == 0 {
			delete(r.staticEntries, set)
		}
	}
}

func (r *IPSetRegistry) IsStaticEntry(set, entry string) bool {
	r.staticMu.Lock()
	defer r.staticMu.Unlock()
	_, ok := r.staticEntries[set][entry]
	return ok
}

func (r *IPSetRegistry) LockSet(name string) func() {
	r.opMu.Lock()
	lock, ok := r.opLocks[name]
	if !ok {
		lock = &sync.Mutex{}
		r.opLocks[name] = lock
	}
	r.opMu.Unlock()

	lock.Lock()
	return lock.Unlock
}

func (r *IPSetRegistry) ClearStaleCountsForRule(ipsetName, pattern string) {
	prefix := buildStaleKey(ipsetName, ruleCommentPrefix(pattern))

	r.staleMu.Lock()
	defer r.staleMu.Unlock()

	for key := range r.staleCounts {
		if hasKeyPrefix(key, prefix) {
			delete(r.staleCounts, key)
		}
	}
}

func (r *IPSetRegistry) CollectStaleEntries(key string, existing []string, resolved map[string]struct{}, threshold int) []staleEntry {
	if threshold <= 0 {
		return nil
	}

	r.staleMu.Lock()
	defer r.staleMu.Unlock()

	counts, ok := r.staleCounts[key]
	if !ok {
		counts = make(map[string]int)
		r.staleCounts[key] = counts
	}

	existingSet := make(map[string]struct{}, len(existing))
	var stale []staleEntry

	for _, entry := range existing {
		existingSet[entry] = struct{}{}
		if _, ok := resolved[entry]; ok {
			counts[entry] = 0
			continue
		}
		counts[entry]++
		if counts[entry] >= threshold {
			stale = append(stale, staleEntry{entry: entry, misses: counts[entry]})
		}
	}

	for ip := range counts {
		if _, ok := existingSet[ip]; ok {
			continue
		}
		if _, ok := resolved[ip]; ok {
			continue
		}
		delete(counts, ip)
	}

	if len(counts) == 0 {
		delete(r.staleCounts, key)
	}

	return stale
}

func (r *IPSetRegistry) ConfirmStaleDeleted(key string, entries []string) {
	if len(entries) == 0 {
		return
	}

	r.staleMu.Lock()
	defer r.staleMu.Unlock()

	counts, ok := r.staleCounts[key]
	if !ok {
		return
	}
	for _, entry := range entries {
		delete(counts, entry)
	}
	if len(counts) == 0 {
		delete(r.staleCounts, key)
	}
}

func hasKeyPrefix(key, prefix string) bool {
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}
