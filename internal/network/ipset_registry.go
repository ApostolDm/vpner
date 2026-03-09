package network

import "sync"

type IPSetRegistry struct {
	mu          sync.Mutex
	sets        map[string]*IPSet
	staleMu     sync.Mutex
	staleCounts map[string]map[string]int
}

func NewIPSetRegistry() *IPSetRegistry {
	return &IPSetRegistry{
		sets:        make(map[string]*IPSet),
		staleCounts: make(map[string]map[string]int),
	}
}

func (r *IPSetRegistry) ObtainOrCreateFamily(name, family string) (*IPSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if set, ok := r.sets[name]; ok {
		return set, nil
	}

	params := &Params{Timeout: DefaultIPSetTimeout, WithComments: true, HashFamily: family}
	set, err := NewIPset(name, "hash:net", params)
	if err != nil {
		return nil, err
	}
	r.sets[name] = set
	return set, nil
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

	for ip := range resolved {
		counts[ip] = 0
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
			delete(counts, entry)
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

func hasKeyPrefix(key, prefix string) bool {
	return len(key) >= len(prefix) && key[:len(prefix)] == prefix
}
