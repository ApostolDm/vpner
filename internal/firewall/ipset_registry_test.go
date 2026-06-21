package firewall

import (
	"sync"
	"testing"
)

func resolvedSet(ips ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		m[ip] = struct{}{}
	}
	return m
}

func TestCollectStaleEntriesThreshold(t *testing.T) {
	r := NewIPSetRegistry()
	const key = "set|comment"
	existing := []string{"1.1.1.1"}

	if got := r.CollectStaleEntries(key, existing, resolvedSet(), 2); len(got) != 0 {
		t.Fatalf("miss 1: expected no stale, got %v", got)
	}

	got := r.CollectStaleEntries(key, existing, resolvedSet(), 2)
	if len(got) != 1 || got[0].entry != "1.1.1.1" {
		t.Fatalf("miss 2: expected 1.1.1.1 stale, got %v", got)
	}
}

func TestStaleEntryRetriedUntilConfirmed(t *testing.T) {
	r := NewIPSetRegistry()
	const key = "set|comment"
	existing := []string{"1.1.1.1"}

	if got := r.CollectStaleEntries(key, existing, resolvedSet(), 1); len(got) != 1 {
		t.Fatalf("expected stale on first miss, got %v", got)
	}

	if got := r.CollectStaleEntries(key, existing, resolvedSet(), 1); len(got) != 1 {
		t.Fatalf("expected stale to be retried while unconfirmed, got %v", got)
	}

	r.ConfirmStaleDeleted(key, []string{"1.1.1.1"})
	if got := r.CollectStaleEntries(key, nil, resolvedSet(), 1); len(got) != 0 {
		t.Fatalf("expected no stale after confirm, got %v", got)
	}
}

func TestResolvedResetsMissCount(t *testing.T) {
	r := NewIPSetRegistry()
	const key = "set|comment"
	existing := []string{"1.1.1.1"}

	r.CollectStaleEntries(key, existing, resolvedSet(), 2)

	if got := r.CollectStaleEntries(key, existing, resolvedSet("1.1.1.1"), 2); len(got) != 0 {
		t.Fatalf("resolved IP should not be stale, got %v", got)
	}

	if got := r.CollectStaleEntries(key, existing, resolvedSet(), 2); len(got) != 0 {
		t.Fatalf("counter should have reset, got %v", got)
	}
}

func TestLockSetSerializesByName(t *testing.T) {
	r := NewIPSetRegistry()
	var mu sync.Mutex
	inCritical := false
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := r.LockSet("set")
			defer unlock()
			mu.Lock()
			if inCritical {
				mu.Unlock()
				t.Error("LockSet allowed concurrent entry for the same name")
				return
			}
			inCritical = true
			mu.Unlock()

			mu.Lock()
			inCritical = false
			mu.Unlock()
		}()
	}
	wg.Wait()
}
