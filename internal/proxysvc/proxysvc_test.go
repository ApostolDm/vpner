package proxysvc

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func newTestService(start func(context.Context, string) error) *Service {
	return &Service{
		process:     make(map[string]*procEntry),
		start:       start,
		startGrace:  30 * time.Millisecond,
		baseBackoff: 5 * time.Millisecond,
		maxBackoff:  20 * time.Millisecond,
		healthyRun:  time.Hour,
	}
}

func TestSupervisorRestartsCrashedChain(t *testing.T) {
	var calls int32
	svc := newTestService(func(ctx context.Context, name string) error {
		n := atomic.AddInt32(&calls, 1)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
		if n >= 4 {
			<-ctx.Done()
			return ctx.Err()
		}
		return fmt.Errorf("crash %d", n)
	})

	if err := svc.StartOne("c"); err != nil {
		t.Fatalf("StartOne: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("supervisor should have restarted the chain (>=3 starts), got %d", got)
	}
	if rt := svc.Runtimes()["c"]; rt.Restarts < 2 {
		t.Fatalf("expected restart count tracked, got %d", rt.Restarts)
	}

	svc.StopOne("c")
	time.Sleep(60 * time.Millisecond)
	stopped := atomic.LoadInt32(&calls)
	time.Sleep(80 * time.Millisecond)
	if atomic.LoadInt32(&calls) != stopped {
		t.Fatal("supervisor kept restarting after StopOne")
	}
	if svc.IsRunning("c") {
		t.Fatal("chain should not be tracked after StopOne")
	}
}

func TestFastInitialFailureNotSupervised(t *testing.T) {
	var calls int32
	svc := newTestService(func(ctx context.Context, name string) error {
		atomic.AddInt32(&calls, 1)
		return fmt.Errorf("bad config")
	})

	if err := svc.StartOne("c"); err == nil {
		t.Fatal("expected StartOne to report the immediate failure")
	}
	time.Sleep(120 * time.Millisecond)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("a fast-failing chain must not be retried, got %d starts", got)
	}
	if svc.IsRunning("c") {
		t.Fatal("a fast-failed chain should not remain tracked")
	}
}

func TestStopReplacedChainKeepsNewProcess(t *testing.T) {

	release := make(chan struct{})
	var live int32
	svc := newTestService(func(ctx context.Context, name string) error {
		atomic.AddInt32(&live, 1)
		defer atomic.AddInt32(&live, -1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return fmt.Errorf("done")
		}
	})

	if err := svc.StartOne("c"); err != nil {
		t.Fatalf("StartOne#1: %v", err)
	}
	svc.StopOne("c")
	if err := svc.StartOne("c"); err != nil {
		t.Fatalf("StartOne#2: %v", err)
	}
	close(release)
	time.Sleep(60 * time.Millisecond)

	if !svc.IsRunning("c") {
		t.Fatal("freshly started chain was wrongly forgotten by the old supervisor")
	}
	svc.StopOne("c")
}
