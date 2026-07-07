package netif

import "testing"

func TestFindInterfaceByIPLoopback(t *testing.T) {
	t.Parallel()

	name, err := findInterfaceByIP("127.0.0.1")
	if err != nil {
		t.Fatalf("findInterfaceByIP: %v", err)
	}
	if name == "" {
		t.Fatal("expected non-empty interface name for loopback")
	}
}

func TestFindInterfaceByIPUnknown(t *testing.T) {
	t.Parallel()

	if _, err := findInterfaceByIP("192.0.2.123"); err == nil {
		t.Fatal("expected error for unassigned address")
	}
}

func TestFindInterfaceByIPInvalid(t *testing.T) {
	t.Parallel()

	if _, err := findInterfaceByIP("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid address")
	}
}
