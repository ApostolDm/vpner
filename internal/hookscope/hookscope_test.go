package hookscope

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func incomingFromOutgoing(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestNormalizeEvent(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"up":        EventUp,
		"UP":        EventUp,
		"yes":       EventUp,
		"connected": EventUp,
		"1":         EventUp,
		"down":      EventDown,
		"no":        EventDown,
		"0":         EventDown,
		"":          "",
		"weird":     "",
	}
	for in, want := range cases {
		if got := NormalizeEvent(in); got != want {
			t.Fatalf("NormalizeEvent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInterfaceScopeRoundTrip(t *testing.T) {
	t.Parallel()

	out := AppendOutgoingContext(context.Background(), Scope{
		Interface:  "OpenVPN0",
		SystemName: "ovpn_br0",
		Event:      NormalizeEvent("up"),
	})
	in := FromIncomingContext(incomingFromOutgoing(out))
	if in.Interface != "OpenVPN0" {
		t.Fatalf("Interface = %q", in.Interface)
	}
	if in.SystemName != "ovpn_br0" {
		t.Fatalf("SystemName = %q", in.SystemName)
	}
	if in.Event != EventUp {
		t.Fatalf("Event = %q", in.Event)
	}
}

func TestNonInterfaceScopeHasEmptyInterface(t *testing.T) {
	t.Parallel()

	out := AppendOutgoingContext(context.Background(), Scope{Family: FamilyIPv4, Table: TableMangle})
	in := FromIncomingContext(incomingFromOutgoing(out))
	if in.Interface != "" || in.Event != "" {
		t.Fatalf("expected empty interface scope, got iface=%q event=%q", in.Interface, in.Event)
	}
	if in.Family != FamilyIPv4 || in.Table != TableMangle {
		t.Fatalf("family/table lost: %q/%q", in.Family, in.Table)
	}
}
