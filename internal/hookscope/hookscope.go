package hookscope

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"
)

const (
	FamilyIPv4  = "ipv4"
	FamilyIPv6  = "ipv6"
	TableNat    = "nat"
	TableMangle = "mangle"
	EventUp     = "up"
	EventDown   = "down"
)

type Scope struct {
	Family     string
	Table      string
	Interface  string
	SystemName string
	Event      string
}

func NormalizeFamily(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "v4", "ipv4", "iptables":
		return FamilyIPv4, nil
	case "v6", "ipv6", "ip6tables":
		return FamilyIPv6, nil
	default:
		return "", fmt.Errorf("unsupported family %q", value)
	}
}

func NormalizeTable(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "nat":
		return TableNat, nil
	case "mangle":
		return TableMangle, nil
	default:
		return "", fmt.Errorf("unsupported table %q", value)
	}
}

func NormalizeEvent(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "up", "yes", "1", "true", "connected":
		return EventUp
	case "down", "no", "0", "false", "disconnected":
		return EventDown
	default:
		return ""
	}
}

func AppendOutgoingContext(ctx context.Context, scope Scope) context.Context {
	if scope.Family != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-family", scope.Family)
	}
	if scope.Table != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-table", scope.Table)
	}
	if scope.Interface != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-iface", scope.Interface)
	}
	if scope.SystemName != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-sysname", scope.SystemName)
	}
	if scope.Event != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-event", scope.Event)
	}
	return ctx
}

func FromIncomingContext(ctx context.Context) Scope {
	var scope Scope

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return scope
	}

	if values := md.Get("hook-family"); len(values) > 0 {
		scope.Family, _ = NormalizeFamily(values[0])
	}
	if values := md.Get("hook-table"); len(values) > 0 {
		scope.Table, _ = NormalizeTable(values[0])
	}
	if values := md.Get("hook-iface"); len(values) > 0 {
		scope.Interface = strings.TrimSpace(values[0])
	}
	if values := md.Get("hook-sysname"); len(values) > 0 {
		scope.SystemName = strings.TrimSpace(values[0])
	}
	if values := md.Get("hook-event"); len(values) > 0 {
		scope.Event = NormalizeEvent(values[0])
	}

	return scope
}

func (s Scope) RestoreIPv4() bool {
	return s.Family == "" || s.Family == FamilyIPv4
}

func (s Scope) RestoreIPv6() bool {
	return s.Family == "" || s.Family == FamilyIPv6
}
