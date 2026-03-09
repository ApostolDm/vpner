package hookmeta

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
)

type Scope struct {
	Family string
	Table  string
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

func AppendOutgoingContext(ctx context.Context, scope Scope) context.Context {
	if scope.Family != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-family", scope.Family)
	}
	if scope.Table != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-table", scope.Table)
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

	return scope
}

func (s Scope) RestoreIPv4() bool {
	return s.Family == "" || s.Family == FamilyIPv4
}

func (s Scope) RestoreIPv6() bool {
	return s.Family == "" || s.Family == FamilyIPv6
}
