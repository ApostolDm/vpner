package patterns

import "testing"

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{name: "domain", pattern: "*.example.com"},
		{name: "ip", pattern: "203.0.113.10"},
		{name: "cidr", pattern: "203.0.113.0/24"},
		{name: "empty", pattern: "", wantErr: true},
		{name: "middle wildcard", pattern: "api.*.example.com", wantErr: true},
		{name: "slash in domain", pattern: "example.com/test", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := Validate(tc.pattern)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.pattern)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.pattern, err)
			}
		})
	}
}

func TestOverlapAndMatch(t *testing.T) {
	t.Parallel()

	if !Match("*.example.com", "api.example.com") {
		t.Fatalf("expected wildcard suffix match")
	}
	if Match("*.example.com", "example.net") {
		t.Fatalf("unexpected match for different domain")
	}
	if !Overlap("*.example.com", "api.example.com") {
		t.Fatalf("expected overlap between wildcard and concrete domain")
	}
	if !Overlap("203.0.113.0/24", "203.0.113.10") {
		t.Fatalf("expected overlap between cidr and ip")
	}
	if Overlap("*.example.com", "*.example.net") {
		t.Fatalf("unexpected overlap between unrelated patterns")
	}
}
