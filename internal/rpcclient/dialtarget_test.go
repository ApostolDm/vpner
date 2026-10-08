package rpcclient

import "testing"

func TestDialTargetKeepsPassthroughForTCP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		opts ResolvedOptions
		want string
	}{
		{ResolvedOptions{Unix: "/tmp/vpner.sock"}, "unix:///tmp/vpner.sock"},
		{ResolvedOptions{Unix: "unix:///tmp/x.sock"}, "unix:///tmp/x.sock"},
		{ResolvedOptions{Addr: ":50051"}, "passthrough:///:50051"},
		{ResolvedOptions{Addr: "192.168.1.1:50051"}, "passthrough:///192.168.1.1:50051"},
		{ResolvedOptions{Addr: "router.lan:50051"}, "passthrough:///router.lan:50051"},
		{ResolvedOptions{Addr: "dns:///router.lan:50051"}, "dns:///router.lan:50051"},
		{ResolvedOptions{Addr: "unix:///tmp/y.sock"}, "unix:///tmp/y.sock"},
	}
	for _, c := range cases {
		if got := dialTarget(c.opts); got != c.want {
			t.Errorf("dialTarget(%+v) = %q, want %q", c.opts, got, c.want)
		}
	}
}
