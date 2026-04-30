//go:build linux

package network

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func probeTransparentBind(ipv6Enabled bool) error {
	if err := probeTransparentListen("tcp4", "127.0.0.1:0", unix.SOL_IP, unix.IP_TRANSPARENT); err != nil {
		return err
	}
	if !ipv6Enabled {
		return nil
	}
	return probeTransparentListen("tcp6", "[::1]:0", unix.SOL_IPV6, unix.IPV6_TRANSPARENT)
}

func probeTransparentListen(network, addr string, level, option int) error {
	cfg := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			ctlErr := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), level, option, 1)
			})
			if ctlErr != nil {
				return ctlErr
			}
			return sockErr
		},
	}
	ln, err := cfg.Listen(context.Background(), network, addr)
	if err != nil {
		return err
	}
	return ln.Close()
}
