//go:build !linux

package firewall

import "fmt"

func probeTransparentBind(bool) error {
	return fmt.Errorf("transparent sockets are only supported on linux")
}
