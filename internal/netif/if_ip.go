package netif

import (
	"fmt"
	"net"
	"strings"
)

func findInterfaceByIP(ipAddress string) (string, error) {
	target := net.ParseIP(ipAddress)
	if target == nil {
		return "", fmt.Errorf("invalid IP address: %q", ipAddress)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error fetching interfaces: %w", err)
	}

	var candidates []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(target) {
				candidates = append(candidates, iface.Name)
				break
			}
		}
	}

	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("no active system interface carries address %s; is the VPN connection up?", ipAddress)
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("address %s is carried by multiple interfaces (%s); set system_name for the tracked interface in vpn_interfaces.yaml", ipAddress, strings.Join(candidates, ", "))
	}
}
