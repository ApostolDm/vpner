package network

import "fmt"

const defaultTag = "vpner"

func IpsetName(vpnType, chainName string) (string, error) {
	if vpnType == "" || chainName == "" {
		return "", fmt.Errorf("vpnType and chainName cannot be empty")
	}

	name := defaultTag + "-" + vpnType + "-" + chainName
	if len(name) > 32 {
		return "", fmt.Errorf("ipset name is too long: %s", name)
	}
	return name, nil
}
