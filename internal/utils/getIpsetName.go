package utils

import "fmt"

const (
	defaultTag = "vpner"
)

func GetIpsetName(vpnType string, chainName string) (string, error) {
	if vpnType == "" || chainName == "" {
		return "", fmt.Errorf("vpnType and chainName cannot be empty")
	}

	ipsetName := defaultTag + "-" + vpnType + "-" + chainName

	if len(ipsetName) > 32 {
		return "", fmt.Errorf("ipset name is too long: %s", ipsetName)
	}

	return ipsetName, nil
}
