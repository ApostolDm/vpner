package network

import "fmt"

const defaultTag = "vpner"
const ipv6Suffix = "-6"

func IpsetName(vpnType, chainName string) (string, error) {
	if vpnType == "" || chainName == "" {
		return "", fmt.Errorf("vpnType and chainName cannot be empty")
	}

	name := defaultTag + "-" + vpnType + "-" + chainName
	return validateIpsetName(name)
}

func IpsetName6(vpnType, chainName string) (string, error) {
	base, err := IpsetName(vpnType, chainName)
	if err != nil {
		return "", err
	}
	return IpsetName6FromBase(base)
}

func IpsetName6FromBase(base string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("ipset name cannot be empty")
	}
	return validateIpsetName(base + ipv6Suffix)
}

func validateIpsetName(name string) (string, error) {
	if len(name) > 32 {
		return "", fmt.Errorf("ipset name is too long: %s", name)
	}
	return name, nil
}
