package firewall

import (
	"os/exec"
	"strconv"
	"strings"
)

func ManagedIpsetCounts() (v4, v6 int64) {
	out, err := exec.Command(ipsetPath, "list", "-n").CombinedOutput()
	if err != nil {
		return 0, 0
	}
	for _, name := range strings.Fields(string(out)) {
		if !strings.HasPrefix(name, defaultTag+"-") {
			continue
		}
		n := ipsetEntryCount(name)
		if strings.HasSuffix(name, ipv6Suffix) {
			v6 += n
		} else {
			v4 += n
		}
	}
	return v4, v6
}

func ipsetEntryCount(name string) int64 {
	out, err := exec.Command(ipsetPath, "list", name).CombinedOutput()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "Number of entries:")
		if !ok {
			continue
		}
		if v, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
			return v
		}
	}
	return 0
}
