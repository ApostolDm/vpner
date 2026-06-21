package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/tablefmt"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "doctor",
		Short:             "Check the local environment for running vpnerd (no daemon needed)",
		PersistentPreRunE: noDial,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor()
		},
	}
}

type checkResult struct {
	name, status, detail string
}

func runDoctor() error {
	var results []checkResult
	add := func(name, status, detail string) {
		results = append(results, checkResult{name, status, detail})
	}

	for _, bin := range []string{"xray", "iptables", "ip", "ipset"} {
		if p, err := exec.LookPath(bin); err == nil {
			add(bin, "OK", p)
		} else {
			add(bin, "FAIL", "not found in PATH")
		}
	}

	for _, bin := range []string{"ip6tables", "iptables-save"} {
		if p, err := exec.LookPath(bin); err == nil {
			add(bin, "OK", p)
		} else {
			add(bin, "WARN", "not found (needed for IPv6 / restore)")
		}
	}

	rel := kernelRelease()
	for _, mod := range []string{"xt_TPROXY", "xt_socket"} {
		switch {
		case rel == "":
			add(mod, "WARN", "could not determine kernel release (uname -r)")
		default:
			path := fmt.Sprintf("/lib/modules/%s/%s.ko", rel, mod)
			if _, err := os.Stat(path); err == nil {
				add(mod, "OK", path)
			} else {
				add(mod, "WARN", path+" not found (TPROXY may be unavailable; REDIRECT still works)")
			}
		}
	}

	for _, dir := range []string{"/opt/etc/vpner", "/opt/etc/vpner/xray"} {
		if writable(dir) {
			add(dir, "OK", "writable")
		} else {
			add(dir, "WARN", "missing or not writable")
		}
	}

	tbl := tablefmt.Table{Headers: []string{"Check", "Status", "Detail"}}
	fails := 0
	for _, r := range results {
		if r.status == "FAIL" {
			fails++
		}
		tbl.Rows = append(tbl.Rows, []string{r.name, r.status, r.detail})
	}
	printTable(tbl)

	if fails > 0 {
		return fmt.Errorf("%d required check(s) failed", fails)
	}
	return nil
}

func kernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func writable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	probe := filepath.Join(dir, ".vpner-doctor-probe")
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}
