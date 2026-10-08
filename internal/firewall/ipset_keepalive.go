package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

const (
	keepaliveIntervalFloor = 30 * time.Second
	keepaliveIntervalCap   = 300 * time.Second
)

var conntrackPaths = []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"}

type KeepaliveOptions struct {
	EntryTimeout int
	Interval     int
	Enabled      bool
	Debug        bool
}

type KeepaliveSweeper struct {
	registry        *IPSetRegistry
	entryTimeout    int
	interval        time.Duration
	threshold       int
	debug           bool
	legacyAdd       bool
	disabled        bool
	conntrackMisses int
}

const conntrackMissLimit = 3

func NewKeepaliveSweeper(registry *IPSetRegistry, opts KeepaliveOptions) *KeepaliveSweeper {
	if !opts.Enabled || opts.EntryTimeout <= 0 || registry == nil {
		return nil
	}
	if err := initCheck(); err != nil {
		logx.Warnf("ipset keepalive disabled: %v", err)
		return nil
	}
	legacyAdd := false
	if version, err := getIpsetVersionString(); err == nil && compareVersions(version, timeoutRefreshVersion) < 0 {
		legacyAdd = true
	}
	interval := keepaliveInterval(opts.EntryTimeout, opts.Interval)
	return &KeepaliveSweeper{
		registry:     registry,
		entryTimeout: opts.EntryTimeout,
		interval:     interval,
		threshold:    refreshThreshold(opts.EntryTimeout, interval),
		debug:        opts.Debug,
		legacyAdd:    legacyAdd,
	}
}

func (k *KeepaliveSweeper) Interval() time.Duration {
	return k.interval
}

func (k *KeepaliveSweeper) Threshold() int {
	return k.threshold
}

func keepaliveInterval(entryTimeout, override int) time.Duration {
	timeout := time.Duration(entryTimeout) * time.Second
	interval := timeout / 6
	if override > 0 {
		interval = time.Duration(override) * time.Second
	} else if interval > keepaliveIntervalCap {
		interval = keepaliveIntervalCap
	}
	if max := timeout * 3 / 8; interval > max {
		interval = max
	}
	if interval < keepaliveIntervalFloor {
		interval = keepaliveIntervalFloor
	}
	return interval
}

func refreshThreshold(entryTimeout int, interval time.Duration) int {
	threshold := int64(2 * interval / time.Second)
	if limit := int64(entryTimeout) * 3 / 4; threshold > limit {
		threshold = limit
	}
	return int(threshold)
}

type keepaliveEntry struct {
	Entry   string
	Timeout int
	Comment string
}

func scanSaveEntries(r io.Reader, name string, fn func(keepaliveEntry)) error {
	scanner := bufio.NewScanner(r)
	prefix := "add " + name + " "
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		timeout, ok := parseTimeoutValue(line)
		if !ok {
			continue
		}
		fn(keepaliveEntry{
			Entry:   parts[2],
			Timeout: timeout,
			Comment: parseCommentFromLine(line),
		})
	}
	return scanner.Err()
}

func (k *KeepaliveSweeper) isCandidate(name string, entry keepaliveEntry) (string, bool) {
	if entry.Timeout <= 0 || entry.Timeout >= k.threshold {
		return "", false
	}
	if strings.Contains(entry.Entry, "/") {
		return "", false
	}
	ip := net.ParseIP(entry.Entry)
	if ip == nil {
		return "", false
	}
	if k.registry.IsStaticEntry(name, entry.Entry) {
		return "", false
	}
	if !strings.HasPrefix(entry.Comment, ipsetCommentPrefix) || !safeKeepaliveComment(entry.Comment) {
		return "", false
	}
	return ip.String(), true
}

func safeKeepaliveComment(comment string) bool {
	return !strings.ContainsAny(comment, "\"\\\n")
}

func conntrackActive(r io.Reader, want map[string]keepaliveEntry) []keepaliveEntry {
	var active []keepaliveEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() && len(want) > 0 {
		line := scanner.Text()
		idx := strings.Index(line, "dst=")
		if idx < 0 {
			continue
		}
		value := line[idx+4:]
		if end := strings.IndexByte(value, ' '); end >= 0 {
			value = value[:end]
		}
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		key := ip.String()
		if entry, ok := want[key]; ok {
			active = append(active, entry)
			delete(want, key)
		}
	}
	return active
}

func openConntrack() (*os.File, bool, error) {
	var errs []error
	missing := true
	for _, path := range conntrackPaths {
		file, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) {
				missing = false
			}
			errs = append(errs, err)
			continue
		}
		return file, false, nil
	}
	return nil, missing, errors.Join(errs...)
}

func managedSetNames() ([]string, error) {
	out, err := exec.Command(ipsetPath, "list", "-n").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipset list -n: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	var names []string
	for _, name := range strings.Fields(string(out)) {
		if strings.HasPrefix(name, defaultTag+"-") {
			names = append(names, name)
		}
	}
	return names, nil
}

func buildKeepaliveScript(name string, entries []keepaliveEntry, timeout int, legacy bool) string {
	var buf bytes.Buffer
	for _, entry := range entries {
		if legacy {
			buf.WriteString("del ")
			buf.WriteString(name)
			buf.WriteByte(' ')
			buf.WriteString(entry.Entry)
			buf.WriteByte('\n')
		}
		buf.WriteString("add ")
		buf.WriteString(name)
		buf.WriteByte(' ')
		buf.WriteString(entry.Entry)
		buf.WriteString(" timeout ")
		buf.WriteString(strconv.Itoa(timeout))
		if entry.Comment != "" {
			buf.WriteString(" comment \"")
			buf.WriteString(entry.Comment)
			buf.WriteString("\"")
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

func (k *KeepaliveSweeper) refreshEntries(name string, entries []keepaliveEntry) error {
	script := buildKeepaliveScript(name, entries, k.entryTimeout, k.legacyAdd)
	cmd := exec.Command(ipsetPath, "-exist", "restore")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restore: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (k *KeepaliveSweeper) SweepOnce() bool {
	if k == nil || k.disabled {
		return false
	}
	names, err := managedSetNames()
	if err != nil {
		logx.Debugf("keepalive: list sets: %v", err)
		return true
	}
	for _, name := range names {
		if !k.sweepSet(name) {
			return false
		}
	}
	return true
}

func (k *KeepaliveSweeper) collectCandidates(name string) (map[string]keepaliveEntry, error) {
	cmd := exec.Command(ipsetPath, "save", name)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	want := make(map[string]keepaliveEntry)
	scanErr := scanSaveEntries(stdout, name, func(entry keepaliveEntry) {
		if key, ok := k.isCandidate(name, entry); ok {
			want[key] = entry
		}
	})
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return want, scanErr
}

func (k *KeepaliveSweeper) sweepSet(name string) bool {
	if !ipsetPresent(name) {
		return true
	}
	want, err := k.collectCandidates(name)
	if err != nil {
		logx.Debugf("keepalive: save %s: %v", name, err)
		return true
	}
	if len(want) == 0 {
		return true
	}

	file, missing, err := openConntrack()
	if err != nil {
		if missing {
			if k.conntrackMisses++; k.conntrackMisses >= conntrackMissLimit {
				k.disabled = true
				logx.Warnf("ipset keepalive disabled: conntrack unreadable: %v", err)
				return false
			}
		}
		logx.Warnf("keepalive: conntrack read failed, skipping sweep: %v", err)
		return true
	}
	k.conntrackMisses = 0
	active := conntrackActive(bufio.NewReader(file), want)
	file.Close()
	if len(active) == 0 {
		return true
	}
	k.refreshActive(name, active)
	return true
}

func (k *KeepaliveSweeper) refreshActive(name string, active []keepaliveEntry) {
	unlock := k.registry.LockSet(name)
	defer unlock()

	if !ipsetPresent(name) {
		return
	}
	current, err := k.collectCandidates(name)
	if err != nil {
		logx.Debugf("keepalive: re-read %s: %v", name, err)
		return
	}
	entries := stillEligible(active, current)
	if len(entries) == 0 {
		return
	}
	if err := k.refreshEntries(name, entries); err != nil {
		logx.Warnf("keepalive: refresh %s: %v", name, err)
		return
	}
	if k.debug {
		for _, entry := range entries {
			logx.Infof("ipset add: set=%s entry=%s reason=keepalive remaining=%d timeout=%d", name, entry.Entry, entry.Timeout, k.entryTimeout)
		}
	}
}

func stillEligible(active []keepaliveEntry, current map[string]keepaliveEntry) []keepaliveEntry {
	var out []keepaliveEntry
	for _, entry := range active {
		ip := net.ParseIP(entry.Entry)
		if ip == nil {
			continue
		}
		if fresh, ok := current[ip.String()]; ok {
			out = append(out, fresh)
		}
	}
	return out
}
