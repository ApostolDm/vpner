package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

const (
	minIpsetVersion       = "6.0"
	timeoutRefreshVersion = "6.20"
	maxIpsetNameLen       = 31
)

func tempSetName(base, suffix string) string {
	name := base + suffix
	if len(name) <= maxIpsetNameLen {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(base))
	return fmt.Sprintf("vt%08x%s", h.Sum32(), suffix)
}

func warnIfTimeoutRefreshUnsupported() {
	if err := initCheck(); err != nil {
		return
	}
	version, err := getIpsetVersionString()
	if err != nil {
		return
	}
	if compareVersions(version, timeoutRefreshVersion) < 0 {
		logx.Warnf("ipset %s is older than %s: `add -exist` may not refresh entry timeouts; consider ipset-entry-timeout: -1", version, timeoutRefreshVersion)
	}
}

var (
	ipsetPath            string
	errIpsetNotFound     = errors.New("ipset utility not found")
	errIpsetNotSupported = fmt.Errorf("ipset version must be >= %s", minIpsetVersion)
)

type Params struct {
	HashFamily   string
	HashSize     int
	MaxElem      int
	Timeout      int
	WithComments bool
}

type IPSet struct {
	Name         string
	HashType     string
	HashFamily   string
	HashSize     int
	MaxElem      int
	Timeout      int
	WithComments bool
}

func normalizeParams(p *Params) Params {
	if p == nil {
		return Params{HashFamily: "inet", HashSize: 1024, MaxElem: 65536}
	}
	cfg := *p
	if cfg.HashSize == 0 {
		cfg.HashSize = 1024
	}
	if cfg.MaxElem == 0 {
		cfg.MaxElem = 65536
	}
	if cfg.HashFamily == "" {
		cfg.HashFamily = "inet"
	}
	return cfg
}

func initCheck() error {
	if ipsetPath != "" {
		return nil
	}

	path, err := exec.LookPath("ipset")
	if err != nil {
		return errIpsetNotFound
	}
	ipsetPath = path

	supported, err := getIpsetSupportedVersion()
	if err != nil {
		logx.Warnf("ipset: failed to detect version, assuming supported: %v", err)
	} else if !supported {
		return errIpsetNotSupported
	}

	return nil
}

func (s *IPSet) createHashSet(name string) error {
	exists := exec.Command(ipsetPath, "-q", "list", name).Run() == nil
	if !exists {
		args := []string{
			"-exist",
			"create", name, s.HashType,
			"family", s.HashFamily,
			"hashsize", strconv.Itoa(s.HashSize),
			"maxelem", strconv.Itoa(s.MaxElem),
		}
		if s.Timeout > 0 {
			args = append(args, "timeout", strconv.Itoa(s.Timeout))
		}
		if s.WithComments {
			args = append(args, "comment")
		}
		out, err := exec.Command(ipsetPath, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to create ipset %s: %v (%s)", name, err, out)
		}
		return nil
	}
	return ensureSetProperties(name, s)
}

func NewIPset(name, hashtype string, p *Params) (*IPSet, error) {
	if err := initCheck(); err != nil {
		return nil, err
	}

	if !strings.HasPrefix(hashtype, "hash:") {
		return nil, fmt.Errorf("unsupported ipset type: %s", hashtype)
	}

	cfg := normalizeParams(p)

	s := &IPSet{
		Name:         name,
		HashType:     hashtype,
		HashFamily:   cfg.HashFamily,
		HashSize:     cfg.HashSize,
		MaxElem:      cfg.MaxElem,
		Timeout:      cfg.Timeout,
		WithComments: cfg.WithComments,
	}

	if err := s.createHashSet(name); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *IPSet) timeoutArgs(timeout int) []string {
	if s.Timeout > 0 || timeout > 0 {
		return []string{"timeout", strconv.Itoa(timeout)}
	}
	return nil
}

func (s *IPSet) Add(entry string, timeout int) error {
	args := []string{"add", s.Name, entry}
	args = append(args, s.timeoutArgs(timeout)...)
	args = append(args, "-exist")

	if out, err := exec.Command(ipsetPath, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

func (s *IPSet) AddComment(entry, comment string, timeout int) error {
	args := []string{"add", s.Name, entry}
	args = append(args, s.timeoutArgs(timeout)...)
	args = append(args, "comment", comment, "-exist")
	if out, err := exec.Command(ipsetPath, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add entry %s with comment: %v (%s)", entry, err, out)
	}
	return nil
}

func buildBulkAddScript(setName string, entries []string, comment string, timeout int, hasTimeout bool) string {
	var buf bytes.Buffer
	for _, entry := range entries {
		buf.WriteString("add ")
		buf.WriteString(setName)
		buf.WriteByte(' ')
		buf.WriteString(entry)
		if hasTimeout {
			buf.WriteString(" timeout ")
			buf.WriteString(strconv.Itoa(timeout))
		}
		buf.WriteString(" comment \"")
		buf.WriteString(comment)
		buf.WriteString("\"\n")
	}
	return buf.String()
}

func (s *IPSet) BulkAddComment(entries []string, comment string, timeout int) error {
	if len(entries) == 0 {
		return nil
	}
	if err := initCheck(); err != nil {
		return err
	}
	script := buildBulkAddScript(s.Name, entries, comment, timeout, s.Timeout > 0)
	cmd := exec.Command(ipsetPath, "-exist", "restore")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bulk add %d entries to %s: %v (%s)", len(entries), s.Name, err, out)
	}
	return nil
}

func (s *IPSet) Del(entry string) error {
	out, err := exec.Command(ipsetPath, "del", s.Name, entry, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete entry %s: %v (%s)", entry, err, out)
	}
	return nil
}

func destroyIPSet(name string) error {
	out, err := exec.Command(ipsetPath, "destroy", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to destroy ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

func Swap(from, to string) error {
	out, err := exec.Command(ipsetPath, "swap", from, to).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to swap ipsets %s -> %s: %v (%s)", from, to, err, out)
	}
	return nil
}

func IPSetExists(name string) bool {
	if err := initCheck(); err != nil {
		return false
	}
	return exec.Command(ipsetPath, "-q", "list", name).Run() == nil
}

func EnsureIPSet(name, hashtype string, p *Params) error {
	if err := initCheck(); err != nil {
		return err
	}
	if !strings.HasPrefix(hashtype, "hash:") {
		return fmt.Errorf("unsupported ipset type: %s", hashtype)
	}
	cfg := normalizeParams(p)
	if err := exec.Command(ipsetPath, "-q", "list", name).Run(); err == nil {
		stub := &IPSet{Name: name, HashType: hashtype, HashFamily: cfg.HashFamily, HashSize: cfg.HashSize, MaxElem: cfg.MaxElem, Timeout: cfg.Timeout, WithComments: cfg.WithComments}
		return ensureSetProperties(name, stub)
	}

	args := []string{
		"-exist",
		"create", name, hashtype,
		"family", cfg.HashFamily,
		"hashsize", strconv.Itoa(cfg.HashSize),
		"maxelem", strconv.Itoa(cfg.MaxElem),
	}
	if cfg.Timeout > 0 {
		args = append(args, "timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.WithComments {
		args = append(args, "comment")
	}
	if out, err := exec.Command(ipsetPath, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to ensure ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

func getIpsetSupportedVersion() (bool, error) {
	vstring, err := getIpsetVersionString()
	if err != nil {
		return false, err
	}
	return compareVersions(vstring, minIpsetVersion) >= 0, nil
}

func getIpsetVersionString() (string, error) {
	out, err := exec.Command(ipsetPath, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get ipset version: %v (%s)", err, out)
	}
	versionMatcher := regexp.MustCompile(`v?(\d+\.\d+)`)
	match := versionMatcher.FindStringSubmatch(string(out))
	if len(match) < 2 {
		return "", fmt.Errorf("could not parse ipset version from output: %s", out)
	}
	return match[1], nil
}

func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		n1, _ := strconv.Atoi(parts1[i])
		n2, _ := strconv.Atoi(parts2[i])
		if n1 != n2 {
			if n1 > n2 {
				return 1
			}
			return -1
		}
	}
	return len(parts1) - len(parts2)
}

func ensureSetProperties(name string, set *IPSet) error {
	if set.Timeout <= 0 && !set.WithComments {
		return nil
	}
	data, err := exec.Command(ipsetPath, "save", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to inspect ipset %s: %v (%s)", name, err, data)
	}
	createLine, err := findCreateLine(data, name)
	if err != nil {
		return err
	}
	timeoutValue, hasTimeout := parseTimeoutValue(createLine)
	hasComment := strings.Contains(createLine, " comment")
	needRecreate := false
	if set.Timeout > 0 {
		if !hasTimeout || timeoutValue != set.Timeout {
			needRecreate = true
		}
	} else if hasTimeout && timeoutValue > 0 {
		needRecreate = true
	}
	if set.WithComments && !hasComment {
		needRecreate = true
	}
	if !needRecreate {
		return nil
	}
	logx.Infof("ipset %s missing required options; recreating", name)
	entries := extractAddLines(data, name)
	if set.Timeout <= 0 {
		for i, line := range entries {
			entries[i] = stripTimeoutOption(line)
		}
	}
	if err := recreateIPSetWithSwap(name, set, entries); err != nil {
		return err
	}
	return nil
}

func findCreateLine(data []byte, name string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "create ") {
			parts := strings.Fields(line)
			if len(parts) > 2 && parts[1] == name {
				return line, nil
			}
		}
	}
	return "", scanner.Err()
}

func extractAddLines(data []byte, name string) []string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "add ") {
			parts := strings.Fields(line)
			if len(parts) > 1 && parts[1] == name {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

var timeoutOptionPattern = regexp.MustCompile(`\s+timeout\s+\d+`)
var timeoutValuePattern = regexp.MustCompile(`\stimeout\s+(\d+)`)

func stripTimeoutOption(line string) string {
	return timeoutOptionPattern.ReplaceAllString(line, "")
}

func parseTimeoutValue(line string) (int, bool) {
	match := timeoutValuePattern.FindStringSubmatch(line)
	if len(match) < 2 {
		return 0, false
	}
	val, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return val, true
}

func recreateIPSetWithSwap(name string, set *IPSet, entries []string) error {
	temp := tempSetName(name, "-tmp")
	if err := set.createHashSet(temp); err != nil {
		return err
	}

	if len(entries) > 0 {
		script := &bytes.Buffer{}
		for _, line := range entries {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			line = replaceAddSetName(line, name, temp)
			script.WriteString(line)
			script.WriteByte('\n')
		}
		cmd := exec.Command(ipsetPath, "restore")
		cmd.Stdin = script
		if out, err := cmd.CombinedOutput(); err != nil {
			if derr := destroyIPSet(temp); derr != nil {
				logx.Warnf("ipset: failed to destroy temp set %s after failed restore: %v", temp, derr)
			}
			return fmt.Errorf("failed to restore ipset %s: %v (%s)", temp, err, out)
		}
	}

	if err := Swap(temp, name); err != nil {
		if derr := destroyIPSet(temp); derr != nil {
			logx.Warnf("ipset: failed to destroy temp set %s after failed swap: %v", temp, derr)
		}
		return err
	}
	if err := destroyIPSet(temp); err != nil {
		logx.Warnf("ipset: failed to destroy temp ipset %s: %v", temp, err)
	}
	return nil
}

func replaceAddSetName(line, oldName, newName string) string {
	prefix := "add " + oldName + " "
	if strings.HasPrefix(line, prefix) {
		return "add " + newName + " " + line[len(prefix):]
	}
	return line
}

type ipsetEntry struct {
	Entry   string
	Comment string
}

func parseCommentFromLine(line string) string {
	const key = " comment "
	idx := strings.Index(line, key)
	if idx == -1 {
		return ""
	}
	rest := line[idx+len(key):]
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, "\"") {
		rest = rest[1:]
		end := strings.Index(rest, "\"")
		if end == -1 {
			return strings.TrimSpace(rest)
		}
		return rest[:end]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func extractEntriesWithComments(data []byte, name string) []ipsetEntry {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var entries []ipsetEntry
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "add ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 || parts[1] != name {
			continue
		}
		entries = append(entries, ipsetEntry{
			Entry:   parts[2],
			Comment: parseCommentFromLine(line),
		})
	}
	return entries
}

func listEntriesWithComments(name string) ([]ipsetEntry, error) {
	if err := initCheck(); err != nil {
		return nil, err
	}
	if err := exec.Command(ipsetPath, "-q", "list", name).Run(); err != nil {
		return nil, nil
	}
	data, err := exec.Command(ipsetPath, "save", name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect ipset %s: %v (%s)", name, err, data)
	}
	return extractEntriesWithComments(data, name), nil
}

func entriesByCommentPrefix(name, prefix string) ([]string, error) {
	if prefix == "" {
		return nil, nil
	}
	entries, err := listEntriesWithComments(name)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Comment, prefix) {
			out = append(out, entry.Entry)
		}
	}
	return out, nil
}

func removeEntries(name string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}
	if err := initCheck(); err != nil {
		return err
	}
	if err := exec.Command(ipsetPath, "-q", "list", name).Run(); err != nil {
		return nil
	}

	var errs []error
	for _, entry := range entries {
		if out, err := exec.Command(ipsetPath, "del", name, entry, "-exist").CombinedOutput(); err != nil {
			logx.Warnf("ipset: failed to delete %s from %s: %v (%s)", entry, name, err, strings.TrimSpace(string(out)))
			errs = append(errs, fmt.Errorf("del %s: %w", entry, err))
		}
	}
	return errors.Join(errs...)
}
