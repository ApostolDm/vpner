package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

const (
	defaultXrayBaseDir = "/opt/etc/vpner/xray"
	minInboundPort     = 1080
	maxInboundPort     = 20000
)

type ChainInfo struct {
	Type        string `json:"type"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	AutoRun     bool   `json:"auto_run"`
	InboundPort int    `json:"inbound_port"`
}

type Manager struct {
	mu            sync.RWMutex
	store         *store
	tproxyEnabled bool
}

func New(tproxyEnabled bool) (*Manager, error) {
	return newManager(defaultXrayBaseDir, tproxyEnabled)
}

func newManager(dir string, tproxyEnabled bool) (*Manager, error) {

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to prepare xray directory %s: %w", dir, err)
	}
	m := &Manager{store: &store{dir: dir}, tproxyEnabled: tproxyEnabled}
	m.store.migrateLegacy()
	return m, nil
}

func (x *Manager) Create(link string, autoRun bool) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if err := checkXrayBinary(); err != nil {
		return "", err
	}
	parsed, err := ParseLink(link)
	if err != nil {
		return "", err
	}
	port, err := x.findFreePort()
	if err != nil {
		return "", err
	}
	data, outbound, err := renderConfig(parsed, port, x.tproxyEnabled)
	if err != nil {
		return "", err
	}
	if dup, err := x.isDuplicate(outbound, ""); err != nil {
		return "", err
	} else if dup {
		return "", fmt.Errorf("duplicate configuration exists")
	}

	name := x.uniqueName()
	if err := x.write(name, link, parsed, port, autoRun, data); err != nil {
		return "", err
	}
	return name, nil
}

func (x *Manager) Update(name, link string) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if err := checkXrayBinary(); err != nil {
		return err
	}
	meta, err := x.store.readMeta(name)
	if err != nil {
		return notFound(name, err)
	}
	parsed, err := ParseLink(link)
	if err != nil {
		return err
	}

	port := meta.InboundPort
	if port == 0 {
		if port, err = x.findFreePort(); err != nil {
			return err
		}
	}
	data, outbound, err := renderConfig(parsed, port, x.tproxyEnabled)
	if err != nil {
		return err
	}
	if dup, err := x.isDuplicate(outbound, name); err != nil {
		return err
	} else if dup {
		return fmt.Errorf("duplicate configuration exists")
	}
	return x.write(name, link, parsed, port, meta.AutoRun, data)
}

func (x *Manager) Delete(name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.store.remove(name)
}

func (x *Manager) SetAutoRun(name string, autoRun bool) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	meta, err := x.store.readMeta(name)
	if err != nil {
		return notFound(name, err)
	}
	if meta.AutoRun == autoRun {
		return nil
	}
	meta.AutoRun = autoRun
	return x.store.writeMeta(name, meta)
}

func (x *Manager) write(name, link string, l *Link, port int, autoRun bool, configJSON []byte) error {
	meta := &chainMeta{
		Link:        link,
		Protocol:    string(l.Protocol),
		Address:     l.Address,
		Port:        l.Port,
		InboundPort: port,
		AutoRun:     autoRun,
	}
	if err := x.store.writeMeta(name, meta); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}
	if err := x.store.writeConfig(name, configJSON); err != nil {
		_ = x.store.remove(name)
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

func (x *Manager) Start(ctx context.Context, name string) error {
	if err := checkXrayBinary(); err != nil {
		return err
	}
	path, err := x.prepareConfig(name)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "xray", "run", "-config", path)
	prefix := fmt.Sprintf("xray-%s", name)
	cmd.Stdout = logx.NewStreamWriter(prefix, logx.LevelInfo)
	cmd.Stderr = logx.NewStreamWriter(prefix, logx.LevelWarn)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		logx.Errorf("[%s] exited with error: %v", prefix, err)
		return err
	}
	logx.Infof("[%s] exited cleanly", prefix)
	return nil
}

func (x *Manager) prepareConfig(name string) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	meta, err := x.store.readMeta(name)
	if err != nil {
		return "", notFound(name, err)
	}

	if meta.Link != "" {
		parsed, err := ParseLink(meta.Link)
		if err != nil {
			return "", err
		}
		data, _, err := renderConfig(parsed, meta.InboundPort, x.tproxyEnabled)
		if err != nil {
			return "", err
		}
		if err := x.store.writeConfig(name, data); err != nil {
			return "", err
		}
	} else if err := x.refreshLegacyConfig(name, meta); err != nil {
		return "", err
	}
	return x.store.configPath(name), nil
}

func (x *Manager) refreshLegacyConfig(name string, meta *chainMeta) error {
	_, outbounds, err := x.store.readConfigParts(name)
	if err != nil {
		return err
	}
	if len(outbounds) == 0 {
		return fmt.Errorf("config %s has no outbounds", name)
	}
	normalizeVLESSEncryption(outbounds)
	cfg := jobj{
		"inbounds":  []jobj{buildInbound(meta.InboundPort, x.tproxyEnabled)},
		"outbounds": outbounds,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return x.store.writeConfig(name, data)
}

func (x *Manager) List() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.store.chains()
}

func (x *Manager) ListAuto() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	names, err := x.store.chains()
	if err != nil {
		return nil, err
	}
	var auto []string
	for _, n := range names {
		if m, err := x.store.readMeta(n); err == nil && m.AutoRun {
			auto = append(auto, n)
		}
	}
	return auto, nil
}

func (x *Manager) Infos() (map[string]ChainInfo, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	names, err := x.store.chains()
	if err != nil {
		return nil, err
	}
	out := make(map[string]ChainInfo, len(names))
	for _, n := range names {
		if m, err := x.store.readMeta(n); err == nil {
			out[n] = m.toInfo()
		}
	}
	return out, nil
}

func (x *Manager) Get(name string) (ChainInfo, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	meta, err := x.store.readMeta(name)
	if err != nil {
		return ChainInfo{}, notFound(name, err)
	}
	return meta.toInfo(), nil
}

func (x *Manager) Test(name string) (string, error) {
	x.mu.RLock()
	meta, err := x.store.readMeta(name)
	configPath := x.store.configPath(name)
	x.mu.RUnlock()
	if err != nil {
		return "", notFound(name, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s):\n", name, meta.Protocol)

	if _, statErr := os.Stat(configPath); statErr != nil {
		b.WriteString("  config:  MISSING\n")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, terr := exec.CommandContext(ctx, "xray", "run", "-test", "-config", configPath).CombinedOutput()
		cancel()
		if terr == nil {
			b.WriteString("  config:  OK\n")
		} else {
			fmt.Fprintf(&b, "  config:  could not validate (%v): %s\n", terr, strings.TrimSpace(string(out)))
		}
	}

	if meta.Address != "" && meta.Port > 0 {
		addr := net.JoinHostPort(meta.Address, strconv.Itoa(meta.Port))
		conn, derr := net.DialTimeout("tcp", addr, 5*time.Second)
		if derr == nil {
			_ = conn.Close()
			fmt.Fprintf(&b, "  server:  reachable (%s)\n", addr)
		} else {
			fmt.Fprintf(&b, "  server:  UNREACHABLE (%s): %v\n", addr, derr)
		}
	}

	if meta.InboundPort > 0 {
		if isPortFree(meta.InboundPort) {
			fmt.Fprintf(&b, "  inbound: not listening on :%d (chain stopped?)\n", meta.InboundPort)
		} else {
			fmt.Fprintf(&b, "  inbound: listening on :%d\n", meta.InboundPort)
		}
	}

	return b.String(), nil
}

func (x *Manager) IsChain(name string) bool {
	if len(name) < 4 || name[:4] != "xray" {
		return false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.store.exists(name)
}

func (x *Manager) uniqueName() string {
	for i := 1; ; i++ {
		name := fmt.Sprintf("xray%d", i)
		if !x.store.exists(name) {
			return name
		}
	}
}

func (x *Manager) isDuplicate(outbound jobj, exclude string) (bool, error) {
	fp := fingerprint(outbound)
	names, err := x.store.chains()
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n == exclude {
			continue
		}
		ob, err := x.store.readConfigOutbound(n)
		if err != nil || ob == nil {
			continue
		}
		if fingerprint(ob) == fp {
			return true, nil
		}
	}
	return false, nil
}

func (x *Manager) findFreePort() (int, error) {
	used := x.usedPorts()
	span := maxInboundPort - minInboundPort
	for i := 0; i < 1000; i++ {
		port := minInboundPort + rand.Intn(span)
		if used[port] {
			continue
		}
		if isPortFree(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port found")
}

func (x *Manager) usedPorts() map[int]bool {
	used := make(map[int]bool)
	names, err := x.store.chains()
	if err != nil {
		return used
	}
	for _, n := range names {
		if m, err := x.store.readMeta(n); err == nil && m.InboundPort > 0 {
			used[m.InboundPort] = true
		}
	}
	return used
}

func fingerprint(ob jobj) string {
	data, _ := json.Marshal(ob)
	return string(data)
}

func checkXrayBinary() error {
	if _, err := exec.LookPath("xray"); err != nil {
		return fmt.Errorf("xray binary not found in PATH: %w", err)
	}
	return nil
}

func isPortFree(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = udp.Close()
	return true
}

func notFound(name string, err error) error {
	if os.IsNotExist(err) {
		return fmt.Errorf("no such xray config: %s", name)
	}
	return err
}
