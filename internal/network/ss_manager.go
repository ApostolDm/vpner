package network

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/utils"
	"gopkg.in/yaml.v3"
)

const defaultSSConfigFile = "/opt/etc/vpner/vpner_ss.yaml"
const defaultVpnType = "Shadowsocks"

type SSminConfig struct {
	Host       string `yaml:"host"`
	ServerPort int    `yaml:"server_port"`
	Mode       string `yaml:"mode"`
	Password   string `yaml:"password"`
	Method     string `yaml:"method"`
	AutoRun    bool   `yaml:"auto_run"`
}

type SSConfig struct {
	SSminConfig `yaml:",inline"`
	LocalPort   int `yaml:"local_port"`
	Timeout     int `yaml:"timeout"`
}

type SsManager struct {
	cachedConf map[string]*SSConfig
	ConfigFile string
	mu         sync.RWMutex
	iptables   *IptablesManager
}

type taggedPrefixWriter struct {
	prefix string
	target io.Writer
	buf    []byte
}

func (w *taggedPrefixWriter) Write(p []byte) (int, error) {
	start := 0
	for i, b := range p {
		if b == '\n' {
			line := append([]byte(w.prefix), p[start:i+1]...)
			if _, err := w.target.Write(line); err != nil {
				return 0, err
			}
			start = i + 1
		}
	}
	if start < len(p) {
		w.buf = append(w.buf, p[start:]...)
	}
	return len(p), nil
}

func NewSsManager(path string, iptables *IptablesManager) *SsManager {
	if path == "" {
		path = defaultSSConfigFile
	}
	return &SsManager{
		ConfigFile: path,
		cachedConf: make(map[string]*SSConfig),
		iptables:   iptables,
	}
}

func (ss *SsManager) checkDependencies() error {
	if _, err := exec.LookPath("ss-redir"); err != nil {
		return fmt.Errorf("ss-redir not found in PATH: %v", err)
	}
	return nil
}

func (ss *SsManager) Init() error {
	if ss.ConfigFile == "" {
		ss.ConfigFile = defaultSSConfigFile
	}
	data, err := ss.loadFromFile()
	if err != nil {
		return err
	}
	if data != nil {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		ss.cachedConf = data
	}
	return nil
}

func (ss *SsManager) validateSSminConfig(min *SSminConfig) error {
	if min.Host == "" {
		return fmt.Errorf("host is required")
	}
	if min.ServerPort <= 0 || min.ServerPort > 65535 {
		return fmt.Errorf("invalid server port: %d", min.ServerPort)
	}
	switch min.Mode {
	case "tcp", "udp", "tcp_and_udp":
	default:
		return fmt.Errorf("invalid mode: %s", min.Mode)
	}
	if min.Password == "" {
		return fmt.Errorf("password is required")
	}
	if min.Method == "" {
		return fmt.Errorf("method is required")
	}
	return nil
}

func (ss *SsManager) CreateSS(min SSminConfig) error {
	if err := ss.checkDependencies(); err != nil {
		return err
	}
	if err := ss.validateSSminConfig(&min); err != nil {
		return err
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()

	usedPorts := make(map[int]bool)
	for _, existing := range ss.cachedConf {
		usedPorts[existing.LocalPort] = true
		if ss.isSameMinConfig(&min, existing) {
			return fmt.Errorf("a configuration with the same parameters already exists")
		}
	}

	localPort, err := findFreePort(usedPorts, 1080, 11000)
	if err != nil {
		return err
	}

	cfg := SSConfig{
		SSminConfig: min,
		LocalPort:   localPort,
		Timeout:     300,
	}

	newName := ss.generateUniqueName()
	ss.cachedConf[newName] = &cfg
	return ss.writeConfig()
}

func (ss *SsManager) isSameMinConfig(min *SSminConfig, full *SSConfig) bool {
	return min.Host == full.Host &&
		min.ServerPort == full.ServerPort &&
		min.Mode == full.Mode &&
		min.Password == full.Password &&
		min.Method == full.Method
}

func (ss *SsManager) DeleteSS(chainName string) error {
	if err := ss.checkDependencies(); err != nil {
		return err
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()

	if _, exists := ss.cachedConf[chainName]; !exists {
		return fmt.Errorf("no such chain: %s", chainName)
	}
	delete(ss.cachedConf, chainName)
	return ss.writeConfig()
}

func (ss *SsManager) loadFromFile() (map[string]*SSConfig, error) {
	file, err := os.Open(ss.ConfigFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	config := make(map[string]*SSConfig)
	if err := yaml.NewDecoder(file).Decode(&config); err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	return config, nil
}

func (ss *SsManager) writeConfig() error {
	file, err := os.OpenFile(ss.ConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if err := yaml.NewEncoder(file).Encode(ss.cachedConf); err != nil {
		return fmt.Errorf("failed to write YAML: %w", err)
	}
	return nil
}

func (ss *SsManager) StartSS(ctx context.Context, chainName string) error {
	ss.mu.RLock()
	config, exists := ss.cachedConf[chainName]
	ss.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no such chain: %s", chainName)
	}

	cmdArgs := []string{
		"-t", fmt.Sprintf("%d", config.Timeout),
		"-l", fmt.Sprintf("%d", config.LocalPort),
		"-s", config.Host,
		"-p", fmt.Sprintf("%d", config.ServerPort),
		"-m", config.Method,
		"-k", config.Password,
	}

	switch config.Mode {
	case "tcp":
		cmdArgs = append(cmdArgs, "-T")
	case "udp":
		cmdArgs = append(cmdArgs, "-U")
	case "tcp_and_udp":
		cmdArgs = append(cmdArgs, "-T", "-u")
	default:
		return fmt.Errorf("unsupported mode: %s", config.Mode)
	}

	cmd := exec.Command("ss-redir", cmdArgs...)
	prefix := fmt.Sprintf("[ss-%s] ", chainName)
	cmd.Stdout = &taggedPrefixWriter{prefix: prefix, target: os.Stdout}
	cmd.Stderr = &taggedPrefixWriter{prefix: prefix, target: os.Stderr}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ss-redir: %w", err)
	}

	ipsetName, err := utils.GetIpsetName(defaultVpnType, chainName)
	if err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("failed to get ipset name: %w", err)
	}

	if err := ss.iptables.AddRules(defaultVpnType, ipsetName, config.LocalPort, "br0", ""); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("failed to add iptables rules: %w", err)
	}

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("failed to kill ss-redir: %v", err)
		} else {
			log.Printf("ss-redir process killed successfully")
		}
		if err := ss.iptables.RemoveRules(ipsetName); err != nil {
			log.Printf("failed to delete iptables rules: %v", err)
		} else {
			log.Printf("iptables rules deleted successfully")
		}
	}()
	if err := cmd.Wait(); err != nil {
		log.Printf("ss-redir (%s) exited with error: %v", chainName, err)
	} else if !cmd.ProcessState.Success() {
		log.Printf("ss-redir (%s) exited non-zero: %s", chainName, cmd.ProcessState.String())
	} else {
		log.Printf("ss-redir (%s) exited normally", chainName)
	}
	return nil
}

func (ss *SsManager) GetAll() map[string]*SSConfig {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	copy := make(map[string]*SSConfig)
	for k, v := range ss.cachedConf {
		copy[k] = v
	}
	return copy
}

func findFreePort(used map[int]bool, min, max int) (int, error) {
	for port := min; port <= max; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free local port in range %d–%d", min, max)
}

func (ss *SsManager) generateUniqueName() string {
	for i := 1; ; i++ {
		name := fmt.Sprintf("ss%d", i)
		if _, exists := ss.cachedConf[name]; !exists {
			return name
		}
	}
}
