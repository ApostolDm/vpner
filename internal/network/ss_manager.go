package network

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"gopkg.in/yaml.v3"
)

const defaultSSConfigFile = "/opt/etc/vpner/vpner_ss.yaml"

type SSConfig struct {
	Host       string `json:"host"`
	ServerPort int    `json:"server_port"`
	LocalPort  int    `json:"local_port"`
	Mode       string `json:"mode"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Timeout    int    `json:"timeout"`
}

type SsManager struct {
	cachedConf map[string]*SSConfig
	ConfigFile string
	mu         sync.RWMutex
}

func NewSsManager(path string) *SsManager {
	if path == "" {
		path = defaultSSConfigFile
	}
	return &SsManager{
		ConfigFile: path,
		cachedConf: make(map[string]*SSConfig),
	}
}

func (ss *SsManager) сheckDependencies() error {
	if _, err := exec.LookPath("ss-redir"); err != nil {
		log.Fatalf("ss-redir not found in PATH: %v", err)
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
	if data == nil {
		return nil
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.cachedConf = data
	return nil
}

func (ss *SsManager) CreateSS(cfg SSConfig) error {
	if err := ss.сheckDependencies(); err != nil {
		return err
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()

	for _, existing := range ss.cachedConf {
		if ss.isSameConfig(&cfg, existing) {
			return fmt.Errorf("such configuration already exists")
		}
	}
	var newName string
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("ss%d", i)
		if _, exists := ss.cachedConf[candidate]; !exists {
			newName = candidate
			break
		}
	}
	ss.cachedConf[newName] = &cfg

	return ss.writeConfig()
}
func (ss *SsManager) DeleteSS(chainName string) error {
	if err := ss.сheckDependencies(); err != nil {
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

func (ss *SsManager) isSameConfig(a, b *SSConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Host == b.Host && a.ServerPort == b.ServerPort && a.LocalPort == b.LocalPort &&
		a.Mode == b.Mode && a.Password == b.Password && a.Method == b.Method && a.Timeout == b.Timeout
}

func (ss *SsManager) StartSS(ctx context.Context, chainName string) error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	config, exists := ss.cachedConf[chainName]
	if !exists {
		return fmt.Errorf("no such chain: %s", chainName)
	}

	cmdArgs := []string{
		"-t", fmt.Sprintf("%d", config.Timeout),
		"-l", fmt.Sprintf(":%d", config.LocalPort),
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

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ss-redir: %w", err)
	}

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("failed to kill ss-redir: %v", err)
		} else {
			log.Printf("ss-redir process killed successfully")
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("ss-redir exited with error: %w", err)
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
