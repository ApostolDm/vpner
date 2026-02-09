package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Options struct {
	ConfigPath   string
	Addr         string
	Unix         string
	Password     string
	Timeout      string
	DefaultChain string
}

type ResolvedOptions struct {
	Addr         string
	Unix         string
	Password     string
	Timeout      time.Duration
	DefaultChain string
}

type fileConfig struct {
	Addr         string `yaml:"addr"`
	Unix         string `yaml:"unix"`
	Password     string `yaml:"password"`
	Timeout      string `yaml:"timeout"`
	DefaultChain string `yaml:"default-chain"`
}

const defaultTimeout = 5 * time.Second

func ResolveOptions(opts Options) (ResolvedOptions, error) {
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfgPath = filepath.Join(home, ".vpner.cnf")
		}
	}

	var fileCfg *fileConfig
	if cfgPath != "" {
		if cfg, err := readConfig(cfgPath); err != nil {
			return ResolvedOptions{}, err
		} else {
			fileCfg = cfg
		}
	}

	resolved := ResolvedOptions{
		Addr:     opts.Addr,
		Unix:     opts.Unix,
		Password: opts.Password,
	}
	timeoutValue := strings.TrimSpace(opts.Timeout)
	defaultChain := strings.TrimSpace(opts.DefaultChain)

	if resolved.Addr == "" && fileCfg != nil && fileCfg.Addr != "" {
		resolved.Addr = fileCfg.Addr
	}
	if resolved.Unix == "" && fileCfg != nil && fileCfg.Unix != "" {
		resolved.Unix = fileCfg.Unix
	}
	if resolved.Password == "" && fileCfg != nil && fileCfg.Password != "" {
		resolved.Password = fileCfg.Password
	}
	if timeoutValue == "" && fileCfg != nil && strings.TrimSpace(fileCfg.Timeout) != "" {
		timeoutValue = fileCfg.Timeout
	}
	if defaultChain == "" && fileCfg != nil && strings.TrimSpace(fileCfg.DefaultChain) != "" {
		defaultChain = fileCfg.DefaultChain
	}

	if resolved.Addr == "" && resolved.Unix == "" {
		resolved.Unix = "/tmp/vpner.sock"
	}
	if resolved.Addr == "" {
		resolved.Addr = ":50051"
	}

	if timeoutValue != "" {
		timeout, err := parseTimeout(timeoutValue)
		if err != nil {
			return ResolvedOptions{}, err
		}
		resolved.Timeout = timeout
	} else {
		resolved.Timeout = defaultTimeout
	}
	resolved.DefaultChain = strings.TrimSpace(defaultChain)

	return resolved, nil
}

func readConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg fileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseTimeout(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	if dur, err := time.ParseDuration(trimmed); err == nil {
		if dur < 0 {
			return 0, fmt.Errorf("timeout must be >= 0")
		}
		return dur, nil
	}
	seconds, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q (use 30s or number of seconds)", trimmed)
	}
	if seconds < 0 {
		return 0, fmt.Errorf("timeout must be >= 0")
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
