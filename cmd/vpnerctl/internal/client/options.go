package client

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Options struct {
	ConfigPath string
	Addr       string
	Unix       string
	Password   string
}

type ResolvedOptions struct {
	Addr     string
	Unix     string
	Password string
}

type fileConfig struct {
	Addr     string `yaml:"addr"`
	Unix     string `yaml:"unix"`
	Password string `yaml:"password"`
}

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

	if resolved.Addr == "" && fileCfg != nil && fileCfg.Addr != "" {
		resolved.Addr = fileCfg.Addr
	}
	if resolved.Unix == "" && fileCfg != nil && fileCfg.Unix != "" {
		resolved.Unix = fileCfg.Unix
	}
	if resolved.Password == "" && fileCfg != nil && fileCfg.Password != "" {
		resolved.Password = fileCfg.Password
	}

	if resolved.Addr == "" && resolved.Unix == "" {
		resolved.Unix = "/tmp/vpner.sock"
	}
	if resolved.Addr == "" {
		resolved.Addr = ":50051"
	}

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
