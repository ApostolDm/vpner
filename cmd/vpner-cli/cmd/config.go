package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type CLIConfig struct {
	Unix     string `yaml:"unix"`
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
}

func loadCLIConfig(path string) (*CLIConfig, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".vpner.cnf")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil // не ошибка
	}

	var cfg CLIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("ошибка парсинга %s: %w", path, err)
	}

	return &cfg, nil
}
