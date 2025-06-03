package network

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const xrayBaseDir = "/opt/etc/vpner/xray/"

type VMessConfig struct {
	V    string `yaml:"v"`
	Ps   string `yaml:"ps"`
	Add  string `yaml:"add"`
	Port string `yaml:"port"`
	ID   string `yaml:"id"`
	Aid  string `yaml:"aid"`
	Net  string `yaml:"net"`
	Type string `yaml:"type"`
	Host string `yaml:"host"`
	Path string `yaml:"path"`
	TLS  string `yaml:"tls"`
}

type XrayInfoDetails struct {
	Type    string `yaml:"type"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	AutoRun bool   `yaml:"auto_run"`
}

type XrayManager struct {
	mu sync.RWMutex
}

func NewXrayManager() *XrayManager {
	return &XrayManager{}
}

func (x *XrayManager) configPath(name string) string {
	return filepath.Join(xrayBaseDir, name+".yaml")
}

func (x *XrayManager) checkDependencies() error {
	if _, err := exec.LookPath("xray"); err != nil {
		return fmt.Errorf("xray binary not found in PATH: %w", err)
	}
	return nil
}

func (x *XrayManager) parseVLESS(link string) (map[string]string, error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" {
		return nil, fmt.Errorf("invalid VLESS URL")
	}
	q := u.Query()
	return map[string]string{
		"uuid":       u.User.Username(),
		"address":    u.Hostname(),
		"port":       u.Port(),
		"encryption": q.Get("encryption"),
		"security":   q.Get("security"),
		"type":       q.Get("type"),
		"sni":        q.Get("sni"),
	}, nil
}

func (x *XrayManager) parseVMESS(link string) (*VMessConfig, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	var cfg VMessConfig
	if err := yaml.Unmarshal(decoded, &cfg); err != nil {
		return nil, fmt.Errorf("invalid VMess YAML: %w", err)
	}
	return &cfg, nil
}

func (x *XrayManager) parseSS(link string) (map[string]string, error) {
	raw := strings.TrimPrefix(link, "ss://")
	if strings.Contains(raw, "@") {
		parts := strings.Split(raw, "@")
		decoded, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid base64: %w", err)
		}
		auth := strings.Split(string(decoded), ":")
		addr := strings.Split(parts[1], ":")
		return map[string]string{
			"method":   auth[0],
			"password": auth[1],
			"address":  addr[0],
			"port":     addr[1],
		}, nil
	}
	return nil, fmt.Errorf("unsupported SS link format")
}

func (x *XrayManager) getUsedInboundPorts() map[int]bool {
	used := make(map[int]bool)
	entries, _ := os.ReadDir(xrayBaseDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(xrayBaseDir, e.Name()))
		var config map[string]interface{}
		_ = yaml.Unmarshal(data, &config)
		if inbounds, ok := config["inbounds"].([]interface{}); ok {
			for _, in := range inbounds {
				if inMap, ok := in.(map[string]interface{}); ok {
					if p, ok := inMap["port"].(int); ok {
						used[p] = true
					}
				}
			}
		}
	}
	return used
}

func (x *XrayManager) findFreePort(min, max int) (int, error) {
	used := x.getUsedInboundPorts()
	for i := 0; i < 1000; i++ {
		port := rand.Intn(max-min) + min
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free port found")
}

func (x *XrayManager) generateUniqueName() string {
	for i := 1; ; i++ {
		name := fmt.Sprintf("xray%d", i)
		if _, err := os.Stat(x.configPath(name)); os.IsNotExist(err) {
			return name
		}
	}
}

func (x *XrayManager) isDuplicate(newConfig map[string]interface{}) bool {
	entries, _ := os.ReadDir(xrayBaseDir)
	for _, f := range entries {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(xrayBaseDir, f.Name()))
		if err != nil {
			continue
		}
		var existing map[string]interface{}
		if err := yaml.Unmarshal(data, &existing); err != nil {
			continue
		}
		existingOut, _ := yaml.Marshal(existing["outbounds"])
		newOut, _ := yaml.Marshal(newConfig["outbounds"])
		if string(existingOut) == string(newOut) {
			return true
		}
	}
	return false
}

func (x *XrayManager) CreateXray(link string, autoRun bool) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	if err := x.checkDependencies(); err != nil {
		return "", err
	}

	port, err := x.findFreePort(1080, 20000)
	if err != nil {
		return "", err
	}

	var config map[string]interface{}

	switch {
	case strings.HasPrefix(link, "vless://"):
		cfg, err := x.parseVLESS(link)
		if err != nil {
			return "", err
		}
		config = generateVLESSConfig(cfg, port)
	case strings.HasPrefix(link, "vmess://"):
		cfg, err := x.parseVMESS(link)
		if err != nil {
			return "", err
		}
		config = generateVMESSConfig(cfg, port)
	case strings.HasPrefix(link, "ss://"):
		cfg, err := x.parseSS(link)
		if err != nil {
			return "", err
		}
		config = generateSSConfig(cfg, port)
	default:
		return "", fmt.Errorf("unsupported link scheme")
	}

	if x.isDuplicate(config) {
		return "", fmt.Errorf("duplicate configuration exists")
	}

	config["auto_run"] = autoRun
	name := x.generateUniqueName()
	data, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(x.configPath(name), data, 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}
	return name, nil
}

func (x *XrayManager) DeleteXray(name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkDependencies(); err != nil {
		return err
	}
	return os.Remove(x.configPath(name))
}

func (x *XrayManager) StartXray(ctx context.Context, name string) error {
	x.mu.RLock()
	configPath := x.configPath(name)
	_, err := os.Stat(configPath)
	x.mu.RUnlock()

	if err := x.checkDependencies(); err != nil {
		return err
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("no such xray config: %s", name)
	} else if err != nil {
		return fmt.Errorf("failed to stat config: %w", err)
	}

	cmd := exec.CommandContext(ctx, "xray", "run", "-config", configPath)
	prefix := fmt.Sprintf("[xray-%s] ", name)
	cmd.Stdout = &taggedPrefixWriter{prefix: prefix, target: os.Stdout}
	cmd.Stderr = &taggedPrefixWriter{prefix: prefix, target: os.Stderr}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start xray: %w", err)
	}

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			fmt.Fprintf(os.Stderr, "[xray-%s] failed to kill: %v\n", name, err)
		} else {
			fmt.Fprintf(os.Stderr, "[xray-%s] process killed by context\n", name)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited with error: %v\n", name, err)
	} else {
		fmt.Fprintf(os.Stderr, "[xray-%s] exited cleanly\n", name)
	}
	return nil
}

func (x *XrayManager) ListXray() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(xrayBaseDir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			list = append(list, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return list, nil
}

func (x *XrayManager) ListAutoRun() ([]string, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(xrayBaseDir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(xrayBaseDir, e.Name()))
		if err != nil {
			continue
		}
		var cfg map[string]interface{}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if auto, ok := cfg["auto_run"].(bool); ok && auto {
			list = append(list, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return list, nil
}

func (x *XrayManager) ListXrayInfo() (map[string]XrayInfoDetails, error) {
	x.mu.RLock()
	defer x.mu.RUnlock()

	entries, err := os.ReadDir(xrayBaseDir)
	if err != nil {
		return nil, err
	}

	result := make(map[string]XrayInfoDetails)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(xrayBaseDir, e.Name()))
		if err != nil {
			continue
		}
		var cfg map[string]interface{}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		autoRun, _ := cfg["auto_run"].(bool)
		var host string
		var port int
		outbounds, ok := cfg["outbounds"].([]interface{})
		if !ok || len(outbounds) == 0 {
			continue
		}
		ob, ok := outbounds[0].(map[string]interface{})
		if !ok {
			continue
		}
		protocol, _ := ob["protocol"].(string)
		settings, _ := ob["settings"].(map[string]interface{})
		switch protocol {
		case "vmess", "vless":
			if vnextList, ok := settings["vnext"].([]interface{}); ok && len(vnextList) > 0 {
				if vnext, ok := vnextList[0].(map[string]interface{}); ok {
					host, _ = vnext["address"].(string)
					if p, ok := vnext["port"].(int); ok {
						port = p
					} else if pf, ok := vnext["port"].(float64); ok {
						port = int(pf)
					}
				}
			}
		case "shadowsocks":
			if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
				if s, ok := servers[0].(map[string]interface{}); ok {
					host, _ = s["address"].(string)
					if p, ok := s["port"].(int); ok {
						port = p
					} else if pf, ok := s["port"].(float64); ok {
						port = int(pf)
					}
				}
			}
		}
		result[name] = XrayInfoDetails{
			Type:    protocol,
			Host:    host,
			Port:    port,
			AutoRun: autoRun,
		}
	}
	return result, nil
}

func (x *XrayManager) IsXrayChain(name string) bool {
	if len(name) < 4 || name[:4] != "xray" {
		return false
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	list, err := x.ListXray()
	if err != nil {
		return false
	}
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}

type taggedPrefixWriter struct {
	prefix string
	target io.Writer
}

func (w *taggedPrefixWriter) Write(p []byte) (int, error) {
	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		if line != "" {
			_, err := fmt.Fprintf(w.target, "%s%s\n", w.prefix, line)
			if err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func generateVLESSConfig(cfg map[string]string, port int) map[string]interface{} {
	encryption := cfg["encryption"]
	if encryption == "" {
		encryption = "none"
	}
	return map[string]interface{}{
		"inbounds": []map[string]interface{}{{
			"port":     port,
			"protocol": "socks",
			"settings": map[string]interface{}{
				"udp": true,
			},
		}},
		"outbounds": []map[string]interface{}{{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []map[string]interface{}{{
					"address": cfg["address"],
					"port":    toInt(cfg["port"]),
					"users": []map[string]interface{}{{
						"id":         cfg["uuid"],
						"encryption": encryption,
					}},
				}},
			},
			"streamSettings": map[string]interface{}{
				"network":  cfg["type"],
				"security": cfg["security"],
				"tlsSettings": map[string]interface{}{
					"serverName": cfg["sni"],
				},
			},
		}},
	}
}

func generateVMESSConfig(cfg *VMessConfig, port int) map[string]interface{} {
	return map[string]interface{}{
		"inbounds": []map[string]interface{}{{
			"port":     port,
			"protocol": "socks",
			"settings": map[string]interface{}{
				"udp": true,
			},
		}},
		"outbounds": []map[string]interface{}{{
			"protocol": "vmess",
			"settings": map[string]interface{}{
				"vnext": []map[string]interface{}{{
					"address": cfg.Add,
					"port":    toInt(cfg.Port),
					"users": []map[string]interface{}{{
						"id":       cfg.ID,
						"alterId":  toInt(cfg.Aid),
						"security": "auto",
					}},
				}},
			},
			"streamSettings": map[string]interface{}{
				"network":  cfg.Net,
				"security": cfg.TLS,
				"tlsSettings": map[string]interface{}{
					"serverName": cfg.Host,
				},
			},
		}},
	}
}

func generateSSConfig(cfg map[string]string, port int) map[string]interface{} {
	return map[string]interface{}{
		"inbounds": []map[string]interface{}{{
			"port":     port,
			"protocol": "socks",
			"settings": map[string]interface{}{
				"udp": true,
			},
		}},
		"outbounds": []map[string]interface{}{{
			"protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{{
					"address":  cfg["address"],
					"port":     toInt(cfg["port"]),
					"method":   cfg["method"],
					"password": cfg["password"],
				}},
			},
		}},
	}
}
