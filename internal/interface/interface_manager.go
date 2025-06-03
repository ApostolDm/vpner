package manager_interface

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/utils"
	"gopkg.in/yaml.v3"
)

const defaultOutputFile = "/opt/etc/vpner/vpn_interfaces.yaml"

const (
	interfaceStatusURL  = "http://127.0.0.1:79/rci/show/interface"
	interfaceControlURL = "http://127.0.0.1:79/rci/interface"
)

type Interface struct {
	Type        string `json:"type" yaml:"type"`
	State       string `json:"state" yaml:"status"`
	Description string `json:"description" yaml:"description"`
	SystemName  string `json:"system_name" yaml:"system_name"`
	DefaultGW   bool   `json:"defaultgw" yaml:"defaultgw"`
	Global      bool   `json:"global" yaml:"global"`
	Address     string `json:"address" yaml:"address"`
}

type InterfaceState struct {
	State string `json:"state"`
}

type VPNInterfaces struct {
	Interfaces map[string]Interface `yaml:"interfaces"`
}

type Manager struct {
	OutputFile string
	mu         sync.RWMutex
}

func NewInterfaceManager(outputFile string) *Manager {
	if outputFile == "" {
		outputFile = defaultOutputFile
	}
	return &Manager{OutputFile: outputFile}
}

func (m *Manager) readVPNInterfaces() (*VPNInterfaces, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, err := os.Open(m.OutputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &VPNInterfaces{Interfaces: make(map[string]Interface)}, nil
		}
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var vpnInterfaces VPNInterfaces
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&vpnInterfaces)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to parse YAML file: %v", err)
	}

	if vpnInterfaces.Interfaces == nil {
		vpnInterfaces.Interfaces = make(map[string]Interface)
	}

	return &vpnInterfaces, nil
}

func (m *Manager) writeVPNInterfaces(vpnInterfaces *VPNInterfaces) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.OpenFile(m.OutputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %v", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()

	if err := encoder.Encode(vpnInterfaces); err != nil {
		return fmt.Errorf("failed to write YAML data: %v", err)
	}

	return nil
}

func (m *Manager) AddInterface(id string) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}
	interfaceMap, err := m.FetchInterfaces()
	if err != nil {
		return fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	iface, exists := interfaceMap[id]
	if !exists {
		return fmt.Errorf("interface %s not found", id)
	}

	if _, exists := vpnInterfaces.Interfaces[id]; exists {
		return fmt.Errorf("interface %s already added", id)
	}

	vpnInterfaces.Interfaces[id] = iface
	utils.LogF("Added interface %s", id)

	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) AddSS(id string, iface Interface) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}

	if _, exists := vpnInterfaces.Interfaces[id]; exists {
		return fmt.Errorf("interface %s already added", id)
	}

	vpnInterfaces.Interfaces[id] = iface
	utils.LogF("Added interface %s", id)

	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) DeleteInterface(id string) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}

	if _, exists := vpnInterfaces.Interfaces[id]; !exists {
		return fmt.Errorf("interface %s not found", id)
	}

	delete(vpnInterfaces.Interfaces, id)
	utils.LogF("Removed interface %s", id)

	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) LoadInterfacesFromFile() (*VPNInterfaces, error) {
	if err := utils.EnsureFileExists(m.OutputFile); err != nil {
		return nil, err
	}
	return m.readVPNInterfaces()
}

func (m *Manager) ListTrackedInterfaceIDs() (map[string]bool, error) {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return nil, err
	}

	added := make(map[string]bool)
	for id := range vpnInterfaces.Interfaces {
		added[id] = true
	}

	return added, nil
}

func (m *Manager) UpdateInterfaceAttribute(id, field, newValue string) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}

	iface, exists := vpnInterfaces.Interfaces[id]
	if !exists {
		return fmt.Errorf("interface with ID %s not found", id)
	}

	updated := false
	switch field {
	case "type":
		if iface.Type != newValue {
			iface.Type = newValue
			updated = true
		}
	case "status":
		if iface.State != newValue {
			iface.State = newValue
			updated = true
		}
	case "description":
		if iface.Description != newValue {
			iface.Description = newValue
			updated = true
		}
	case "system_name":
		if iface.SystemName != newValue {
			iface.SystemName = newValue
			updated = true
		}
	default:
		return fmt.Errorf("unknown field: %s", field)
	}

	if !updated {
		utils.LogF("Field '%s' of interface '%s' is already '%s'; no update needed", field, id, newValue)
		return nil
	}

	vpnInterfaces.Interfaces[id] = iface
	utils.LogF("Updated field '%s' of interface '%s' to '%s'", field, id, newValue)
	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) GetInterfaceTypeByNameFromVpner(name string) (string, bool) {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil || vpnInterfaces.Interfaces == nil {
		return "", false
	}

	iface, exists := vpnInterfaces.Interfaces[name]
	return iface.Type, exists
}

func (m *Manager) GetInterfaceTypeByNameFromRouter(name string) (string, bool) {
	vpnInterfaces, err := m.FetchInterfaces()
	if err != nil || vpnInterfaces == nil {
		return "", false
	}

	iface, exists := vpnInterfaces[name]
	return iface.Type, exists
}

func (m *Manager) RestartInterface(ctx context.Context, interfaceName string, delaySeconds int, force bool) error {
	logPrefix := fmt.Sprintf("[RestartInterface:%s]", interfaceName)

	state, err := m.getInterfaceState(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("%s failed to get current state: %w", logPrefix, err)
	}
	if state == "" {
		return fmt.Errorf("%s received empty state from API", logPrefix)
	}
	utils.LogF("%s current state: %s", logPrefix, state)

	ispState, err := m.getISPState(ctx)
	if err != nil {
		return fmt.Errorf("%s failed to get ISP state: %w", logPrefix, err)
	}
	if ispState == "down" && !force {
		return fmt.Errorf("%s ISP appears to be down — use force=true to override", logPrefix)
	}
	utils.LogF("%s ISP state: %s", logPrefix, ispState)

	targetState := "up"
	if state == "up" {
		targetState = "down"
	}

	if targetState == state {
		utils.LogF("%s already in desired state '%s'; nothing to do", logPrefix, state)
		return nil
	}

	utils.LogF("%s setting state to '%s'...", logPrefix, targetState)
	if err := m.setInterfaceStateWithContext(ctx, interfaceName, targetState); err != nil {
		return fmt.Errorf("%s failed to set state to '%s': %w", logPrefix, targetState, err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("%s cancelled during wait: %w", logPrefix, ctx.Err())
	case <-time.After(time.Duration(delaySeconds) * time.Second):
	}

	utils.LogF("%s restoring original state '%s'...", logPrefix, state)
	if err := m.setInterfaceStateWithContext(ctx, interfaceName, state); err != nil {
		return fmt.Errorf("%s failed to restore original state '%s': %w", logPrefix, state, err)
	}

	utils.LogF("%s restart completed successfully", logPrefix)
	return nil
}

func (m *Manager) setInterfaceStateWithContext(ctx context.Context, interfaceName, desiredState string) error {
	requestBody := map[string]string{desiredState: "true"}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (m *Manager) getInterfaceState(ctx context.Context, interfaceName string) (string, error) {
	url := fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch state: %w", err)
	}
	defer resp.Body.Close()

	var state InterfaceState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return "", fmt.Errorf("failed to decode state JSON: %w", err)
	}

	return state.State, nil
}

func (m *Manager) getISPState(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", interfaceStatusURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	defer resp.Body.Close()

	var interfaces []Interface
	if err := json.NewDecoder(resp.Body).Decode(&interfaces); err != nil {
		return "", fmt.Errorf("failed to decode interfaces JSON: %w", err)
	}

	for _, iface := range interfaces {
		if iface.DefaultGW && iface.Global {
			return iface.State, nil
		}
	}

	return "down", nil
}
func (m *Manager) FetchInterfaces() (map[string]Interface, error) {
	resp, err := http.Get(interfaceStatusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read interface response: %w", err)
	}

	var interfacesMap map[string]Interface
	if err := json.Unmarshal(body, &interfacesMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interface JSON: %w", err)
	}

	interfacesFiltered := make(map[string]Interface)

	allowedTypes := map[string]bool{
		"OpenVPN":   true,
		"Wireguard": true,
		"IKE":       true,
		"SSTP":      true,
		"PPPOE":     true,
		"L2TP":      true,
		"PPTP":      true,
	}

	for id, iface := range interfacesMap {
		if allowedTypes[iface.Type] {
			interfacesFiltered[id] = iface
		}
	}

	return interfacesFiltered, nil
}
