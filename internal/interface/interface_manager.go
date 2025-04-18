package manager_interface

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/utils"
	"gopkg.in/yaml.v3"
)

const defaultOutputFile = "/opt/etc/vpner/vpn_interfaces.yaml"

type Interface struct {
	Type        string `json:"type" yaml:"type"`
	State       string `json:"state" yaml:"status"`
	Description string `json:"description" yaml:"description"`
	SystemName  string `json:"system_name" yaml:"system_name"`
	DefaultGW   bool   `json:"defaultgw" yaml:"defaultgw"`
	Global      bool   `json:"global" yaml:"global"`
	Address     string `json:"address" yaml:"address"`
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
			return &VPNInterfaces{}, nil
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

func (m *Manager) AddOrRemoveInterface(id string, iface Interface) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}

	if vpnInterfaces.Interfaces == nil {
		vpnInterfaces.Interfaces = make(map[string]Interface)
	}

	if _, exists := vpnInterfaces.Interfaces[id]; exists {
		delete(vpnInterfaces.Interfaces, id)
	} else {
		vpnInterfaces.Interfaces[id] = iface
	}

	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) ReadInterfaces() (*VPNInterfaces, error) {
	if err := utils.EnsureFileExists(m.OutputFile); err != nil {
		return nil, err
	}
	return m.readVPNInterfaces()
}

func (m *Manager) ReadAddedInterfaces() (map[string]bool, error) {
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

func (m *Manager) UpdateInterfaceField(id, field, newValue string) error {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return err
	}

	if vpnInterfaces.Interfaces == nil {
		return fmt.Errorf("no interfaces found")
	}

	iface, exists := vpnInterfaces.Interfaces[id]
	if !exists {
		return fmt.Errorf("interface with ID %s not found", id)
	}

	needsUpdate := false

	switch field {
	case "type":
		if iface.Type != newValue {
			iface.Type = newValue
			needsUpdate = true
		}
	case "status":
		if iface.State != newValue {
			iface.State = newValue
			needsUpdate = true
		}
	case "description":
		if iface.Description != newValue {
			iface.Description = newValue
			needsUpdate = true
		}
	case "system_name":
		if iface.SystemName != newValue {
			iface.SystemName = newValue
			needsUpdate = true
		}
	default:
		return fmt.Errorf("unknown field: %s", field)
	}

	if !needsUpdate {
		fmt.Printf("Field '%s' of interface with ID '%s' already has value '%s'. No update needed.\n", field, id, newValue)
		return nil
	}

	vpnInterfaces.Interfaces[id] = iface

	return m.writeVPNInterfaces(vpnInterfaces)
}

func (m *Manager) PrintInterfaceTypeByName(name string) (string, bool) {
	vpnInterfaces, err := m.readVPNInterfaces()
	if err != nil {
		return "", false
	}

	if vpnInterfaces.Interfaces == nil {
		return "", false
	}

	iface, exists := vpnInterfaces.Interfaces[name]

	if exists {
		return iface.Type, true
	}
	return "", false
}
