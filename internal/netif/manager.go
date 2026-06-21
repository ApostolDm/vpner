package netif

import (
	"context"
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/logx"
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
	store  *trackedStore
	router *routerClient
}

func NewInterfaceManager(outputFile string) *Manager {
	if outputFile == "" {
		outputFile = defaultOutputFile
	}
	return &Manager{
		store:  newTrackedStore(outputFile),
		router: newRouterClient(nil),
	}
}

func (m *Manager) AddInterface(id string) error {
	interfaceMap, err := m.FetchInterfaces()
	if err != nil {
		return fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	iface, exists := interfaceMap[id]
	if !exists {
		return fmt.Errorf("interface %s not found", id)
	}
	return m.addTrackedInterface(id, iface)
}

func (m *Manager) addTrackedInterface(id string, iface Interface) error {
	if err := m.store.Add(id, iface); err != nil {
		return err
	}
	logx.Infof("Added interface %s", id)
	return nil
}

func (m *Manager) DeleteInterface(id string) error {
	if err := m.store.Delete(id); err != nil {
		return err
	}
	logx.Infof("Removed interface %s", id)
	return nil
}

func (m *Manager) LoadInterfacesFromFile() (*VPNInterfaces, error) {
	return m.store.Load()
}

func (m *Manager) LookupTrackedType(name string) (string, bool) {
	return m.store.LookupType(name)
}

func (m *Manager) LookupRouterType(name string) (string, bool) {
	return m.router.LookupType(context.Background(), name)
}

func (m *Manager) FetchInterfaces() (map[string]Interface, error) {
	return m.router.FetchInterfaces(context.Background())
}
