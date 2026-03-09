package interfaces

import (
	"context"
	"fmt"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logging"
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

type InterfaceState struct {
	State string `json:"state"`
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

func (m *Manager) AddSS(id string, iface Interface) error {
	return m.addTrackedInterface(id, iface)
}

func (m *Manager) addTrackedInterface(id string, iface Interface) error {
	if err := m.store.Add(id, iface); err != nil {
		return err
	}
	logging.Infof("Added interface %s", id)
	return nil
}

func (m *Manager) DeleteInterface(id string) error {
	if err := m.store.Delete(id); err != nil {
		return err
	}
	logging.Infof("Removed interface %s", id)
	return nil
}

func (m *Manager) LoadInterfacesFromFile() (*VPNInterfaces, error) {
	return m.store.Load()
}

func (m *Manager) ListTrackedInterfaceIDs() (map[string]bool, error) {
	return m.store.ListIDs()
}

func (m *Manager) UpdateInterfaceAttribute(id, field, newValue string) error {
	updated, err := m.store.UpdateAttribute(id, field, newValue)
	if err != nil {
		return err
	}
	if !updated {
		logging.Infof("Field '%s' of interface '%s' is already '%s'; no update needed", field, id, newValue)
		return nil
	}
	logging.Infof("Updated field '%s' of interface '%s' to '%s'", field, id, newValue)
	return nil
}

func (m *Manager) LookupTrackedType(name string) (string, bool) {
	return m.store.LookupType(name)
}

func (m *Manager) LookupRouterType(name string) (string, bool) {
	return m.router.LookupType(context.Background(), name)
}

func (m *Manager) RestartInterface(ctx context.Context, interfaceName string, delaySeconds int, force bool) error {
	logPrefix := fmt.Sprintf("[RestartInterface:%s]", interfaceName)

	state, err := m.router.GetInterfaceState(ctx, interfaceName)
	if err != nil {
		return fmt.Errorf("%s failed to get current state: %w", logPrefix, err)
	}
	if state == "" {
		return fmt.Errorf("%s received empty state from API", logPrefix)
	}
	logging.Infof("%s current state: %s", logPrefix, state)

	ispState, err := m.router.GetISPState(ctx)
	if err != nil {
		return fmt.Errorf("%s failed to get ISP state: %w", logPrefix, err)
	}
	if ispState == "down" && !force {
		return fmt.Errorf("%s ISP appears to be down; use force=true to override", logPrefix)
	}
	logging.Infof("%s ISP state: %s", logPrefix, ispState)

	targetState := "up"
	if state == "up" {
		targetState = "down"
	}

	if targetState == state {
		logging.Infof("%s already in desired state '%s'; nothing to do", logPrefix, state)
		return nil
	}

	logging.Infof("%s setting state to '%s'...", logPrefix, targetState)
	if err := m.router.SetInterfaceState(ctx, interfaceName, targetState); err != nil {
		return fmt.Errorf("%s failed to set state to '%s': %w", logPrefix, targetState, err)
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("%s cancelled during wait: %w", logPrefix, ctx.Err())
	case <-time.After(time.Duration(delaySeconds) * time.Second):
	}

	logging.Infof("%s restoring original state '%s'...", logPrefix, state)
	if err := m.router.SetInterfaceState(ctx, interfaceName, state); err != nil {
		return fmt.Errorf("%s failed to restore original state '%s': %w", logPrefix, state, err)
	}

	logging.Infof("%s restart completed successfully", logPrefix)
	return nil
}

func (m *Manager) FetchInterfaces() (map[string]Interface, error) {
	return m.router.FetchInterfaces(context.Background())
}
