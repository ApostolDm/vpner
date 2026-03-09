package interfaces

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/fsutil"
	"gopkg.in/yaml.v3"
)

type trackedStore struct {
	outputFile string
	mu         sync.RWMutex
}

func newTrackedStore(outputFile string) *trackedStore {
	return &trackedStore{outputFile: outputFile}
}

func (s *trackedStore) Load() (*VPNInterfaces, error) {
	if err := fsutil.EnsureFile(s.outputFile); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	return cloneVPNInterfaces(cfg), nil
}

func (s *trackedStore) Add(id string, iface Interface) error {
	return s.modify(func(items map[string]Interface) error {
		if _, exists := items[id]; exists {
			return fmt.Errorf("interface %s already added", id)
		}
		items[id] = iface
		return nil
	})
}

func (s *trackedStore) Delete(id string) error {
	return s.modify(func(items map[string]Interface) error {
		if _, exists := items[id]; !exists {
			return fmt.Errorf("interface %s not found", id)
		}
		delete(items, id)
		return nil
	})
}

func (s *trackedStore) UpdateAttribute(id, field, newValue string) (bool, error) {
	updated := false
	err := s.modify(func(items map[string]Interface) error {
		iface, exists := items[id]
		if !exists {
			return fmt.Errorf("interface with ID %s not found", id)
		}

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

		if updated {
			items[id] = iface
		}
		return nil
	})
	return updated, err
}

func (s *trackedStore) LookupType(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, err := s.readLocked()
	if err != nil {
		return "", false
	}
	iface, exists := cfg.Interfaces[name]
	return iface.Type, exists
}

func (s *trackedStore) ListIDs() (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(cfg.Interfaces))
	for id := range cfg.Interfaces {
		ids[id] = true
	}
	return ids, nil
}

func (s *trackedStore) modify(fn func(map[string]Interface) error) error {
	if err := fsutil.EnsureFile(s.outputFile); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.readLocked()
	if err != nil {
		return err
	}
	if err := fn(cfg.Interfaces); err != nil {
		return err
	}
	return s.writeLocked(cfg)
}

func (s *trackedStore) readLocked() (*VPNInterfaces, error) {
	file, err := os.Open(s.outputFile)
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

func (s *trackedStore) writeLocked(vpnInterfaces *VPNInterfaces) error {
	file, err := os.OpenFile(s.outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
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

func cloneVPNInterfaces(src *VPNInterfaces) *VPNInterfaces {
	if src == nil {
		return &VPNInterfaces{Interfaces: make(map[string]Interface)}
	}
	out := &VPNInterfaces{Interfaces: make(map[string]Interface, len(src.Interfaces))}
	for id, iface := range src.Interfaces {
		out.Interfaces[id] = iface
	}
	return out
}
