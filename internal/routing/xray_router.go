package routing

import (
	"fmt"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/network"
)

type XrayRouter struct {
	iptables *network.IptablesManager
	lanIface string

	mu      sync.Mutex
	applied map[string]bool // chain -> applied
}

func NewXrayRouter(ipt *network.IptablesManager, lanInterface string) *XrayRouter {
	if lanInterface == "" {
		lanInterface = "br0"
	}
	return &XrayRouter{
		iptables: ipt,
		lanIface: lanInterface,
		applied:  make(map[string]bool),
	}
}

func (r *XrayRouter) Apply(chain string, info network.XrayInfoDetails) error {
	if r == nil || r.iptables == nil || r.lanIface == "" {
		return nil
	}
	if info.InboundPort == 0 {
		return fmt.Errorf("missing inbound port for chain %s", chain)
	}
	ipsetName, err := network.IpsetName("Xray", chain)
	if err != nil {
		return err
	}
	if err := network.EnsureIPSet(ipsetName, "hash:net", &network.Params{Timeout: network.DefaultIPSetTimeout}); err != nil {
		return fmt.Errorf("ensure ipset %s: %w", ipsetName, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.applied[chain] {
		return nil
	}
	if err := r.iptables.AddRules(network.Xray, ipsetName, info.InboundPort, r.lanIface, ""); err != nil {
		return err
	}
	r.applied[chain] = true
	return nil
}

func (r *XrayRouter) Remove(chain string) error {
	if r == nil || r.iptables == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.applied[chain] {
		return nil
	}
	ipsetName, err := network.IpsetName("Xray", chain)
	if err != nil {
		return err
	}
	if err := r.iptables.RemoveRules(ipsetName); err != nil {
		return err
	}
	delete(r.applied, chain)
	return nil
}

func (r *XrayRouter) Restore(info map[string]network.XrayInfoDetails, isRunning func(string) bool) {
	if r == nil || r.iptables == nil {
		return
	}
	for name, cfg := range info {
		if isRunning != nil && !isRunning(name) {
			continue
		}
		if err := r.Apply(name, cfg); err != nil {
			logging.Errorf("restore routing for %s: %v", name, err)
		}
	}
}

func (r *XrayRouter) Shutdown() {
	if r == nil || r.iptables == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.applied {
		ipsetName, err := network.IpsetName("Xray", name)
		if err == nil {
			_ = r.iptables.RemoveRules(ipsetName)
		}
		delete(r.applied, name)
	}
}

func (r *XrayRouter) ResetState() {
	if r == nil || r.iptables == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for chain := range r.applied {
		ipsetName, err := network.IpsetName("Xray", chain)
		if err == nil {
			_ = r.iptables.RemoveRules(ipsetName)
		}
		delete(r.applied, chain)
	}
}
