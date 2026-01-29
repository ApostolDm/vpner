package routing

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/network"
)

type XrayRouter struct {
	iptables  *network.IptablesManager
	lanIfaces []string

	mu      sync.Mutex
	applied map[string]appliedState // chain -> applied families

	ipv6Enabled bool
}

type appliedState struct {
	v4 bool
	v6 bool
}

func NewXrayRouter(ipt *network.IptablesManager, lanInterfaces []string, ipv6Enabled bool) *XrayRouter {
	lanIfaces := make([]string, 0, len(lanInterfaces))
	for _, iface := range lanInterfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		lanIfaces = append(lanIfaces, iface)
	}
	if len(lanIfaces) == 0 {
		lanIfaces = []string{"br0"}
	}
	return &XrayRouter{
		iptables:    ipt,
		lanIfaces:   lanIfaces,
		applied:     make(map[string]appliedState),
		ipv6Enabled: ipv6Enabled,
	}
}

func (r *XrayRouter) Apply(chain string, info network.XrayInfoDetails) error {
	return r.applyWithFamily(chain, info, true, r.ipv6Enabled)
}

func (r *XrayRouter) applyWithFamily(chain string, info network.XrayInfoDetails, applyV4, applyV6 bool) error {
	if r == nil || r.iptables == nil {
		return nil
	}
	if info.InboundPort == 0 {
		return fmt.Errorf("missing inbound port for chain %s", chain)
	}
	if applyV6 && !r.ipv6Enabled {
		applyV6 = false
	}
	if !applyV4 && !applyV6 {
		return nil
	}
	ipsetName, err := network.IpsetName("Xray", chain)
	if err != nil {
		return err
	}
	if applyV4 {
		if err := network.EnsureIPSet(ipsetName, "hash:net", &network.Params{Timeout: network.DefaultIPSetTimeout, WithComments: true}); err != nil {
			return fmt.Errorf("ensure ipset %s: %w", ipsetName, err)
		}
	}
	if applyV6 {
		ipsetName6, err := network.IpsetName6("Xray", chain)
		if err != nil {
			return err
		}
		if err := network.EnsureIPSet(ipsetName6, "hash:net", &network.Params{Timeout: network.DefaultIPSetTimeout, WithComments: true, HashFamily: "inet6"}); err != nil {
			return fmt.Errorf("ensure ipv6 ipset %s: %w", ipsetName6, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	state := r.applied[chain]
	if applyV4 && state.v4 {
		applyV4 = false
	}
	if applyV6 && state.v6 {
		applyV6 = false
	}
	if !applyV4 && !applyV6 {
		return nil
	}
	for _, iface := range r.lanIfaces {
		if applyV4 {
			if err := r.iptables.AddRulesV4(network.Xray, ipsetName, info.InboundPort, iface, ""); err != nil {
				return fmt.Errorf("apply v4 rules on %s: %w", iface, err)
			}
			state.v4 = true
		}
		if applyV6 {
			if err := r.iptables.AddRulesV6(network.Xray, ipsetName, info.InboundPort, iface, ""); err != nil {
				return fmt.Errorf("apply v6 rules on %s: %w", iface, err)
			}
			state.v6 = true
		}
	}
	r.applied[chain] = state
	return nil
}

func (r *XrayRouter) Remove(chain string) error {
	if r == nil || r.iptables == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.applied[chain]
	if !ok || (!state.v4 && !state.v6) {
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
	r.RestoreFamily(info, isRunning, true, r.ipv6Enabled)
}

func (r *XrayRouter) RestoreFamily(info map[string]network.XrayInfoDetails, isRunning func(string) bool, restoreV4, restoreV6 bool) {
	if r == nil || r.iptables == nil {
		return
	}
	if restoreV6 && !r.ipv6Enabled {
		restoreV6 = false
	}
	if !restoreV4 && !restoreV6 {
		return
	}
	for name, cfg := range info {
		if isRunning != nil && !isRunning(name) {
			continue
		}
		if err := r.applyWithFamily(name, cfg, restoreV4, restoreV6); err != nil {
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

func (r *XrayRouter) ResetStateFamily(resetV4, resetV6 bool) {
	if r == nil || r.iptables == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for chain, state := range r.applied {
		ipsetName, err := network.IpsetName("Xray", chain)
		if err != nil {
			continue
		}
		if resetV4 && state.v4 {
			_ = r.iptables.RemoveRulesV4(ipsetName)
			state.v4 = false
		}
		if resetV6 && state.v6 {
			_ = r.iptables.RemoveRulesV6(ipsetName)
			state.v6 = false
		}
		if !state.v4 && !state.v6 {
			delete(r.applied, chain)
		} else {
			r.applied[chain] = state
		}
	}
}
