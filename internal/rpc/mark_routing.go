package rpc

import (
	"errors"

	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/hookscope"
	"github.com/ApostolDmitry/vpner/internal/logx"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (s *VpnerServer) applyMarkRouting(vpnType, chainName string) error {
	if !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}
	resolve := s.ifManager.SystemNameResolver()

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.iptables.ApplyMark(vpnType, chainName, func() (string, error) {
		return resolve(chainName)
	})
}

func (s *VpnerServer) syncMarkRouting(vpnType, chainName string, resolve func(string) (string, error)) error {
	if !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.iptables.SyncMark(vpnType, chainName, func() (string, error) {
		return resolve(chainName)
	})
}

func (s *VpnerServer) removeMarkRouting(vpnType, chainName string) error {
	if !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.iptables.RemoveMark(vpnType, chainName)
}

func (s *VpnerServer) dropMarkRoutingIfUnused(vpnType, chainName string) error {
	if !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	if s.unblock.RuleCount(vpnType, chainName) > 0 {
		return nil
	}
	return s.iptables.RemoveMark(vpnType, chainName)
}

func (s *VpnerServer) handleInterfaceEvent(id, sysname, event string) {
	if id == "" {
		return
	}
	if event == hookscope.EventDown {
		logx.Infof("interface %s reported down; keeping routing until it returns", id)
		return
	}

	base := s.ifManager.SystemNameResolver()
	resolve := func(chain string) (string, error) {
		name, err := base(chain)
		if err != nil && sysname != "" {
			return sysname, nil
		}
		return name, err
	}

	for _, group := range s.markRoutedGroups() {
		if group.ChainName != id {
			continue
		}
		if err := s.syncMarkRouting(group.TypeName, group.ChainName, resolve); err != nil {
			if errors.Is(err, netif.ErrInterfaceDown) {
				logx.Debugf("interface %s up event but no address yet: %v", id, err)
			} else {
				logx.Warnf("interface %s up: restore routing: %v", id, err)
			}
			continue
		}
		logx.Infof("interface %s up: routing restored", id)
	}
}

func (s *VpnerServer) RestoreMarkRouting(table string) {
	if table != "" && table != hookscope.TableMangle {
		return
	}

	resolve := s.ifManager.SystemNameResolver()
	for _, group := range s.markRoutedGroups() {
		if err := s.syncMarkRouting(group.TypeName, group.ChainName, resolve); err != nil {
			if errors.Is(err, netif.ErrInterfaceDown) {
				logx.Debugf("skip %s routing for %s: %v", group.TypeName, group.ChainName, err)
			} else {
				logx.Warnf("restore %s routing for %s: %v", group.TypeName, group.ChainName, err)
			}
		}
	}
}

func (s *VpnerServer) MarkRoutingHealthy() bool {
	for _, group := range s.markRoutedGroups() {
		if !s.iptables.MarkIntact(group.TypeName, group.ChainName) {
			return false
		}
	}
	return true
}

func (s *VpnerServer) markRoutedGroups() []firewall.RuleGroup {
	var out []firewall.RuleGroup
	for _, group := range s.unblock.Groups() {
		if vpnkind.IsRouterManaged(group.TypeName) && len(group.Rules) > 0 {
			out = append(out, group)
		}
	}
	return out
}
