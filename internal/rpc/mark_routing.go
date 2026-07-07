package rpc

import (
	"fmt"

	"github.com/ApostolDmitry/vpner/internal/hookscope"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (s *VpnerServer) applyMarkRouting(vpnType, chainName string) error {
	if s.markRouter == nil || !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}
	iface, ok := s.ifManager.LookupTracked(chainName)
	if !ok {
		return fmt.Errorf("interface %q is not tracked", chainName)
	}
	if iface.SystemName == "" {
		return fmt.Errorf("interface %q has no system name; delete and re-add it", chainName)
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.markRouter.Apply(vpnType, chainName, iface.SystemName)
}

func (s *VpnerServer) removeMarkRouting(vpnType, chainName string) error {
	if s.markRouter == nil || !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.markRouter.Remove(vpnType, chainName)
}

func (s *VpnerServer) dropMarkRoutingIfUnused(vpnType, chainName string) error {
	if s.markRouter == nil || !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	if s.unblock.RuleCount(vpnType, chainName) > 0 {
		return nil
	}
	return s.markRouter.Remove(vpnType, chainName)
}

func (s *VpnerServer) RestoreMarkRouting(table string) {
	if s.markRouter == nil {
		return
	}
	if table != "" && table != hookscope.TableMangle {
		return
	}

	groups, err := s.unblock.List()
	if err != nil {
		logx.Errorf("failed to list unblock rules: %v", err)
		return
	}
	for _, group := range groups {
		if !vpnkind.IsRouterManaged(group.TypeName) || len(group.Rules) == 0 {
			continue
		}
		if err := s.applyMarkRouting(group.TypeName, group.ChainName); err != nil {
			logx.Warnf("restore %s routing for %s: %v", group.TypeName, group.ChainName, err)
		}
	}
}
