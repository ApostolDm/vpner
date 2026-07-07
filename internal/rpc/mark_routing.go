package rpc

import (
	"github.com/ApostolDmitry/vpner/internal/hookscope"
	"github.com/ApostolDmitry/vpner/internal/logx"
	unblock "github.com/ApostolDmitry/vpner/internal/unblock"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func (s *VpnerServer) applyMarkRouting(vpnType, chainName string) error {
	if s.markRouter == nil || !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	resolve := s.ifManager.SystemNameResolver()

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.markRouter.Apply(vpnType, chainName, func() (string, error) {
		return resolve(chainName)
	})
}

func (s *VpnerServer) syncMarkRouting(vpnType, chainName string, resolve func(string) (string, error)) error {
	if s.markRouter == nil || !vpnkind.IsRouterManaged(vpnType) {
		return nil
	}

	s.markMu.Lock()
	defer s.markMu.Unlock()
	return s.markRouter.Sync(vpnType, chainName, func() (string, error) {
		return resolve(chainName)
	})
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

	resolve := s.ifManager.SystemNameResolver()
	for _, group := range s.markRoutedGroups() {
		if err := s.syncMarkRouting(group.TypeName, group.ChainName, resolve); err != nil {
			logx.Warnf("restore %s routing for %s: %v", group.TypeName, group.ChainName, err)
		}
	}
}

func (s *VpnerServer) MarkRoutingHealthy() bool {
	if s.markRouter == nil {
		return true
	}
	for _, group := range s.markRoutedGroups() {
		if !s.markRouter.Intact(group.TypeName, group.ChainName) {
			return false
		}
	}
	return true
}

func (s *VpnerServer) markRoutedGroups() []unblock.RuleGroup {
	groups, err := s.unblock.List()
	if err != nil {
		logx.Errorf("failed to list unblock rules: %v", err)
		return nil
	}

	var out []unblock.RuleGroup
	for _, group := range groups {
		if vpnkind.IsRouterManaged(group.TypeName) && len(group.Rules) > 0 {
			out = append(out, group)
		}
	}
	return out
}
