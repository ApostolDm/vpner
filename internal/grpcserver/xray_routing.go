package grpcserver

import "github.com/ApostolDmitry/vpner/internal/logging"

func (s *VpnerServer) applyXrayRouting(chain string) error {
	if s.xrayRouter == nil {
		return nil
	}
	info, err := s.xrayService.GetInfo(chain)
	if err != nil {
		return err
	}
	return s.xrayRouter.Apply(chain, info)
}

func (s *VpnerServer) removeXrayRouting(chain string) error {
	if s.xrayRouter == nil {
		return nil
	}
	return s.xrayRouter.Remove(chain)
}

// RestoreXrayRouting rebuilds iptables rules for all running Xray chains.
// table may be "" (restore everything) or a specific table name.
func (s *VpnerServer) RestoreXrayRouting(restoreV4, restoreV6 bool, table string) {
	if s.xrayRouter == nil {
		return
	}
	infoMap, err := s.xrayService.ListInfo()
	if err != nil {
		logging.Errorf("failed to list Xray configs: %v", err)
		return
	}
	s.xrayRouter.Restore(infoMap, s.xrayService.IsRunning, restoreV4, restoreV6, table)
}

func (s *VpnerServer) DisableAllXrayRouting() {
	if s.xrayRouter != nil {
		s.xrayRouter.Shutdown()
	}
}
