package grpcserver

import "github.com/ApostolDmitry/vpner/internal/common/logging"

func (s *VpnerServer) applyXrayRouting(chain string) error {
	if s.xrayRouter == nil {
		return nil
	}
	info, err := s.xrayManager.GetXrayInfo(chain)
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

func (s *VpnerServer) RestoreXrayRouting() {
	if s.xrayRouter == nil {
		return
	}
	infoMap, err := s.xrayManager.ListXrayInfo()
	if err != nil {
		logging.Errorf("failed to list Xray configs: %v", err)
		return
	}
	s.xrayRouter.Restore(infoMap, s.xrayService.IsRunning)
}

func (s *VpnerServer) DisableAllXrayRouting() {
	if s.xrayRouter != nil {
		s.xrayRouter.Shutdown()
	}
}
