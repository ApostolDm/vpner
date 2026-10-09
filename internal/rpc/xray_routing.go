package rpc

import "github.com/ApostolDmitry/vpner/internal/logx"

func (s *VpnerServer) applyXrayRouting(chain string) error {
	info, err := s.xrayService.GetInfo(chain)
	if err != nil {
		return err
	}
	return s.iptables.ApplyXray(chain, info.InboundPort)
}

func (s *VpnerServer) removeXrayRouting(chain string) error {
	return s.iptables.RemoveXrayChain(chain)
}

func (s *VpnerServer) RestoreXrayRouting(restoreV4, restoreV6 bool, table string) {
	s.xrayMu.Lock()
	defer s.xrayMu.Unlock()
	infos, err := s.xrayService.ListInfo()
	if err != nil {
		logx.Errorf("failed to list Xray configs: %v", err)
		return
	}
	ports := make(map[string]int, len(infos))
	for name, info := range infos {
		if s.xrayService.IsRunning(name) {
			ports[name] = info.InboundPort
		}
	}
	s.iptables.RestoreXray(ports, restoreV4, restoreV6, table)
}

func (s *VpnerServer) DisableAllXrayRouting() {
	s.iptables.ShutdownXray()
}

func (s *VpnerServer) RoutingHealthy() bool {
	return s.iptables.RoutingIntact()
}

func (s *VpnerServer) ReconcileRouting() {
	s.iptables.ResetAfterFlush("", true, true)
	s.RestoreMarkRouting("")
	s.RestoreXrayRouting(true, true, "")
}
