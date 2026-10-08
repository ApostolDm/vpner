package firewall

import "github.com/ApostolDmitry/vpner/internal/logx"

func (i *IptablesManager) ApplyXray(chain string, port int) error {
	spec, state, err := i.PrepareXrayChain(chain, port, i.lanIfaces)
	if err != nil {
		return err
	}
	if state.V4Applied && (state.V6Applied || !i.ipv6Enabled) {
		return nil
	}
	if i.tproxyEnabled {
		return i.BatchApplyAllTProxy([]ChainSpec{spec})
	}
	return i.BatchApplyAllRedirect([]ChainSpec{spec})
}

func (i *IptablesManager) RestoreXray(ports map[string]int, restoreV4, restoreV6 bool, table string) {
	if restoreV6 && !i.ipv6Enabled {
		restoreV6 = false
	}
	if !restoreV4 && !restoreV6 {
		return
	}
	if table == "" || table == i.XrayTable() {
		for name, port := range ports {
			if _, _, err := i.PrepareXrayChain(name, port, i.lanIfaces); err != nil {
				logx.Errorf("prepare xray chain %s: %v", name, err)
			}
		}
	}
	i.RestoreRouting(table, restoreV4, restoreV6)
}

func (i *IptablesManager) ShutdownXray() {
	i.RemoveAllXrayRoutes()
	i.Shutdown()
}
