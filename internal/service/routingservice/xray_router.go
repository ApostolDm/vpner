package routingservice

import (
	"strings"

	"github.com/ApostolDmitry/vpner/internal/logging"
	"github.com/ApostolDmitry/vpner/internal/network"
	xraypkg "github.com/ApostolDmitry/vpner/internal/xray"
)

type XrayRouter struct {
	iptables  *network.IptablesManager
	lanIfaces []string
}

func NewXrayRouter(ipt *network.IptablesManager, lanInterfaces []string) *XrayRouter {
	lanIfaces := make([]string, 0, len(lanInterfaces))
	for _, iface := range lanInterfaces {
		if iface = strings.TrimSpace(iface); iface != "" {
			lanIfaces = append(lanIfaces, iface)
		}
	}
	if len(lanIfaces) == 0 {
		lanIfaces = []string{"br0"}
	}
	return &XrayRouter{iptables: ipt, lanIfaces: lanIfaces}
}

func (r *XrayRouter) ready() bool {
	return r != nil && r.iptables != nil
}

func (r *XrayRouter) Apply(chain string, info xraypkg.XrayInfoDetails) error {
	if !r.ready() {
		return nil
	}

	spec, state, err := r.iptables.PrepareXrayChain(chain, info.InboundPort, r.lanIfaces)
	if err != nil {
		return err
	}
	if state.V4Applied && (state.V6Applied || !r.iptables.IPv6Enabled()) {
		return nil
	}

	if r.iptables.TProxyEnabled() {
		return r.iptables.BatchApplyAllTProxy([]network.ChainSpec{spec})
	}
	return r.iptables.BatchApplyAllRedirect([]network.ChainSpec{spec})
}

func (r *XrayRouter) Remove(chain string) error {
	if !r.ready() {
		return nil
	}
	return r.iptables.RemoveXrayChain(chain)
}

func (r *XrayRouter) ClearAppliedState(table string, clearV4, clearV6 bool) {
	if !r.ready() {
		return
	}
	r.iptables.ResetAfterFlush(table, clearV4, clearV6)
}

func (r *XrayRouter) ResetStateFamily(resetV4, resetV6 bool) {
	if !r.ready() {
		return
	}
	r.iptables.ResetXrayFamilies(resetV4, resetV6)
}

func (r *XrayRouter) Restore(info map[string]xraypkg.XrayInfoDetails, isRunning func(string) bool, restoreV4, restoreV6 bool, table string) {
	if !r.ready() {
		return
	}
	if restoreV6 && !r.iptables.IPv6Enabled() {
		restoreV6 = false
	}
	if !restoreV4 && !restoreV6 {
		return
	}

	xrayTable := r.iptables.XrayTable()
	if table == "" || table == xrayTable {
		for name, cfg := range info {
			if isRunning != nil && !isRunning(name) {
				continue
			}
			if _, _, err := r.iptables.PrepareXrayChain(name, cfg.InboundPort, r.lanIfaces); err != nil {
				logging.Errorf("prepare xray chain %s: %v", name, err)
			}
		}
	}

	r.iptables.RestoreRouting(table, restoreV4, restoreV6)
}

func (r *XrayRouter) Shutdown() {
	if !r.ready() {
		return
	}
	r.iptables.RemoveAllXrayRoutes()
	r.iptables.Shutdown()
}
