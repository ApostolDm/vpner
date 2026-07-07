package routing

import (
	"github.com/ApostolDmitry/vpner/internal/firewall"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

type MarkRouter struct {
	iptables  *firewall.IptablesManager
	lanIfaces []string
}

func NewMarkRouter(ipt *firewall.IptablesManager, lanInterfaces []string) *MarkRouter {
	return &MarkRouter{iptables: ipt, lanIfaces: normalizeLANIfaces(lanInterfaces)}
}

func (r *MarkRouter) ready() bool {
	return r != nil && r.iptables != nil
}

func (r *MarkRouter) Apply(vpnType, chain, vpnIface string) error {
	if !r.ready() {
		return nil
	}

	ipsetName, err := firewall.IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	if r.iptables.MarkRouteKnown(ipsetName) {
		return nil
	}
	if err := r.iptables.EnsureMarkIPSets(ipsetName); err != nil {
		return err
	}
	return r.iptables.AddMarkRoute(vpnkind.Kind(vpnType), ipsetName, r.lanIfaces, vpnIface)
}

func (r *MarkRouter) Remove(vpnType, chain string) error {
	if !r.ready() {
		return nil
	}

	ipsetName, err := firewall.IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	return r.iptables.RemoveMarkRoute(ipsetName)
}
