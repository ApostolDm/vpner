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

func (r *MarkRouter) Apply(vpnType, chain string, resolveIface func() (string, error)) error {
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
	return r.install(vpnkind.Kind(vpnType), ipsetName, resolveIface)
}

func (r *MarkRouter) Sync(vpnType, chain string, resolveIface func() (string, error)) error {
	if !r.ready() {
		return nil
	}

	ipsetName, err := firewall.IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	if !r.iptables.MarkRouteKnown(ipsetName) {
		return r.install(vpnkind.Kind(vpnType), ipsetName, resolveIface)
	}

	if err := r.iptables.EnsureMarkIPSets(ipsetName); err != nil {
		return err
	}
	vpnIface, err := resolveIface()
	if err != nil {
		return err
	}
	return r.iptables.SyncMarkRoute(ipsetName, vpnIface)
}

func (r *MarkRouter) Intact(vpnType, chain string) bool {
	if !r.ready() {
		return true
	}

	ipsetName, err := firewall.IpsetName(vpnType, chain)
	if err != nil {
		return true
	}
	return r.iptables.MarkRouteIntact(ipsetName)
}

func (r *MarkRouter) install(kind vpnkind.Kind, ipsetName string, resolveIface func() (string, error)) error {
	vpnIface, err := resolveIface()
	if err != nil {
		return err
	}
	if err := r.iptables.EnsureMarkIPSets(ipsetName); err != nil {
		return err
	}
	return r.iptables.AddMarkRoute(kind, ipsetName, r.lanIfaces, vpnIface)
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
