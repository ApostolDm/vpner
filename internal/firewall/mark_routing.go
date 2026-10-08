package firewall

import "github.com/ApostolDmitry/vpner/internal/vpnkind"

func (i *IptablesManager) ApplyMark(vpnType, chain string, resolveIface func() (string, error)) error {
	ipsetName, err := IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	if i.MarkRouteKnown(ipsetName) {
		return nil
	}
	return i.installMark(vpnkind.Kind(vpnType), ipsetName, resolveIface)
}

func (i *IptablesManager) SyncMark(vpnType, chain string, resolveIface func() (string, error)) error {
	ipsetName, err := IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	if !i.MarkRouteKnown(ipsetName) {
		return i.installMark(vpnkind.Kind(vpnType), ipsetName, resolveIface)
	}
	if err := i.EnsureMarkIPSets(ipsetName); err != nil {
		return err
	}
	vpnIface, err := resolveIface()
	if err != nil {
		return err
	}
	return i.SyncMarkRoute(ipsetName, vpnIface)
}

func (i *IptablesManager) MarkIntact(vpnType, chain string) bool {
	ipsetName, err := IpsetName(vpnType, chain)
	if err != nil {
		return true
	}
	return i.MarkRouteIntact(ipsetName)
}

func (i *IptablesManager) RemoveMark(vpnType, chain string) error {
	ipsetName, err := IpsetName(vpnType, chain)
	if err != nil {
		return err
	}
	return i.RemoveMarkRoute(ipsetName)
}

func (i *IptablesManager) installMark(kind vpnkind.Kind, ipsetName string, resolveIface func() (string, error)) error {
	vpnIface, err := resolveIface()
	if err != nil {
		return err
	}
	if err := i.EnsureMarkIPSets(ipsetName); err != nil {
		return err
	}
	return i.AddMarkRoute(kind, ipsetName, i.lanIfaces, vpnIface)
}
