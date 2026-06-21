package vpnkind

type Kind string

const (
	Xray      Kind = "Xray"
	OpenVPN   Kind = "OpenVPN"
	WireGuard Kind = "Wireguard"
	IKE       Kind = "IKE"
	SSTP      Kind = "SSTP"
	PPPoE     Kind = "PPPOE"
	L2TP      Kind = "L2TP"
	PPTP      Kind = "PPTP"
)

var router = []Kind{OpenVPN, WireGuard, IKE, SSTP, PPPoE, L2TP, PPTP}

var all = append([]Kind{Xray}, router...)

var (
	knownSet  = toSet(all)
	routerSet = toSet(router)
)

func (k Kind) String() string { return string(k) }

func All() []Kind { return append([]Kind(nil), all...) }

func Router() []Kind { return append([]Kind(nil), router...) }

func IsKnown(value string) bool {
	_, ok := knownSet[Kind(value)]
	return ok
}

func IsRouterManaged(value string) bool {
	_, ok := routerSet[Kind(value)]
	return ok
}

func toSet(kinds []Kind) map[Kind]struct{} {
	set := make(map[Kind]struct{}, len(kinds))
	for _, k := range kinds {
		set[k] = struct{}{}
	}
	return set
}
