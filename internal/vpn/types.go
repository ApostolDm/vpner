package vpn

type Type string

const (
	Xray      Type = "Xray"
	OpenVPN   Type = "OpenVPN"
	Wireguard Type = "Wireguard"
	IKE       Type = "IKE"
	SSTP      Type = "SSTP"
	PPPOE     Type = "PPPOE"
	L2TP      Type = "L2TP"
	PPTP      Type = "PPTP"
)

var (
	allTypes = []Type{
		Xray,
		OpenVPN,
		Wireguard,
		IKE,
		SSTP,
		PPPOE,
		L2TP,
		PPTP,
	}
	routerTypes = []Type{
		OpenVPN,
		Wireguard,
		IKE,
		SSTP,
		PPPOE,
		L2TP,
		PPTP,
	}
	allTypeSet    = buildTypeSet(allTypes)
	routerTypeSet = buildTypeSet(routerTypes)
)

func (t Type) String() string {
	return string(t)
}

func AllTypes() []Type {
	return append([]Type(nil), allTypes...)
}

func RouterTypes() []Type {
	return append([]Type(nil), routerTypes...)
}

func IsKnown(value string) bool {
	_, ok := allTypeSet[Type(value)]
	return ok
}

func IsRouterManaged(value string) bool {
	_, ok := routerTypeSet[Type(value)]
	return ok
}

func buildTypeSet(values []Type) map[Type]struct{} {
	out := make(map[Type]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
