package firewall

import (
	"fmt"
	"testing"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

func TestMarkAndTableFitBusyboxTableRange(t *testing.T) {
	t.Parallel()

	names := []string{"vpner-OpenVPN-OpenVPN0", "vpner-Wireguard-Wireguard0"}
	for i := 0; i < 500; i++ {
		names = append(names, fmt.Sprintf("vpner-OpenVPN-chain%d", i))
	}
	for _, name := range names {
		mark, tableID := markAndTableFromIPSet(name)
		if mark != tableID {
			t.Fatalf("%s: mark %d != table %d", name, mark, tableID)
		}
		if mark < markTableMin || mark > markTableMax {
			t.Fatalf("%s: id %d outside busybox-safe range [%d,%d]", name, mark, markTableMin, markTableMax)
		}
		if mark == tproxyTableID {
			t.Fatalf("%s: id collides with tproxy table %d", name, tproxyTableID)
		}
	}
}

func TestPickMarkForFamilyAvoidsCollisions(t *testing.T) {
	t.Parallel()

	routing := make(map[string]vpnRoutingInfo)
	for i := 0; i < markTableSpan()-1; i++ {
		name := fmt.Sprintf("vpner-OpenVPN-chain%d", i)
		mark, err := pickMarkForFamily(routing, name)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if mark == tproxyTableID {
			t.Fatalf("%s: assigned reserved tproxy table %d", name, tproxyTableID)
		}
		if mark < markTableMin || mark > markTableMax {
			t.Fatalf("%s: id %d outside range", name, mark)
		}
		for other, info := range routing {
			if info.Mark == mark {
				t.Fatalf("%s: id %d collides with %s", name, mark, other)
			}
		}
		routing[name] = vpnRoutingInfo{VPNType: vpnkind.OpenVPN, Mark: mark, TableID: mark}
	}

	if _, err := pickMarkForFamily(routing, "vpner-OpenVPN-overflow"); err == nil {
		t.Fatalf("expected error when all routing slots are exhausted")
	}
}

func TestPickMarkForFamilyIgnoresXrayEntries(t *testing.T) {
	t.Parallel()

	name := "vpner-OpenVPN-chainX"
	base := seededMarkID(checksumIPSetName(name))
	routing := map[string]vpnRoutingInfo{
		"vpner-Xray-proxy": {VPNType: vpnkind.Xray, Mark: 0},
	}
	mark, err := pickMarkForFamily(routing, name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mark != base {
		t.Fatalf("expected deterministic base id %d, got %d", base, mark)
	}
}
