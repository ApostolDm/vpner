package firewall

import "testing"

func TestParseFwmarkRuleAcceptsHexAndDecimal(t *testing.T) {
	t.Parallel()

	cases := map[string][3]int{
		"2149:\tfrom all fwmark 0x7d lookup 125":            {125, 125, 1},
		"2148:\tfrom all fwmark 0xc8 lookup 200":            {200, 200, 1},
		"100:\tfrom all fwmark 125 table 125":               {125, 125, 1},
		"2150:\tfrom all fwmark 0x7d/0xffffffff lookup 125": {125, 125, 1},
		"0:\tfrom all lookup local":                         {0, 0, 0},
		"32766:\tfrom all lookup main":                      {0, 0, 0},
		"2154:\tfrom 100.64.222.69 lookup 16386":            {0, 0, 0},
		"1:\tfrom all fwmark 0x7d lookup main":              {0, 0, 0},
	}
	for line, want := range cases {
		mark, table, ok := parseFwmarkRule(line)
		if ok != (want[2] == 1) || (ok && (mark != want[0] || table != want[1])) {
			t.Errorf("%q: got (%d,%d,%v), want (%d,%d,%v)", line, mark, table, ok, want[0], want[1], want[2] == 1)
		}
	}
}
