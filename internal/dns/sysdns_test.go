package dns

import (
	"slices"
	"strings"
	"testing"
)

// m5IsUUID reports whether s is a UUID in the 8-4-4-4-12 hex form.
func m5IsUUID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for i, n := range []int{8, 4, 4, 4, 12} {
		if len(parts[i]) != n {
			return false
		}
		for _, r := range parts[i] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}

// Tests follow design 7 (the capture key, the original system DNS: manual,
// else DHCP) and the M5 plan ("Модель": capture, the original servers;
// appendix: scutil samples, verbatim), not the implementation.

// Samples from the appendix of the M5 plan, verbatim.
const (
	m5ScutilGlobalIPv4 = `<dictionary> {
  PrimaryInterface : en0
  PrimaryService : DB5E9594-52DD-4D6A-888E-8D98A75BEC1B
  Router : 192.168.20.1
}
`
	m5ScutilStateDNS = `<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.20.1
  }
}
`
	m5ScutilNoKey = "  No such key\n"

	m5ScutilGlobalDNS = `<dictionary> {
  ServerAddresses : <array> {
    0 : 192.168.20.1
  }
  __CONFIGURATION_ID__ : Default: DB5E9594-52DD-4D6A-888E-8D98A75BEC1B 0
  __FLAGS__ : 2
  __IF_INDEX__ : 14
  __ORDER__ : 0
}
`
	m5ScutilServiceIPv4 = `<dictionary> {
  ARPResolvedHardwareAddress : d4:9c:53:27:85:03
  ARPResolvedIPAddress : 192.168.20.1
  AdditionalRoutes : <array> {
    0 : <dictionary> {
      DestinationAddress : 192.168.20.135
      SubnetMask : 255.255.255.255
    }
    1 : <dictionary> {
      DestinationAddress : 169.254.0.0
      SubnetMask : 255.255.0.0
    }
  }
  Addresses : <array> {
    0 : 192.168.20.135
  }
  ConfirmedInterfaceName : en0
  InterfaceName : en0
  NetworkSignature : IPv4.Router=192.168.20.1;IPv4.RouterHardwareAddress=d4:9c:53:27:85:03
  NetworkSignatureHash : <data> 0x582ba13cf9132fd7fb8e3a3fc0a4dabc5eda57f5
  Router : 192.168.20.1
  SubnetMasks : <array> {
    0 : 255.255.255.0
  }
}
`
	// Manual DNS (not on the user's machine; "the same form as State:…/DNS"
	// per the appendix): two servers of both families and SearchDomains.
	m5ScutilSetupDNS = `<dictionary> {
  SearchDomains : <array> {
    0 : corp.example
    1 : example.net
  }
  ServerAddresses : <array> {
    0 : 9.9.9.9
    1 : 2620:fe::fe
    2 : 149.112.112.112
  }
}
`
)

func m5Parse(t *testing.T, out string) map[string][]string {
	t.Helper()
	var m map[string][]string
	m5NoPanic(t, "parseScutil", func() { m = parseScutil(out) })
	return m
}

// m5SameMap compares parsed maps; a key listed in want with a nil value must
// be absent.
func m5SameMap(t *testing.T, got, want map[string][]string) {
	t.Helper()
	for k, w := range want {
		g, ok := got[k]
		if w == nil {
			if ok {
				t.Errorf("key %q = %q, want absent", k, g)
			}
			continue
		}
		if !ok || !slices.Equal(g, w) {
			t.Errorf("key %q = %q (present %v), want %q", k, g, ok, w)
		}
	}
}

// --- parseScutil -------------------------------------------------------------

// M5 appendix: scalars as one-element slices, arrays in index order, nested
// dictionaries skipped (with arrays of them), the value of a scalar is all
// after the first " : ".
func TestM5ParseScutil(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want map[string][]string
		size int // exact number of keys; -1: not checked
	}{
		{"State:/Network/Global/IPv4", m5ScutilGlobalIPv4, map[string][]string{
			"PrimaryInterface": {"en0"},
			"PrimaryService":   {"DB5E9594-52DD-4D6A-888E-8D98A75BEC1B"},
			"Router":           {"192.168.20.1"},
		}, 3},
		{"State:/Network/Service/<id>/DNS", m5ScutilStateDNS, map[string][]string{
			"ServerAddresses": {"192.168.20.1"},
		}, 1},
		{"State:/Network/Global/DNS", m5ScutilGlobalDNS, map[string][]string{
			"ServerAddresses":      {"192.168.20.1"},
			"__CONFIGURATION_ID__": {"Default: DB5E9594-52DD-4D6A-888E-8D98A75BEC1B 0"},
			"__FLAGS__":            {"2"},
			"__IF_INDEX__":         {"14"},
			"__ORDER__":            {"0"},
		}, 5},
		// The value of NetworkSignatureHash ("<data> 0x…") is not checked:
		// the plan does not say how <data> is read.
		{"State:/Network/Service/<id>/IPv4", m5ScutilServiceIPv4, map[string][]string{
			"ARPResolvedHardwareAddress": {"d4:9c:53:27:85:03"},
			"ARPResolvedIPAddress":       {"192.168.20.1"},
			"Addresses":                  {"192.168.20.135"},
			"ConfirmedInterfaceName":     {"en0"},
			"InterfaceName":              {"en0"},
			"NetworkSignature":           {"IPv4.Router=192.168.20.1;IPv4.RouterHardwareAddress=d4:9c:53:27:85:03"},
			"Router":                     {"192.168.20.1"},
			"SubnetMasks":                {"255.255.255.0"},
			// Nested dictionaries and the array of them are skipped.
			"AdditionalRoutes":   nil,
			"DestinationAddress": nil,
			"SubnetMask":         nil,
		}, -1},
		{"Setup:/Network/Service/<id>/DNS, manual", m5ScutilSetupDNS, map[string][]string{
			"SearchDomains":   {"corp.example", "example.net"},
			"ServerAddresses": {"9.9.9.9", "2620:fe::fe", "149.112.112.112"},
		}, 2},
		{"No such key", m5ScutilNoKey, map[string][]string{}, 0},
		{"empty output", "", map[string][]string{}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m5Parse(t, c.out)
			m5SameMap(t, got, c.want)
			if c.size >= 0 && len(got) != c.size {
				t.Errorf("parsed %d keys %q, want %d", len(got), got, c.size)
			}
		})
	}

	// The IPv4 sample has exactly these top-level keys, NetworkSignatureHash
	// included whatever its value.
	t.Run("IPv4 keys", func(t *testing.T) {
		got := m5Parse(t, m5ScutilServiceIPv4)
		var keys []string
		for k := range got {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		want := []string{
			"ARPResolvedHardwareAddress", "ARPResolvedIPAddress", "Addresses",
			"ConfirmedInterfaceName", "InterfaceName", "NetworkSignature",
			"NetworkSignatureHash", "Router", "SubnetMasks",
		}
		slices.Sort(want)
		if !slices.Equal(keys, want) {
			t.Errorf("keys = %q, want %q", keys, want)
		}
	})
}

// --- systemServers -----------------------------------------------------------

// design 7 "Остальное": DNS of the primary service, manual (Setup) first,
// else DHCP (State); invalid addresses are skipped.
func TestM5SystemServers(t *testing.T) {
	setup := m5Parse(t, m5ScutilSetupDNS)
	state := m5Parse(t, m5ScutilStateDNS)
	none := m5Parse(t, m5ScutilNoKey)
	cases := []struct {
		why          string
		setup, state map[string][]string
		want         []string
	}{
		{"Setup wins over State", setup, state, []string{"9.9.9.9", "2620:fe::fe", "149.112.112.112"}},
		{"no Setup key: State (the user's machine)", none, state, []string{"192.168.20.1"}},
		{"nil Setup: State", nil, state, []string{"192.168.20.1"}},
		{"Setup without ServerAddresses: State",
			map[string][]string{"SearchDomains": {"corp.example"}}, state, []string{"192.168.20.1"}},
		{"Setup only", setup, none, []string{"9.9.9.9", "2620:fe::fe", "149.112.112.112"}},
		{"neither", none, none, nil},
		{"both nil", nil, nil, nil},
		{"invalid addresses skipped",
			nil, map[string][]string{"ServerAddresses": {"192.168.20.1", "not-an-ip", "", "10.0.0.300", "2001:db8::53"}},
			[]string{"192.168.20.1", "2001:db8::53"}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			var got []string
			m5NoPanic(t, "systemServers", func() {
				for _, a := range systemServers(c.setup, c.state) {
					got = append(got, a.String())
				}
			})
			if !slices.Equal(got, c.want) {
				t.Errorf("systemServers = %v, want %v", got, c.want)
			}
		})
	}
}

// --- captureScript -----------------------------------------------------------

// design 7, M5 "Модель" (capture): the key State:/Network/Service/<constant
// UUID>/DNS; the script is d.init, d.add of ServerAddresses 127.0.0.1 and
// SupplementalMatchDomains "" (arrays), set of the key.
func TestM5CaptureScript(t *testing.T) {
	const prefix, suffix = "State:/Network/Service/", "/DNS"
	if !strings.HasPrefix(CaptureKey, prefix) || !strings.HasSuffix(CaptureKey, suffix) {
		t.Fatalf("CaptureKey = %q, want %s<UUID>%s", CaptureKey, prefix, suffix)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(CaptureKey, prefix), suffix)
	if !m5IsUUID(id) {
		t.Errorf("CaptureKey UUID %q is not 8-4-4-4-12 hex", id)
	}

	var script string
	m5NoPanic(t, "captureScript", func() { script = captureScript() })
	var lines []string
	for _, l := range strings.Split(script, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	find := func(pred func(string) bool) int { return slices.IndexFunc(lines, pred) }
	iInit := find(func(l string) bool { return l == "d.init" })
	iServers := find(func(l string) bool {
		f := strings.Fields(l)
		return len(f) == 4 && f[0] == "d.add" && f[1] == "ServerAddresses" && f[2] == "*" && f[3] == "127.0.0.1"
	})
	// How the empty string is written (`""` or nothing) is up to scutil;
	// only the array of one empty domain is required, so the token after
	// "*" is not checked beyond not being a real domain.
	iDomains := find(func(l string) bool {
		f := strings.Fields(l)
		return len(f) >= 3 && f[0] == "d.add" && f[1] == "SupplementalMatchDomains" && f[2] == "*" &&
			(len(f) == 3 || (len(f) == 4 && f[3] == `""`))
	})
	iSet := find(func(l string) bool { return l == "set "+CaptureKey })
	if iInit < 0 || iServers < 0 || iDomains < 0 || iSet < 0 {
		t.Fatalf("captureScript lacks a line (d.init %d, ServerAddresses %d, SupplementalMatchDomains %d, set %d):\n%s",
			iInit, iServers, iDomains, iSet, script)
	}
	if !(iInit < iServers && iInit < iDomains && iServers < iSet && iDomains < iSet) {
		t.Errorf("order: d.init, then d.add, then set:\n%s", script)
	}
	// Nothing else is set: one set, no remove.
	for _, l := range lines {
		if (strings.HasPrefix(l, "set ") && l != "set "+CaptureKey) || strings.HasPrefix(l, "remove") {
			t.Errorf("unexpected line %q in:\n%s", l, script)
		}
	}
}
