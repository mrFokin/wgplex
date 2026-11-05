package dns

import (
	"slices"
	"strings"
	"testing"
)

// isUUID reports whether s is a UUID in the 8-4-4-4-12 hex form.
func isUUID(s string) bool {
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

// Tests follow design 8 (the capture key, the original system DNS: manual,
// else DHCP), not the implementation.

// --- CaptureKey --------------------------------------------------------------

// design 8 "Точечный захват": the key State:/Network/Service/<constant
// UUID>/DNS.
func TestCaptureKey(t *testing.T) {
	const prefix, suffix = "State:/Network/Service/", "/DNS"
	if !strings.HasPrefix(CaptureKey, prefix) || !strings.HasSuffix(CaptureKey, suffix) {
		t.Fatalf("CaptureKey = %q, want %s<UUID>%s", CaptureKey, prefix, suffix)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(CaptureKey, prefix), suffix)
	if !isUUID(id) {
		t.Errorf("CaptureKey UUID %q is not 8-4-4-4-12 hex", id)
	}
}

// --- captureValue, sameCapture ------------------------------------------------

// design 8, the table of the key: ServerAddresses [127.0.0.1], ServerPort,
// SupplementalMatchDomains zones, SupplementalMatchOrders 1 per zone,
// SupplementalMatchDomainsNoSearch 1; nothing else.
func TestCaptureValue(t *testing.T) {
	zones := []string{"example.com", "corp.example"}
	v := captureValue(zones)
	want := map[string][]string{
		"ServerAddresses":                  {"127.0.0.1"},
		"ServerPort":                       {"5301"},
		"SupplementalMatchDomains":         {"example.com", "corp.example"},
		"SupplementalMatchOrders":          {"1", "1"},
		"SupplementalMatchDomainsNoSearch": {"1"},
	}
	if len(v) != len(want) {
		t.Errorf("captureValue has %d fields, want %d: %v", len(v), len(want), v)
	}
	for k, w := range want {
		if g := valueStrings(v[k]); !slices.Equal(g, w) {
			t.Errorf("%s = %q, want %q", k, g, w)
		}
	}
	if !sameCapture(want, v) {
		t.Error("sameCapture(read back, captureValue) = false")
	}
	// The zones are copied: changing the caller's slice changes nothing.
	zones[0] = "x.example"
	if g := v["SupplementalMatchDomains"].([]string); g[0] != "example.com" {
		t.Errorf("captureValue keeps the caller's slice: %q", g)
	}
}

func TestSameCapture(t *testing.T) {
	want := captureValue([]string{"a.example", "b.example"})
	good := func() map[string][]string {
		return map[string][]string{
			"ServerAddresses":                  {"127.0.0.1"},
			"ServerPort":                       {"5301"},
			"SupplementalMatchDomains":         {"a.example", "b.example"},
			"SupplementalMatchOrders":          {"1", "1"},
			"SupplementalMatchDomainsNoSearch": {"1"},
		}
	}
	cases := []struct {
		why  string
		edit func(m map[string][]string)
		same bool
	}{
		{"as written", func(map[string][]string) {}, true},
		{"zone missing", func(m map[string][]string) { m["SupplementalMatchDomains"] = []string{"a.example"} }, false},
		{"zones reordered", func(m map[string][]string) {
			m["SupplementalMatchDomains"] = []string{"b.example", "a.example"}
		}, false},
		{"other port", func(m map[string][]string) { m["ServerPort"] = []string{"53"} }, false},
		{"no NoSearch", func(m map[string][]string) { delete(m, "SupplementalMatchDomainsNoSearch") }, false},
		{"extra field", func(m map[string][]string) { m["SearchDomains"] = []string{"x"} }, false},
		{"orders short", func(m map[string][]string) { m["SupplementalMatchOrders"] = []string{"1"} }, false},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m := good()
			c.edit(m)
			if got := sameCapture(m, want); got != c.same {
				t.Errorf("sameCapture = %v, want %v", got, c.same)
			}
		})
	}
	if sameCapture(nil, want) {
		t.Error("sameCapture(nil) = true")
	}
}

// --- systemServers -----------------------------------------------------------

// design 8 "Остальное": DNS of the primary service, manual (Setup) first,
// else DHCP (State); invalid addresses are skipped.
func TestSystemServers(t *testing.T) {
	// Manual DNS: two servers of both families and SearchDomains.
	setup := map[string][]string{
		"SearchDomains":   {"corp.example", "example.net"},
		"ServerAddresses": {"9.9.9.9", "2620:fe::fe", "149.112.112.112"},
	}
	state := map[string][]string{"ServerAddresses": {"192.168.20.1"}}
	none := map[string][]string{}
	cases := []struct {
		why          string
		setup, state map[string][]string
		want         []string
	}{
		{"Setup wins over State", setup, state, []string{"9.9.9.9", "2620:fe::fe", "149.112.112.112"}},
		{"no Setup key: State", none, state, []string{"192.168.20.1"}},
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
			noPanic(t, "systemServers", func() {
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

// --- parseScutilDNS, missingZones --------------------------------------------

// A synthetic `scutil --dns` output in the format of macOS 26: a default
// resolver, our supplemental zones, another service with the same zone on
// :53, an mdns block, and scoped blocks that must be skipped.
const scutilDNSSample = `DNS configuration

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #2
  domain   : example.com
  nameserver[0] : 127.0.0.1
  port     : 5301
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
  order    : 1

resolver #3
  domain   : Corp.Example.
  nameserver[0] : 127.0.0.1
  port     : 5301
  flags    : Supplemental, Request A records, Request AAAA records
  order    : 1

resolver #4
  domain   : other.example
  nameserver[0] : 127.0.0.1
  nameserver[1] : 127.0.0.2
  flags    : Supplemental, Request A records
  order    : 2

resolver #5
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  domain   : scoped.example
  nameserver[0] : 127.0.0.1
  port     : 5301
  if_index : 14 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
`

func TestScutilDNSSample(t *testing.T) {
	var got []resolverBlock
	noPanic(t, "parseScutilDNS", func() { got = parseScutilDNS(scutilDNSSample) })
	want := []resolverBlock{
		{nameserver: "192.0.2.1"},
		{domain: "example.com", nameserver: "127.0.0.1", port: 5301},
		{domain: "Corp.Example.", nameserver: "127.0.0.1", port: 5301},
		{domain: "other.example", nameserver: "127.0.0.1"},
		{domain: "local"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseScutilDNS =\n%+v\nwant\n%+v", got, want)
	}
	if b := parseScutilDNS(""); len(b) != 0 {
		t.Errorf("empty output: %+v", b)
	}
	if b := parseScutilDNS("No DNS configuration available\n"); len(b) != 0 {
		t.Errorf("no configuration: %+v", b)
	}
}

func TestMissingZones(t *testing.T) {
	blocks := parseScutilDNS(scutilDNSSample)
	cases := []struct {
		zones, want []string
	}{
		{[]string{"example.com", "corp.example"}, nil},
		// Port 53 (absent) is not ours; scoped blocks do not count.
		{[]string{"example.com", "other.example", "scoped.example", "absent.example"},
			[]string{"other.example", "scoped.example", "absent.example"}},
		{nil, nil},
	}
	for _, c := range cases {
		if got := missingZones(blocks, c.zones); !slices.Equal(got, c.want) {
			t.Errorf("missingZones(%q) = %q, want %q", c.zones, got, c.want)
		}
	}
}

func TestMissingError(t *testing.T) {
	if err := missingError(nil, 3); err != nil {
		t.Errorf("no zones missing: %v", err)
	}
	err := missingError([]string{"a.example"}, 3)
	if err == nil || !strings.Contains(err.Error(), "a.example") || !strings.Contains(err.Error(), "1 of 3") {
		t.Errorf("one missing: %v", err)
	}
	var many []string
	for i := range 15 {
		many = append(many, "z"+strings.Repeat("x", i)+".example")
	}
	err = missingError(many, 20)
	if err == nil || !strings.Contains(err.Error(), "and 5 more") || strings.Contains(err.Error(), many[14]) {
		t.Errorf("many missing: %v", err)
	}
}
