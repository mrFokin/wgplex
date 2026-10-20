package router

import (
	"net/netip"
	"testing"
)

// Tests follow design 16 (an overlap of tunnel routes with a local network is
// only a warning) and the doc of Overlaps from the M4 plan: routes of the table
// whose prefix overlaps one of the local subnets, in table order, endpoint
// routes excluded.

// m4Overlaps calls Overlaps and turns a panic into a test failure.
func m4Overlaps(t *testing.T, tbl Table, local []netip.Prefix) []Route {
	t.Helper()
	var got []Route
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Overlaps panicked: %v", r)
			}
		}()
		got = Overlaps(tbl, local)
	}()
	return got
}

func TestM4Overlaps(t *testing.T) {
	lan := tPs("192.168.20.0/24")
	cases := []struct {
		name  string
		tbl   Table
		local []netip.Prefix
		want  []Route
	}{
		// design 16: a prefix equal to the LAN subnet overlaps it.
		{name: "equal to LAN", local: lan,
			tbl:  Table{tAllowed("192.168.20.0/24", "home")},
			want: []Route{tAllowed("192.168.20.0/24", "home")}},
		// M4 fact 8: a prefix narrower than the LAN (/25 in /24).
		{name: "narrower than LAN", local: lan,
			tbl:  Table{tAllowed("192.168.20.128/25", "home")},
			want: []Route{tAllowed("192.168.20.128/25", "home")}},
		{name: "host route inside LAN", local: lan,
			tbl:  Table{tDynVia("192.168.20.7/32", "nl", 0)},
			want: []Route{tDynVia("192.168.20.7/32", "nl", 0)}},
		// A prefix that covers the LAN subnet.
		{name: "wider than LAN", local: lan,
			tbl:  Table{tAllowed("192.168.0.0/16", "work")},
			want: []Route{tAllowed("192.168.0.0/16", "work")}},
		{name: "no overlap", local: lan,
			tbl: Table{
				tAllowed("10.0.0.0/8", "work"),
				tAllowed("192.168.21.0/24", "home"),
				tAllowed("192.168.19.0/24", "home"),
			},
			want: nil},
		// Every route of t except endpoints, whatever its target.
		{name: "direct and reject targets", local: lan,
			tbl: Table{
				tRuleRoute("192.168.20.0/26", SourceRuleCIDR, TargetDirect, "", 0),
				tRuleRoute("192.168.20.64/26", SourceRuleCIDR, TargetReject, "", 1),
			},
			want: []Route{
				tRuleRoute("192.168.20.0/26", SourceRuleCIDR, TargetDirect, "", 0),
				tRuleRoute("192.168.20.64/26", SourceRuleCIDR, TargetReject, "", 1),
			}},
		// doc of Overlaps: endpoint routes are not reported.
		{name: "endpoint not reported", local: lan,
			tbl:  Table{tAllowed("192.168.20.0/25", "home"), tEndpoint("192.168.20.5/32")},
			want: []Route{tAllowed("192.168.20.0/25", "home")}},
		{name: "IPv6 narrower", local: tPs("fd00:1::/48"),
			tbl:  Table{tAllowed("fd00:1:0:5::/64", "work")},
			want: []Route{tAllowed("fd00:1:0:5::/64", "work")}},
		{name: "IPv6 wider", local: tPs("2001:db8:1:2::/64"),
			tbl:  Table{tAllowed("2001:db8::/32", "work")},
			want: []Route{tAllowed("2001:db8::/32", "work")}},
		{name: "IPv6 no overlap", local: tPs("fd00:1::/48"),
			tbl:  Table{tAllowed("fd00:2::/48", "work")},
			want: nil},
		// Families never overlap, even ::/0 and 0.0.0.0/0.
		{name: "families do not mix", local: tPs("192.168.20.0/24", "fd00:1::/48"),
			tbl: Table{
				tAllowed("10.0.0.0/8", "work"),
				tRuleRoute("::/0", SourceAllowedIPs, TargetReject, "", -1),
			},
			want: []Route{tRuleRoute("::/0", SourceAllowedIPs, TargetReject, "", -1)}},
		{name: "default overlaps everything of its family", local: tPs("192.168.20.0/24"),
			tbl:  Table{tAllowed("0.0.0.0/0", "work")},
			want: []Route{tAllowed("0.0.0.0/0", "work")}},
		// In t's order; a route overlapping several local subnets is reported
		// once.
		{name: "order and no duplicates", local: tPs("192.168.20.0/24", "10.1.0.0/16", "fd00:1::/48"),
			tbl: Table{
				tAllowed("10.0.0.0/8", "work"),
				tAllowed("10.1.2.0/24", "work"),
				tAllowed("172.16.0.0/12", "work"),
				tAllowed("192.168.0.0/16", "home"),
				tEndpoint("203.0.113.1/32"),
				tAllowed("fd00::/8", "work"),
			},
			want: []Route{
				tAllowed("10.0.0.0/8", "work"),
				tAllowed("10.1.2.0/24", "work"),
				tAllowed("192.168.0.0/16", "home"),
				tAllowed("fd00::/8", "work"),
			}},
		{name: "a route over two local subnets once", local: tPs("192.168.20.0/24", "192.168.21.0/24"),
			tbl:  Table{tAllowed("192.168.0.0/16", "home")},
			want: []Route{tAllowed("192.168.0.0/16", "home")}},
		{name: "empty table", local: lan, tbl: nil, want: nil},
		{name: "no local subnets", local: nil,
			tbl:  Table{tAllowed("192.168.20.0/24", "home")},
			want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m4Overlaps(t, c.tbl, c.local)
			equal := len(got) == len(c.want)
			for i := 0; equal && i < len(got); i++ {
				equal = got[i] == c.want[i]
			}
			if !equal {
				t.Errorf("Overlaps mismatch\ngot:\n%swant:\n%s", tFmtTable(Table(got)), tFmtTable(Table(c.want)))
			}
		})
	}
}
