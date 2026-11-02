package router

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Tests follow design 6 and 7.2 (sync of the computed table with the kernel:
// only the difference, RTF_PROTO2 marks our routes, RTM_CHANGE for another
// utun or gateway, delete + add for another kind, foreign routes and endpoint
// host routes left alone) with the doc comments of wanted, owned, diff and
// routeMsg — not the implementation.

// --- helpers ---------------------------------------------------------------

// noPanic runs f and turns a panic into a test failure.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// ifaceRoute, gwRoute, rejectRoute and holeRoute build kernel routes of each kind.
func ifaceRoute(p string, index int) KernelRoute {
	return KernelRoute{Prefix: tP(p), Kind: KindIface, Index: index}
}

func gwRoute(p, gw string, index int) KernelRoute {
	return KernelRoute{Prefix: tP(p), Kind: KindGateway, Index: index, Gateway: tA(gw)}
}

func rejectRoute(p string) KernelRoute { return KernelRoute{Prefix: tP(p), Kind: KindReject} }
func holeRoute(p string) KernelRoute   { return KernelRoute{Prefix: tP(p), Kind: KindBlackhole} }

// unknownRoute is a route of ours whose kind owned cannot tell (Kind 0).
func unknownRoute(p string) KernelRoute { return KernelRoute{Prefix: tP(p)} }

func addOp(r KernelRoute) Op    { return Op{Type: OpAdd, Route: r} }
func changeOp(r KernelRoute) Op { return Op{Type: OpChange, Route: r} }
func delOp(r KernelRoute) Op    { return Op{Type: OpDelete, Route: r} }

// normRoute keeps what the model keeps of a kernel route: for reject and
// blackhole routes only Prefix and Kind (the interface is lo0, the gateway a
// loopback address, neither is part of the model), the same for a route of
// unknown kind (Kind 0: what else owned keeps of it is not specified); the
// zone of a gateway is dropped (the scope is carried by Index).
func normRoute(r KernelRoute) KernelRoute {
	switch r.Kind {
	case KindReject, KindBlackhole, 0:
		return KernelRoute{Prefix: r.Prefix, Kind: r.Kind}
	}
	r.Gateway = r.Gateway.WithZone("")
	return r
}

// lessPrefix is the table order: Prefix.Addr().Compare, then Bits().
func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// sortedRoutes returns normalized routes sorted by prefix.
func sortedRoutes(rs []KernelRoute) []KernelRoute {
	out := make([]KernelRoute, len(rs))
	for i, r := range rs {
		out[i] = normRoute(r)
	}
	sort.SliceStable(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) })
	return out
}

func kindName(k Kind) string {
	switch k {
	case KindIface:
		return "iface"
	case KindGateway:
		return "gateway"
	case KindReject:
		return "reject"
	case KindBlackhole:
		return "blackhole"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

func fmtRoute(r KernelRoute) string {
	return fmt.Sprintf("%s %s idx=%d gw=%v", r.Prefix, kindName(r.Kind), r.Index, r.Gateway)
}

func fmtRoutes(rs []KernelRoute) string {
	if len(rs) == 0 {
		return "  (empty)\n"
	}
	var b strings.Builder
	for _, r := range rs {
		b.WriteString("  " + fmtRoute(r) + "\n")
	}
	return b.String()
}

func fmtOps(ops []Op) string {
	if len(ops) == 0 {
		return "  (empty)\n"
	}
	var b strings.Builder
	for _, op := range ops {
		b.WriteString(fmt.Sprintf("  %-6s %s\n", op.Type, fmtRoute(op.Route)))
	}
	return b.String()
}

func sameRoutes(t *testing.T, what string, got, want []KernelRoute) {
	t.Helper()
	g, w := sortedRoutes(got), sortedRoutes(want)
	equal := len(g) == len(w)
	for i := 0; equal && i < len(g); i++ {
		equal = g[i] == w[i]
	}
	if !equal {
		t.Errorf("%s mismatch\ngot:\n%swant:\n%s", what, fmtRoutes(g), fmtRoutes(w))
	}
}

// dumpMsgs marshals msgs into one buffer and parses it the way a routing table
// dump (sysctl NET_RT_DUMP) is read. The parsed messages carry the Type they
// were built with (RTM_ADD), not RTM_GET: owned must look at flags only.
func dumpMsgs(t *testing.T, msgs ...*route.RouteMessage) []route.Message {
	t.Helper()
	var buf []byte
	for _, m := range msgs {
		b, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		buf = append(buf, b...)
	}
	out, err := route.ParseRIB(route.RIBTypeRoute, buf)
	if err != nil {
		t.Fatalf("ParseRIB: %v", err)
	}
	if len(out) != len(msgs) {
		t.Fatalf("ParseRIB returned %d messages, want %d", len(out), len(msgs))
	}
	return out
}

// maskAddr is the netmask of p as an address.
func maskAddr(p netip.Prefix) netip.Addr {
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	a, _ := netip.AddrFromSlice(net.CIDRMask(p.Bits(), bits))
	return a
}

// --- wanted ------------------------------------------------------------------

// testEnv is a network with a utun for nl and work and gateways of both
// families; the IPv6 one is link-local, as router advertisements give it.
func testEnv() Env {
	return Env{
		Ifaces: map[string]int{"nl": 7, "work": 9},
		GW4:    Gateway{Addr: tA("192.168.20.1"), Index: 4},
		GW6:    Gateway{Addr: tA("fe80::1"), Index: 4},
	}
}

// design 7.2: tunnel → route on the
// tunnel's utun; direct → via the physical gateway of its family; reject →
// RTF_REJECT; endpoint host routes go to keep; a direct route without a
// gateway of its family is skipped; a tunnel without a utun is reject
// .
func TestWanted(t *testing.T) {
	const noGW = "no physical gateway"
	direct4 := tRuleRoute("9.9.9.9/32", SourceRuleCIDR, TargetDirect, "", 1)
	direct6 := tRuleRoute("2001:db8:5::/48", SourceRuleCIDR, TargetDirect, "", 1)
	dynDirect6 := tRuleRoute("2001:db8:6::9/128", SourceDynamic, TargetDirect, "", 1)
	viaDe := tCIDRVia("198.18.0.0/15", "de", 0)
	type skip struct {
		r      Route
		reason string
	}
	cases := []struct {
		name string
		tbl  Table
		env  Env
		want []KernelRoute
		keep []string
		skip []skip
	}{
		{name: "every target, IPv4 and IPv6", env: testEnv(),
			tbl: Table{
				direct4,
				tAllowed("10.20.0.0/16", "work"),
				tDynVia("192.0.2.10/32", "nl", 0),
				tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 2),
				tCIDRVia("198.51.100.0/24", "nl", 0),
				direct6,
				dynDirect6,
				tRuleRoute("2001:db8:7::/48", SourceRuleCIDR, TargetReject, "", 2),
				tAllowed("fd00:20::/48", "work"),
			},
			want: []KernelRoute{
				gwRoute("9.9.9.9/32", "192.168.20.1", 4),
				ifaceRoute("10.20.0.0/16", 9),
				ifaceRoute("192.0.2.10/32", 7),
				rejectRoute("192.0.2.20/32"),
				ifaceRoute("198.51.100.0/24", 7),
				gwRoute("2001:db8:5::/48", "fe80::1", 4),
				gwRoute("2001:db8:6::9/128", "fe80::1", 4),
				rejectRoute("2001:db8:7::/48"),
				ifaceRoute("fd00:20::/48", 9),
			}},
		// Endpoint routes are AddHost's; they go to keep only,
		// with or without a gateway.
		{name: "endpoints go to keep", env: testEnv(),
			tbl: Table{
				tAllowed("10.20.0.0/16", "work"),
				tEndpoint("203.0.113.1/32"),
				tEndpoint("2001:db8::1/128"),
			},
			want: []KernelRoute{ifaceRoute("10.20.0.0/16", 9)},
			keep: []string{"203.0.113.1/32", "2001:db8::1/128"}},
		{name: "endpoints without any gateway: keep, not skipped", env: Env{},
			tbl:  Table{tEndpoint("203.0.113.1/32"), tEndpoint("2001:db8::1/128")},
			keep: []string{"203.0.113.1/32", "2001:db8::1/128"}},
		// No gateway of its family → skipped; the other family
		// and other targets are unaffected.
		{name: "no IPv4 gateway",
			env: Env{Ifaces: map[string]int{"nl": 7}, GW6: Gateway{Addr: tA("fe80::1"), Index: 4}},
			tbl: Table{direct4, tDynVia("192.0.2.10/32", "nl", 0), direct6},
			want: []KernelRoute{
				ifaceRoute("192.0.2.10/32", 7),
				gwRoute("2001:db8:5::/48", "fe80::1", 4),
			},
			skip: []skip{{direct4, noGW}}},
		{name: "no IPv6 gateway",
			env: Env{Ifaces: map[string]int{"nl": 7}, GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl: Table{direct4, direct6, dynDirect6, tRuleRoute("2001:db8:7::/48", SourceRuleCIDR, TargetReject, "", 2)},
			want: []KernelRoute{
				gwRoute("9.9.9.9/32", "192.168.20.1", 4),
				rejectRoute("2001:db8:7::/48"),
			},
			skip: []skip{{direct6, noGW}, {dynDirect6, noGW}}},
		{name: "no gateways at all: tunnel and reject stay", env: Env{Ifaces: map[string]int{"nl": 7}},
			tbl: Table{
				direct4,
				tDynVia("192.0.2.10/32", "nl", 0),
				tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 2),
				direct6,
			},
			want: []KernelRoute{ifaceRoute("192.0.2.10/32", 7), rejectRoute("192.0.2.20/32")},
			skip: []skip{{direct4, noGW}, {direct6, noGW}}},
		// design 7.2: a tunnel without an entry in Ifaces (on,
		// but its utun is being recreated) gets reject, not a skip: the
		// traffic must not leave directly.
		{name: "tunnel without utun: reject", env: testEnv(),
			tbl: Table{
				tDynVia("192.0.2.10/32", "nl", 0),
				viaDe,
				tDynVia("192.0.2.11/32", "de", 0),
				tAllowed("fd00:30::/48", "de"),
			},
			want: []KernelRoute{
				ifaceRoute("192.0.2.10/32", 7),
				rejectRoute("192.0.2.11/32"),
				rejectRoute("198.18.0.0/15"),
				rejectRoute("fd00:30::/48"),
			}},
		// design 7.2, boundary: an entry with a non-positive
		// index means no utun, the same as a missing entry.
		{name: "tunnel with index 0: reject",
			env: Env{Ifaces: map[string]int{"nl": 7, "de": 0}, GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl: Table{
				tDynVia("192.0.2.10/32", "nl", 0),
				viaDe,
				tAllowed("fd00:30::/48", "de"),
			},
			want: []KernelRoute{
				ifaceRoute("192.0.2.10/32", 7),
				rejectRoute("198.18.0.0/15"),
				rejectRoute("fd00:30::/48"),
			}},
		{name: "tunnel with negative index: reject",
			env:  Env{Ifaces: map[string]int{"de": -1}},
			tbl:  Table{viaDe},
			want: []KernelRoute{rejectRoute("198.18.0.0/15")}},
		{name: "nil Ifaces: reject", env: Env{GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl:  Table{direct4, viaDe},
			want: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 4), rejectRoute("198.18.0.0/15")}},
		// No gateway and no utun: the direct route is skipped, the tunnel
		// one is still reject.
		{name: "no gateway, no utun", env: Env{},
			tbl:  Table{direct4, viaDe},
			want: []KernelRoute{rejectRoute("198.18.0.0/15")},
			skip: []skip{{direct4, noGW}}},
		{name: "empty table", env: testEnv(), tbl: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				want    []KernelRoute
				keep    map[netip.Prefix]bool
				skipped []Skip
			)
			noPanic(t, "wanted", func() { want, keep, skipped = wanted(c.tbl, c.env) })

			sameRoutes(t, "want", want, c.want)

			wantKeep := map[netip.Prefix]bool{}
			for _, p := range c.keep {
				wantKeep[tP(p)] = true
			}
			gotKeep := map[netip.Prefix]bool{}
			for p, v := range keep {
				if v {
					gotKeep[p] = true
				}
			}
			sameKeep := len(gotKeep) == len(wantKeep)
			for p := range wantKeep {
				sameKeep = sameKeep && gotKeep[p]
			}
			if !sameKeep {
				t.Errorf("keep = %v, want %v", gotKeep, wantKeep)
			}

			sort.SliceStable(skipped, func(i, j int) bool { return lessPrefix(skipped[i].Route.Prefix, skipped[j].Route.Prefix) })
			ws := append([]skip(nil), c.skip...)
			sort.SliceStable(ws, func(i, j int) bool { return lessPrefix(ws[i].r.Prefix, ws[j].r.Prefix) })
			equal := len(skipped) == len(ws)
			for i := 0; equal && i < len(ws); i++ {
				equal = skipped[i].Route == ws[i].r && skipped[i].Reason == ws[i].reason
			}
			if !equal {
				var g, w strings.Builder
				for _, s := range skipped {
					g.WriteString("  " + tFmtRoute(s.Route) + "  " + s.Reason + "\n")
				}
				for _, s := range ws {
					w.WriteString("  " + tFmtRoute(s.r) + "  " + s.reason + "\n")
				}
				t.Errorf("skipped mismatch\ngot:\n%swant:\n%s", g.String(), w.String())
			}
		})
	}
}

// --- owned -------------------------------------------------------------------

// entryMsg builds a dump entry for r with routeMsg and sets rtm_index as the
// kernel reports it in a dump (the utun for a route on an interface;
// the gateway's interface; lo0 for reject).
func entryMsg(r KernelRoute) *route.RouteMessage {
	m := routeMsg(unix.RTM_ADD, r, 1)
	switch r.Kind {
	case KindIface, KindGateway:
		m.Index = r.Index
	default:
		m.Index = 1 // lo0
	}
	return m
}

// hostEntryMsg builds a dump entry for an endpoint host route with
// hostRouteMsg (blackhole without a gateway address).
func hostEntryMsg(dst string, gw Gateway) *route.RouteMessage {
	m := hostRouteMsg(unix.RTM_ADD, tA(dst), gw, 1)
	if gw.Addr.IsValid() {
		m.Index = gw.Index
	} else {
		m.Index = 1 // lo0
	}
	return m
}

// design 6, 7.2: owned reads our routes (RTF_PROTO2) back
// from a dump — every kind, host and network, IPv4 and IPv6 — and leaves out
// foreign routes, entries without RTAX_DST and messages of other types.
func TestOwned(t *testing.T) {
	gw4 := Gateway{Addr: tA("192.168.20.1"), Index: 4}
	gw6 := Gateway{Addr: tA("fe80::1"), Index: 4}
	ours := []KernelRoute{
		ifaceRoute("10.20.0.0/16", 9),
		ifaceRoute("192.0.2.10/32", 7),
		gwRoute("9.9.0.0/16", "192.168.20.1", 4),
		gwRoute("9.9.9.9/32", "192.168.20.1", 4),
		rejectRoute("198.51.100.0/24"),
		rejectRoute("192.0.2.20/32"),
		ifaceRoute("fd00:20::/48", 9),
		ifaceRoute("2001:db8:2::10/128", 7),
		gwRoute("2001:db8:5::/48", "fe80::1", 4),
		gwRoute("2001:db8:6::9/128", "2001:db8:ffff::1", 5),
		rejectRoute("2001:db8:7::/48"),
		rejectRoute("2001:db8:dead::1/128"),
	}
	hosts := []KernelRoute{
		gwRoute("203.0.113.1/32", "192.168.20.1", 4),
		holeRoute("203.0.113.2/32"),
		gwRoute("2001:db8::1/128", "fe80::1", 4),
		holeRoute("2001:db8::2/128"),
	}

	var (
		msgs   []route.Message
		parsed bool
	)
	noPanic(t, "routeMsg", func() {
		var in []*route.RouteMessage
		for _, r := range ours {
			in = append(in, entryMsg(r))
		}
		in = append(in,
			hostEntryMsg("203.0.113.1", gw4),
			hostEntryMsg("203.0.113.2", Gateway{}),
			hostEntryMsg("2001:db8::1", gw6),
			hostEntryMsg("2001:db8::2", Gateway{}),
		)
		// A foreign route: the same message without RTF_PROTO2.
		foreign := entryMsg(ifaceRoute("10.30.0.0/16", 9))
		foreign.Flags &^= unix.RTF_PROTO2
		foreignHost := hostEntryMsg("203.0.113.3", gw4)
		foreignHost.Flags &^= unix.RTF_PROTO2
		// An entry of ours without RTAX_DST cannot be read.
		noDst := entryMsg(ifaceRoute("10.40.0.0/16", 9))
		noDst.Addrs[unix.RTAX_DST] = nil
		in = append(in, foreign, foreignHost, noDst)
		msgs = dumpMsgs(t, in...)
		parsed = true
	})
	if !parsed {
		return
	}
	// A message of another type in the dump.
	msgs = append(msgs, &route.InterfaceMessage{Version: unix.RTM_VERSION, Type: unix.RTM_IFINFO, Index: 4, Name: "en0"})

	var got []KernelRoute
	noPanic(t, "owned", func() { got = owned(msgs) })
	sameRoutes(t, "owned", got, append(append([]KernelRoute(nil), ours...), hosts...))
}

// Each kind on its own, so that a failure points at one kind.
func TestOwnedEach(t *testing.T) {
	for _, r := range []KernelRoute{
		ifaceRoute("10.20.0.0/16", 9),
		ifaceRoute("192.0.2.10/32", 7),
		gwRoute("9.9.0.0/16", "192.168.20.1", 4),
		gwRoute("9.9.9.9/32", "192.168.20.1", 4),
		rejectRoute("198.51.100.0/24"),
		rejectRoute("192.0.2.20/32"),
		ifaceRoute("fd00:20::/48", 9),
		gwRoute("2001:db8:5::/48", "fe80::1", 4),
		rejectRoute("2001:db8:7::/48"),
	} {
		t.Run(fmtRoute(r), func(t *testing.T) {
			var msgs []route.Message
			noPanic(t, "routeMsg", func() { msgs = dumpMsgs(t, entryMsg(r)) })
			if msgs == nil {
				return
			}
			var got []KernelRoute
			noPanic(t, "owned", func() { got = owned(msgs) })
			sameRoutes(t, "owned", got, []KernelRoute{r})
		})
	}
}

// design 7.2: in a dump a reject or blackhole route carries lo0's
// index; owned still reports its kind (only Prefix and Kind are compared).
func TestOwnedLo0(t *testing.T) {
	for _, r := range []KernelRoute{
		rejectRoute("198.51.100.0/24"),
		rejectRoute("192.0.2.20/32"),
		rejectRoute("2001:db8:7::/48"),
		rejectRoute("2001:db8:dead::1/128"),
		holeRoute("203.0.113.2/32"),
		holeRoute("2001:db8::2/128"),
	} {
		t.Run(fmtRoute(r), func(t *testing.T) {
			var msgs []route.Message
			noPanic(t, "routeMsg", func() {
				m := entryMsg(r)
				m.Index = 1 // lo0
				msgs = dumpMsgs(t, m)
			})
			if msgs == nil {
				return
			}
			var got []KernelRoute
			noPanic(t, "owned", func() { got = owned(msgs) })
			sameRoutes(t, "owned", got, []KernelRoute{r})
		})
	}
	// The endpoint blackhole as hostRouteMsg builds it, with lo0's index.
	for _, dst := range []string{"203.0.113.2", "2001:db8::2"} {
		t.Run("host blackhole "+dst, func(t *testing.T) {
			var msgs []route.Message
			noPanic(t, "hostRouteMsg", func() {
				m := hostEntryMsg(dst, Gateway{})
				m.Index = 1 // lo0
				msgs = dumpMsgs(t, m)
			})
			if msgs == nil {
				return
			}
			a := tA(dst)
			want := KernelRoute{Prefix: netip.PrefixFrom(a, a.BitLen()), Kind: KindBlackhole}
			var got []KernelRoute
			noPanic(t, "owned", func() { got = owned(msgs) })
			sameRoutes(t, "owned", got, []KernelRoute{want})
		})
	}
}

// Only foreign or unreadable entries: nothing is ours.
func TestOwnedNothing(t *testing.T) {
	noPanic(t, "owned(nil)", func() {
		if got := owned(nil); len(got) != 0 {
			t.Errorf("owned(nil) = %s", fmtRoutes(got))
		}
	})
	var msgs []route.Message
	noPanic(t, "hostRouteMsg", func() {
		foreign := hostEntryMsg("203.0.113.3", Gateway{Addr: tA("192.168.20.1"), Index: 4})
		foreign.Flags &^= unix.RTF_PROTO2
		msgs = dumpMsgs(t, foreign)
	})
	msgs = append(msgs, &route.InterfaceMessage{Version: unix.RTM_VERSION, Type: unix.RTM_IFINFO, Index: 4, Name: "en0"})
	noPanic(t, "owned", func() {
		if got := owned(msgs); len(got) != 0 {
			t.Errorf("owned = %s, want none", fmtRoutes(got))
		}
	})
}

// --- diff --------------------------------------------------------------------

// design 7.2: the ops that turn have into
// want — RTM_CHANGE for another utun or gateway of the same kind, delete +
// add for another kind, adds before deletes, keep left alone.
func TestDiff(t *testing.T) {
	ep4 := gwRoute("203.0.113.1/32", "192.168.20.1", 4)
	hole4 := holeRoute("203.0.113.2/32")
	hole6 := holeRoute("2001:db8::2/128")
	cases := []struct {
		name string
		want []KernelRoute
		have []KernelRoute
		keep []string
		ops  []Op
	}{
		{name: "both empty"},
		{name: "equal",
			want: []KernelRoute{ifaceRoute("10.20.0.0/16", 9), gwRoute("9.9.9.9/32", "192.168.20.1", 4), rejectRoute("198.51.100.0/24")},
			have: []KernelRoute{ifaceRoute("10.20.0.0/16", 9), gwRoute("9.9.9.9/32", "192.168.20.1", 4), rejectRoute("198.51.100.0/24")}},
		// A dump has no particular order.
		{name: "equal, have in another order",
			want: []KernelRoute{ifaceRoute("10.20.0.0/16", 9), gwRoute("9.9.9.9/32", "192.168.20.1", 4), rejectRoute("198.51.100.0/24")},
			have: []KernelRoute{rejectRoute("198.51.100.0/24"), ifaceRoute("10.20.0.0/16", 9), gwRoute("9.9.9.9/32", "192.168.20.1", 4)}},
		// Only Index (KindIface) or Gateway/Index (KindGateway) matter beyond
		// prefix and kind: a reject route from a dump carries lo0's index.
		{name: "reject: index not compared",
			want: []KernelRoute{rejectRoute("198.51.100.0/24")},
			have: []KernelRoute{{Prefix: tP("198.51.100.0/24"), Kind: KindReject, Index: 1}}},
		{name: "only add",
			want: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 4), ifaceRoute("10.20.0.0/16", 9), rejectRoute("198.51.100.0/24")},
			ops: []Op{
				addOp(gwRoute("9.9.9.9/32", "192.168.20.1", 4)),
				addOp(ifaceRoute("10.20.0.0/16", 9)),
				addOp(rejectRoute("198.51.100.0/24")),
			}},
		{name: "only delete",
			have: []KernelRoute{ifaceRoute("10.20.0.0/16", 9), gwRoute("9.9.9.9/32", "192.168.20.1", 4), rejectRoute("198.51.100.0/24")},
			ops: []Op{
				delOp(gwRoute("9.9.9.9/32", "192.168.20.1", 4)),
				delOp(ifaceRoute("10.20.0.0/16", 9)),
				delOp(rejectRoute("198.51.100.0/24")),
			}},
		// Utun → utun is an RTM_CHANGE (failover nl → de).
		{name: "change utun",
			want: []KernelRoute{ifaceRoute("198.51.100.0/24", 8)},
			have: []KernelRoute{ifaceRoute("198.51.100.0/24", 7)},
			ops:  []Op{changeOp(ifaceRoute("198.51.100.0/24", 8))}},
		// Gateway → gateway of a network is an RTM_CHANGE
		// (network switch).
		{name: "change gateway address of a network",
			want: []KernelRoute{gwRoute("9.9.0.0/16", "10.0.1.1", 4)},
			have: []KernelRoute{gwRoute("9.9.0.0/16", "192.168.20.1", 4)},
			ops:  []Op{changeOp(gwRoute("9.9.0.0/16", "10.0.1.1", 4))}},
		{name: "same gateway on another interface, network",
			want: []KernelRoute{gwRoute("9.9.0.0/16", "192.168.20.1", 5)},
			have: []KernelRoute{gwRoute("9.9.0.0/16", "192.168.20.1", 4)},
			ops:  []Op{changeOp(gwRoute("9.9.0.0/16", "192.168.20.1", 5))}},
		// design 7.2: a host route (/32, /128) never gets an
		// RTM_CHANGE — another gateway, interface or utun is delete + add.
		{name: "host: change gateway address → delete + add",
			want: []KernelRoute{gwRoute("9.9.9.9/32", "10.0.1.1", 4)},
			have: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 4)},
			ops:  []Op{delOp(gwRoute("9.9.9.9/32", "192.168.20.1", 4)), addOp(gwRoute("9.9.9.9/32", "10.0.1.1", 4))}},
		{name: "host: same gateway on another interface → delete + add",
			want: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 5)},
			have: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 4)},
			ops:  []Op{delOp(gwRoute("9.9.9.9/32", "192.168.20.1", 4)), addOp(gwRoute("9.9.9.9/32", "192.168.20.1", 5))}},
		{name: "host: change utun → delete + add",
			want: []KernelRoute{ifaceRoute("192.0.2.10/32", 8)},
			have: []KernelRoute{ifaceRoute("192.0.2.10/32", 7)},
			ops:  []Op{delOp(ifaceRoute("192.0.2.10/32", 7)), addOp(ifaceRoute("192.0.2.10/32", 8))}},
		{name: "host v6: change utun → delete + add",
			want: []KernelRoute{ifaceRoute("2001:db8:2::10/128", 8)},
			have: []KernelRoute{ifaceRoute("2001:db8:2::10/128", 7)},
			ops:  []Op{delOp(ifaceRoute("2001:db8:2::10/128", 7)), addOp(ifaceRoute("2001:db8:2::10/128", 8))}},
		{name: "host v6: change gateway → delete + add",
			want: []KernelRoute{gwRoute("2001:db8:6::9/128", "fe80::2", 4)},
			have: []KernelRoute{gwRoute("2001:db8:6::9/128", "fe80::1", 4)},
			ops:  []Op{delOp(gwRoute("2001:db8:6::9/128", "fe80::1", 4)), addOp(gwRoute("2001:db8:6::9/128", "fe80::2", 4))}},
		// The same host route is still no op.
		{name: "host: equal",
			want: []KernelRoute{gwRoute("9.9.9.9/32", "192.168.20.1", 4), ifaceRoute("192.0.2.10/32", 7)},
			have: []KernelRoute{ifaceRoute("192.0.2.10/32", 7), gwRoute("9.9.9.9/32", "192.168.20.1", 4)}},
		// A host delete + add goes to the group of kind
		// changes, in prefix order with them, before the RTM_CHANGEs.
		{name: "host delete + add in the kind change group",
			want: []KernelRoute{
				ifaceRoute("10.0.0.0/16", 8),
				ifaceRoute("10.1.1.1/32", 8),
				rejectRoute("10.9.0.0/16"),
				gwRoute("10.10.10.10/32", "192.168.20.1", 4),
			},
			have: []KernelRoute{
				gwRoute("10.10.10.10/32", "192.168.20.1", 5),
				ifaceRoute("10.9.0.0/16", 7),
				ifaceRoute("10.1.1.1/32", 7),
				ifaceRoute("10.0.0.0/16", 7),
			},
			ops: []Op{
				delOp(ifaceRoute("10.1.1.1/32", 7)),
				addOp(ifaceRoute("10.1.1.1/32", 8)),
				delOp(ifaceRoute("10.9.0.0/16", 7)),
				addOp(rejectRoute("10.9.0.0/16")),
				delOp(gwRoute("10.10.10.10/32", "192.168.20.1", 5)),
				addOp(gwRoute("10.10.10.10/32", "192.168.20.1", 4)),
				changeOp(ifaceRoute("10.0.0.0/16", 8)),
			}},
		// Another kind is delete of the old and add of the new,
		// adjacent.
		{name: "kind change iface → gateway",
			want: []KernelRoute{gwRoute("9.9.9.0/24", "192.168.20.1", 4)},
			have: []KernelRoute{ifaceRoute("9.9.9.0/24", 7)},
			ops:  []Op{delOp(ifaceRoute("9.9.9.0/24", 7)), addOp(gwRoute("9.9.9.0/24", "192.168.20.1", 4))}},
		{name: "kind change gateway → reject",
			want: []KernelRoute{rejectRoute("9.9.9.0/24")},
			have: []KernelRoute{gwRoute("9.9.9.0/24", "192.168.20.1", 4)},
			ops:  []Op{delOp(gwRoute("9.9.9.0/24", "192.168.20.1", 4)), addOp(rejectRoute("9.9.9.0/24"))}},
		{name: "kind change reject → iface",
			want: []KernelRoute{ifaceRoute("9.9.9.0/24", 7)},
			have: []KernelRoute{rejectRoute("9.9.9.0/24")},
			ops:  []Op{delOp(rejectRoute("9.9.9.0/24")), addOp(ifaceRoute("9.9.9.0/24", 7))}},
		// Our endpoint host routes (via a gateway or blackhole)
		// are in keep: neither deleted nor changed.
		{name: "keep not deleted",
			want: []KernelRoute{ifaceRoute("10.20.0.0/16", 9)},
			have: []KernelRoute{ep4, hole4, ifaceRoute("10.20.0.0/16", 9), hole6},
			keep: []string{"203.0.113.1/32", "203.0.113.2/32", "2001:db8::2/128"}},
		{name: "keep alone, rest deleted",
			have: []KernelRoute{ep4, ifaceRoute("10.20.0.0/16", 9), hole4},
			keep: []string{"203.0.113.1/32", "203.0.113.2/32"},
			ops:  []Op{delOp(ifaceRoute("10.20.0.0/16", 9))}},
		// A keep entry absent from the kernel is not added either.
		{name: "keep not in have: nothing",
			keep: []string{"203.0.113.1/32"}},
		// The doc of diff: a route of want whose prefix is in
		// keep is ignored — neither added nor changing the kept route.
		{name: "prefix in want and keep, kept route in have: nothing",
			want: []KernelRoute{ifaceRoute("203.0.113.1/32", 7), ifaceRoute("10.20.0.0/16", 9)},
			have: []KernelRoute{ep4, ifaceRoute("10.20.0.0/16", 9)},
			keep: []string{"203.0.113.1/32"}},
		{name: "prefix in want and keep, blackhole in have: nothing",
			want: []KernelRoute{rejectRoute("203.0.113.2/32")},
			have: []KernelRoute{hole4},
			keep: []string{"203.0.113.2/32"}},
		{name: "prefix in want and keep, not in have: nothing",
			want: []KernelRoute{gwRoute("203.0.113.1/32", "192.168.20.1", 4)},
			keep: []string{"203.0.113.1/32"}},
		// Outside keep a blackhole of ours is just another kind: blackhole →
		// reject is delete + add, a stray blackhole is deleted.
		{name: "blackhole → reject outside keep",
			want: []KernelRoute{rejectRoute("192.0.2.30/32"), rejectRoute("2001:db8:30::/48")},
			have: []KernelRoute{holeRoute("2001:db8:30::/48"), holeRoute("192.0.2.30/32")},
			ops: []Op{
				delOp(holeRoute("192.0.2.30/32")),
				addOp(rejectRoute("192.0.2.30/32")),
				delOp(holeRoute("2001:db8:30::/48")),
				addOp(rejectRoute("2001:db8:30::/48")),
			}},
		{name: "blackhole outside keep, not wanted: deleted",
			have: []KernelRoute{holeRoute("192.0.2.30/32")},
			ops:  []Op{delOp(holeRoute("192.0.2.30/32"))}},
		// A route of ours of unknown kind (Kind 0 from owned) is never equal
		// to a wanted one: replaced by delete + add, or deleted.
		{name: "unknown kind, not wanted: deleted",
			want: []KernelRoute{ifaceRoute("10.20.0.0/16", 9)},
			have: []KernelRoute{unknownRoute("10.30.0.0/16"), ifaceRoute("10.20.0.0/16", 9)},
			ops:  []Op{delOp(unknownRoute("10.30.0.0/16"))}},
		{name: "unknown kind, wanted: delete + add",
			want: []KernelRoute{ifaceRoute("10.30.0.0/16", 9), rejectRoute("2001:db8:7::/48"), gwRoute("9.9.9.9/32", "192.168.20.1", 4)},
			have: []KernelRoute{unknownRoute("2001:db8:7::/48"), unknownRoute("10.30.0.0/16"), unknownRoute("9.9.9.9/32")},
			ops: []Op{
				delOp(unknownRoute("9.9.9.9/32")),
				addOp(gwRoute("9.9.9.9/32", "192.168.20.1", 4)),
				delOp(unknownRoute("10.30.0.0/16")),
				addOp(ifaceRoute("10.30.0.0/16", 9)),
				delOp(unknownRoute("2001:db8:7::/48")),
				addOp(rejectRoute("2001:db8:7::/48")),
			}},
		{name: "unknown kind in keep: left alone",
			have: []KernelRoute{unknownRoute("203.0.113.1/32")},
			keep: []string{"203.0.113.1/32"}},
		{name: "IPv6",
			want: []KernelRoute{
				ifaceRoute("2001:db8:1::/48", 8),
				gwRoute("2001:db8:5::/48", "fe80::1", 5),
				rejectRoute("2001:db8:7::/48"),
				ifaceRoute("fd00:20::/48", 9),
			},
			have: []KernelRoute{
				ifaceRoute("2001:db8:1::/48", 7),
				gwRoute("2001:db8:5::/48", "fe80::1", 4),
				ifaceRoute("2001:db8:7::/48", 7),
				gwRoute("2001:db8:9::/48", "fe80::1", 4),
			},
			ops: []Op{
				delOp(ifaceRoute("2001:db8:7::/48", 7)),
				addOp(rejectRoute("2001:db8:7::/48")),
				changeOp(ifaceRoute("2001:db8:1::/48", 8)),
				changeOp(gwRoute("2001:db8:5::/48", "fe80::1", 5)),
				addOp(ifaceRoute("fd00:20::/48", 9)),
				delOp(gwRoute("2001:db8:9::/48", "fe80::1", 4)),
			}},
		// Kind changes, changes, adds, deletes; prefix order
		// within each group. Prefixes are chosen so that the group order
		// differs from the overall prefix order; have is not sorted.
		{name: "group order and prefix order",
			want: []KernelRoute{
				ifaceRoute("10.0.0.0/8", 7),
				ifaceRoute("10.0.0.0/16", 7),
				ifaceRoute("10.3.0.0/16", 8),
				gwRoute("10.3.1.0/24", "192.168.20.1", 5),
				gwRoute("10.4.0.0/16", "192.168.20.1", 4),
				rejectRoute("10.5.0.0/16"),
				ifaceRoute("fd00:4::/48", 7),
			},
			have: []KernelRoute{
				ifaceRoute("fd00:1::/48", 7),
				ifaceRoute("10.5.0.0/16", 7),
				ifaceRoute("10.4.0.0/16", 7),
				gwRoute("10.3.1.0/24", "192.168.20.1", 4),
				ifaceRoute("10.3.0.0/16", 7),
				ifaceRoute("10.2.0.0/16", 7),
				ifaceRoute("10.1.0.0/16", 7),
				rejectRoute("fd00:4::/48"),
			},
			ops: []Op{
				delOp(ifaceRoute("10.4.0.0/16", 7)),
				addOp(gwRoute("10.4.0.0/16", "192.168.20.1", 4)),
				delOp(ifaceRoute("10.5.0.0/16", 7)),
				addOp(rejectRoute("10.5.0.0/16")),
				delOp(rejectRoute("fd00:4::/48")),
				addOp(ifaceRoute("fd00:4::/48", 7)),
				changeOp(ifaceRoute("10.3.0.0/16", 8)),
				changeOp(gwRoute("10.3.1.0/24", "192.168.20.1", 5)),
				addOp(ifaceRoute("10.0.0.0/8", 7)),
				addOp(ifaceRoute("10.0.0.0/16", 7)),
				delOp(ifaceRoute("10.1.0.0/16", 7)),
				delOp(ifaceRoute("10.2.0.0/16", 7)),
				delOp(ifaceRoute("fd00:1::/48", 7)),
			}},
		// Replacing a /16 by /24s: the adds come before the delete, so the
		// traffic never leaves the tunnel.
		{name: "split a prefix: adds before delete",
			want: []KernelRoute{ifaceRoute("10.20.1.0/24", 9), ifaceRoute("10.20.2.0/24", 9)},
			have: []KernelRoute{ifaceRoute("10.20.0.0/16", 9)},
			ops: []Op{
				addOp(ifaceRoute("10.20.1.0/24", 9)),
				addOp(ifaceRoute("10.20.2.0/24", 9)),
				delOp(ifaceRoute("10.20.0.0/16", 9)),
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var keep map[netip.Prefix]bool
			if c.keep != nil {
				keep = map[netip.Prefix]bool{}
				for _, p := range c.keep {
					keep[tP(p)] = true
				}
			}
			var got []Op
			noPanic(t, "diff", func() { got = diff(c.want, c.have, keep) })
			equal := len(got) == len(c.ops)
			for i := 0; equal && i < len(got); i++ {
				equal = got[i].Type == c.ops[i].Type && normRoute(got[i].Route) == normRoute(c.ops[i].Route)
			}
			if !equal {
				t.Errorf("diff mismatch\ngot:\n%swant:\n%s", fmtOps(got), fmtOps(c.ops))
			}
		})
	}
}

// --- routeMsg ----------------------------------------------------------------

// The doc of routeMsg: flags, destination,
// netmask and gateway of the RTM_ADD / RTM_CHANGE message for each kind.
func TestRouteMsg(t *testing.T) {
	const always = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2
	cases := []struct {
		name string
		r    KernelRoute
	}{
		{"iface net v4", ifaceRoute("10.20.0.0/16", 9)},
		{"iface host v4", ifaceRoute("192.0.2.10/32", 7)},
		{"iface net v6", ifaceRoute("fd00:20::/48", 9)},
		{"iface host v6", ifaceRoute("2001:db8:2::10/128", 7)},
		{"gateway net v4", gwRoute("9.9.0.0/16", "192.168.20.1", 4)},
		{"gateway host v4", gwRoute("9.9.9.9/32", "192.168.20.1", 4)},
		{"gateway net v6", gwRoute("2001:db8:5::/48", "2001:db8:ffff::1", 5)},
		{"gateway host v6 link-local", gwRoute("2001:db8:6::9/128", "fe80::1", 4)},
		{"reject net v4", rejectRoute("198.51.100.0/24")},
		{"reject host v4", rejectRoute("192.0.2.20/32")},
		{"reject net v6", rejectRoute("2001:db8:7::/48")},
		{"reject host v6", rejectRoute("2001:db8:dead::1/128")},
	}
	for _, c := range cases {
		for _, typ := range []int{unix.RTM_ADD, unix.RTM_CHANGE} {
			name := c.name + " add"
			if typ == unix.RTM_CHANGE {
				name = c.name + " change"
			}
			t.Run(name, func(t *testing.T) {
				var m *route.RouteMessage
				noPanic(t, "routeMsg", func() { m = routeMsg(typ, c.r, 42) })
				if m == nil {
					t.Fatal("routeMsg returned nil")
				}
				if m.Type != typ {
					t.Errorf("Type = %d, want %d", m.Type, typ)
				}
				if m.Seq != 42 {
					t.Errorf("Seq = %d, want 42", m.Seq)
				}

				host := c.r.Prefix.IsSingleIP()
				want := always
				if host {
					want |= unix.RTF_HOST
				}
				var clear int
				switch c.r.Kind {
				case KindIface:
					clear = unix.RTF_GATEWAY | unix.RTF_REJECT | unix.RTF_BLACKHOLE
				case KindGateway:
					want |= unix.RTF_GATEWAY
					clear = unix.RTF_REJECT | unix.RTF_BLACKHOLE
				case KindReject:
					want |= unix.RTF_REJECT
					// The gateway is lo0's address, without RTF_GATEWAY;
					// Reject, not blackhole.
					clear = unix.RTF_GATEWAY | unix.RTF_BLACKHOLE
				}
				if !host {
					clear |= unix.RTF_HOST
				}
				if m.Flags&want != want {
					t.Errorf("Flags = %#x, missing %#x", m.Flags, want&^m.Flags)
				}
				if m.Flags&clear != 0 {
					t.Errorf("Flags = %#x, unexpected %#x", m.Flags, m.Flags&clear)
				}

				got := roundTrip(t, m)
				if got.Flags != m.Flags {
					t.Errorf("Flags after round trip = %#x, want %#x", got.Flags, m.Flags)
				}

				// RTAX_DST: the prefix address.
				if dst, ok := addrAt(got, unix.RTAX_DST); !ok || dst != c.r.Prefix.Addr() {
					t.Errorf("RTAX_DST = %v (present=%v), want %v", dst, ok, c.r.Prefix.Addr())
				}

				// RTAX_NETMASK: absent for a host route, the prefix mask
				// otherwise (RTM_CHANGE always carries it).
				hasMask := len(got.Addrs) > unix.RTAX_NETMASK && got.Addrs[unix.RTAX_NETMASK] != nil
				switch {
				case host && hasMask:
					t.Errorf("host route carries RTAX_NETMASK %v", got.Addrs[unix.RTAX_NETMASK])
				case !host && !hasMask:
					t.Errorf("network route has no RTAX_NETMASK")
				case !host:
					if mask, ok := addrAt(got, unix.RTAX_NETMASK); !ok || mask != maskAddr(c.r.Prefix) {
						t.Errorf("RTAX_NETMASK = %v (%T), want %v", mask, got.Addrs[unix.RTAX_NETMASK], maskAddr(c.r.Prefix))
					}
				}

				// RTAX_GATEWAY by kind.
				if len(got.Addrs) <= unix.RTAX_GATEWAY || got.Addrs[unix.RTAX_GATEWAY] == nil {
					t.Fatalf("no RTAX_GATEWAY")
				}
				gwAddr := got.Addrs[unix.RTAX_GATEWAY]
				switch c.r.Kind {
				case KindIface:
					// sockaddr_dl with the utun's index.
					la, ok := gwAddr.(*route.LinkAddr)
					if !ok {
						t.Fatalf("RTAX_GATEWAY is %T, want *route.LinkAddr", gwAddr)
					}
					if la.Index != c.r.Index {
						t.Errorf("LinkAddr.Index = %d, want %d", la.Index, c.r.Index)
					}
				case KindGateway:
					gw, ok := addrAt(got, unix.RTAX_GATEWAY)
					if !ok || gw != c.r.Gateway {
						t.Errorf("RTAX_GATEWAY = %v (%T), want %v", gw, gwAddr, c.r.Gateway)
					}
					if c.r.Gateway.Is4() {
						if _, ok := gwAddr.(*route.Inet4Addr); !ok {
							t.Errorf("RTAX_GATEWAY is %T, want *route.Inet4Addr", gwAddr)
						}
					}
					// A link-local gateway is scoped to its interface
					// (inetAddr(Gateway, Index), as for hostRouteMsg).
					if c.r.Gateway.IsLinkLocalUnicast() {
						a6, ok := gwAddr.(*route.Inet6Addr)
						if !ok {
							t.Fatalf("RTAX_GATEWAY is %T, want *route.Inet6Addr", gwAddr)
						}
						if a6.ZoneID != c.r.Index {
							t.Errorf("gateway ZoneID = %d, want %d", a6.ZoneID, c.r.Index)
						}
					}
				case KindReject:
					// To lo0 — the loopback address of the family.
					loop := tA("127.0.0.1")
					if c.r.Prefix.Addr().Is6() {
						loop = tA("::1")
					}
					if gw, ok := addrAt(got, unix.RTAX_GATEWAY); !ok || gw != loop {
						t.Errorf("RTAX_GATEWAY = %v (%T), want %v", gw, gwAddr, loop)
					}
				}
			})
		}
	}
}

// --- dump entries as the kernel reports them ---------------------------------

// kernelAddr is a as a route address, without any scope.
func kernelAddr(a netip.Addr) route.Addr {
	if a.Is4() {
		return &route.Inet4Addr{IP: a.As4()}
	}
	return &route.Inet6Addr{IP: a.As16()}
}

// kernelEntry builds a dump entry (RTM_GET, as sysctl NET_RT_DUMP gives it) by
// hand, not with routeMsg: RTF_HOST and no netmask for a single IP, the
// prefix mask otherwise; flags are given in full.
func kernelEntry(p string, flags, index int, gw route.Addr) *route.RouteMessage {
	pfx := tP(p)
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = kernelAddr(pfx.Addr())
	addrs[unix.RTAX_GATEWAY] = gw
	if pfx.IsSingleIP() {
		flags |= unix.RTF_HOST
	} else {
		addrs[unix.RTAX_NETMASK] = kernelAddr(maskAddr(pfx))
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   flags,
		Index:   index,
		Seq:     1,
		Addrs:   addrs,
	}
}

// Flags of our routes as the kernel holds them: RTF_PRCLONING is set by
// the kernel on a route to an interface (reject to lo0).
const (
	flagsIface   = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PRCLONING | unix.RTF_PROTO2
	flagsGateway = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_PROTO2
	flagsReject  = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_REJECT | unix.RTF_PROTO2
	lo0Index     = 1
)

// linkAddr is the gateway of a route to a utun in a dump: sockaddr_dl with
// the index and the name.
func linkAddr(index int, name string) route.Addr {
	return &route.LinkAddr{Index: index, Name: name}
}

// scopedAddr is a link-local IPv6 gateway with the scope embedded KAME style
// (bytes 2–3), as the kernel reports it, sin6_scope_id left 0.
func scopedAddr(a string, index int) route.Addr {
	ip := tA(a).As16()
	ip[2], ip[3] = byte(index>>8), byte(index)
	return &route.Inet6Addr{IP: ip}
}

// design 7.2 "only the difference" and
// the ruling of step 3: a table applied once and read back from a dump as the
// kernel reports it gives no ops on the next Sync. The dump entries are made
// by hand with what the kernel adds (RTF_PRCLONING, LinkAddr with a name,
// rtm_index of the interface, lo0 for reject, scope embedded in a link-local
// gateway), not with routeMsg.
func TestIdempotentKernelDump(t *testing.T) {
	const utun5, utun6, en0 = 15, 16, 4
	env := Env{
		Ifaces: map[string]int{"nl": utun5, "work": utun6},
		GW4:    Gateway{Addr: tA("192.168.20.1"), Index: en0},
		GW6:    Gateway{Addr: tA("fe80::1"), Index: en0},
	}
	tbl := Table{
		tCIDRVia("9.9.9.0/24", "nl", 0),
		tRuleRoute("9.9.9.9/32", SourceRuleCIDR, TargetDirect, "", 1),
		tAllowed("10.20.0.0/16", "work"),
		tDynVia("192.0.2.10/32", "nl", 0),
		tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 2),
		tCIDRVia("198.18.0.0/15", "de", 0), // no utun → reject
		tRuleRoute("198.51.100.0/24", SourceRuleCIDR, TargetReject, "", 2),
		tEndpoint("203.0.113.1/32"),
		tRuleRoute("2001:db8:5::/48", SourceRuleCIDR, TargetDirect, "", 1),
		tRuleRoute("2001:db8:6::9/128", SourceDynamic, TargetDirect, "", 1),
		tRuleRoute("2001:db8:7::/48", SourceRuleCIDR, TargetReject, "", 2),
		tAllowed("fd00:20::/48", "work"),
	}
	dump := []*route.RouteMessage{
		kernelEntry("9.9.9.0/24", flagsIface, utun5, linkAddr(utun5, "utun5")),
		kernelEntry("9.9.9.9/32", flagsGateway, en0, kernelAddr(tA("192.168.20.1"))),
		kernelEntry("10.20.0.0/16", flagsIface, utun6, linkAddr(utun6, "utun6")),
		kernelEntry("192.0.2.10/32", flagsIface, utun5, linkAddr(utun5, "utun5")),
		kernelEntry("192.0.2.20/32", flagsReject, lo0Index, kernelAddr(tA("127.0.0.1"))),
		kernelEntry("198.18.0.0/15", flagsReject, lo0Index, kernelAddr(tA("127.0.0.1"))),
		kernelEntry("198.51.100.0/24", flagsReject, lo0Index, kernelAddr(tA("127.0.0.1"))),
		// The endpoint host route (keep).
		kernelEntry("203.0.113.1/32", flagsGateway, en0, kernelAddr(tA("192.168.20.1"))),
		kernelEntry("2001:db8:5::/48", flagsGateway, en0, scopedAddr("fe80::1", en0)),
		kernelEntry("2001:db8:6::9/128", flagsGateway, en0, scopedAddr("fe80::1", en0)),
		kernelEntry("2001:db8:7::/48", flagsReject, lo0Index, kernelAddr(tA("::1"))),
		kernelEntry("fd00:20::/48", flagsIface, utun6, linkAddr(utun6, "utun6")),
		// A clone of 9.9.9.0/24 inherits RTF_PROTO2: not ours to
		// manage, no op.
		kernelEntry("9.9.9.10/32", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, utun5, linkAddr(utun5, "utun5")),
		// A foreign route.
		kernelEntry("192.168.20.0/24", unix.RTF_UP|unix.RTF_CLONING|unix.RTF_STATIC, en0, linkAddr(en0, "en0")),
	}

	var (
		want []KernelRoute
		keep map[netip.Prefix]bool
	)
	noPanic(t, "wanted", func() { want, keep, _ = wanted(tbl, env) })
	msgs := dumpMsgs(t, dump...)
	var have []KernelRoute
	noPanic(t, "owned", func() { have = owned(msgs) })
	var ops []Op
	noPanic(t, "diff", func() { ops = diff(want, have, keep) })
	if len(ops) != 0 {
		t.Errorf("second Sync is not empty\nops:\n%swant:\n%shave:\n%s", fmtOps(ops), fmtRoutes(want), fmtRoutes(have))
	}
}

// --- owned: rtm_index, clones, unknown kind ----------------------------------

// Ruling of step 3: the interface of a route to a utun is rtm_index of the
// dump entry (RTM_CHANGE may change the interface apart from the gateway);
// LinkAddr.Index only when rtm_index is 0. Clones (RTF_WASCLONED) are left
// out. An entry of ours of a kind owned cannot tell is kept with Kind 0, so
// that diff replaces or deletes it.
func TestOwnedKernelEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry *route.RouteMessage
		want  []KernelRoute
	}{
		{name: "iface: rtm_index differs from LinkAddr.Index → rtm_index",
			entry: kernelEntry("10.20.0.0/16", flagsIface, 9, linkAddr(7, "utun3")),
			want:  []KernelRoute{ifaceRoute("10.20.0.0/16", 9)}},
		{name: "iface host: rtm_index differs from LinkAddr.Index → rtm_index",
			entry: kernelEntry("192.0.2.10/32", flagsIface, 9, linkAddr(7, "utun3")),
			want:  []KernelRoute{ifaceRoute("192.0.2.10/32", 9)}},
		{name: "iface: rtm_index 0 → LinkAddr.Index",
			entry: kernelEntry("10.20.0.0/16", flagsIface, 0, linkAddr(7, "utun3")),
			want:  []KernelRoute{ifaceRoute("10.20.0.0/16", 7)}},
		{name: "iface v6: rtm_index 0 → LinkAddr.Index",
			entry: kernelEntry("fd00:20::/48", flagsIface, 0, linkAddr(7, "")),
			want:  []KernelRoute{ifaceRoute("fd00:20::/48", 7)}},
		{name: "clone of an iface route left out",
			entry: kernelEntry("10.20.0.5/32", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, 7, linkAddr(7, "utun3"))},
		{name: "clone of a gateway route left out",
			entry: kernelEntry("9.9.1.1/32", unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_PROTO2|unix.RTF_WASCLONED, 4, kernelAddr(tA("192.168.20.1")))},
		{name: "clone v6 left out",
			entry: kernelEntry("fd00:20::5/128", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, 7, linkAddr(7, "utun3"))},
		// A link gateway with RTF_GATEWAY is neither a route to an interface
		// (no RTF_GATEWAY) nor via a gateway address.
		{name: "unknown: link gateway with RTF_GATEWAY → Kind 0",
			entry: kernelEntry("10.30.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY|unix.RTF_PROTO2, 7, linkAddr(7, "utun3")),
			want:  []KernelRoute{unknownRoute("10.30.0.0/16")}},
		// An address gateway without RTF_GATEWAY, RTF_REJECT or
		// RTF_BLACKHOLE.
		{name: "unknown: address gateway without kind flags → Kind 0",
			entry: kernelEntry("10.31.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_PROTO2, 4, kernelAddr(tA("192.168.20.1"))),
			want:  []KernelRoute{unknownRoute("10.31.0.0/16")}},
		{name: "unknown host v6 → Kind 0",
			entry: kernelEntry("2001:db8:31::1/128", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_PROTO2, 4, kernelAddr(tA("2001:db8:ffff::1"))),
			want:  []KernelRoute{unknownRoute("2001:db8:31::1/128")}},
		// The same shapes without RTF_PROTO2 are foreign: left out.
		{name: "foreign of unknown shape left out",
			entry: kernelEntry("10.30.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY, 7, linkAddr(7, "utun3"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := dumpMsgs(t, c.entry)
			var got []KernelRoute
			noPanic(t, "owned", func() { got = owned(msgs) })
			sameRoutes(t, "owned", got, c.want)
		})
	}
}

// --- routeMsg: rtm_index -----------------------------------------------------

// Ruling of step 3 and the doc of routeMsg: rtm_index is r.Index for routes
// to an interface and via a gateway, 0 for reject.
func TestRouteMsgIndex(t *testing.T) {
	cases := []struct {
		r     KernelRoute
		index int
	}{
		{ifaceRoute("10.20.0.0/16", 9), 9},
		{ifaceRoute("192.0.2.10/32", 7), 7},
		{ifaceRoute("fd00:20::/48", 9), 9},
		{gwRoute("9.9.0.0/16", "192.168.20.1", 4), 4},
		{gwRoute("9.9.9.9/32", "192.168.20.1", 5), 5},
		{gwRoute("2001:db8:5::/48", "fe80::1", 4), 4},
		{rejectRoute("198.51.100.0/24"), 0},
		{rejectRoute("2001:db8:7::/48"), 0},
	}
	for _, c := range cases {
		for _, typ := range []int{unix.RTM_ADD, unix.RTM_CHANGE} {
			t.Run(fmt.Sprintf("%s type %d", fmtRoute(c.r), typ), func(t *testing.T) {
				var m *route.RouteMessage
				noPanic(t, "routeMsg", func() { m = routeMsg(typ, c.r, 1) })
				if m == nil {
					t.Fatal("routeMsg returned nil")
				}
				if m.Index != c.index {
					t.Errorf("Index = %d, want %d", m.Index, c.index)
				}
			})
		}
	}
}

// --- scoped host routes to the DNS servers of tunnels --------------------

// scopedRoute is a scoped host route of ours to a DNS server of a tunnel
// (AddScoped): RTF_HOST|RTF_IFSCOPE|RTF_PROTO2, gateway
// LinkAddr{Index} and rtm_index of the utun, as a dump gives it.
func scopedRoute(dst string, index int, name string) *route.RouteMessage {
	a := tA(dst)
	return kernelEntry(netip.PrefixFrom(a, a.BitLen()).String(),
		unix.RTF_UP|unix.RTF_STATIC|unix.RTF_IFSCOPE|unix.RTF_PROTO2, index, linkAddr(index, name))
}

// design 7.2 (scoped routes are left alone by sync), 8:
// owned skips entries with RTF_IFSCOPE, so Sync does not see our scoped host
// routes; the unscoped routes of ours in the same dump are still read.
func TestOwnedSkipsScoped(t *testing.T) {
	const utun5, utun6 = 15, 16
	cases := []struct {
		name string
		dump []*route.RouteMessage
		want []KernelRoute
	}{
		{name: "scoped v4 only",
			dump: []*route.RouteMessage{scopedRoute("1.0.0.1", utun5, "utun5")}},
		{name: "scoped v6 only",
			dump: []*route.RouteMessage{scopedRoute("2606:4700:4700::1001", utun5, "utun5")}},
		{name: "one DNS server scoped on two utuns",
			dump: []*route.RouteMessage{scopedRoute("1.0.0.1", utun5, "utun5"), scopedRoute("1.0.0.1", utun6, "utun6")}},
		{name: "scoped and an unscoped route of ours to the same address",
			dump: []*route.RouteMessage{
				scopedRoute("1.0.0.1", utun5, "utun5"),
				kernelEntry("1.0.0.1/32", flagsIface, utun6, linkAddr(utun6, "utun6")),
			},
			want: []KernelRoute{ifaceRoute("1.0.0.1/32", utun6)}},
		{name: "scoped among routes of every kind",
			dump: []*route.RouteMessage{
				kernelEntry("9.9.9.0/24", flagsIface, utun5, linkAddr(utun5, "utun5")),
				scopedRoute("10.199.17.1", utun6, "utun6"),
				kernelEntry("198.51.100.0/24", flagsReject, lo0Index, kernelAddr(tA("127.0.0.1"))),
				scopedRoute("1.0.0.1", utun5, "utun5"),
				kernelEntry("9.9.9.9/32", flagsGateway, 4, kernelAddr(tA("192.168.20.1"))),
			},
			want: []KernelRoute{
				ifaceRoute("9.9.9.0/24", utun5),
				rejectRoute("198.51.100.0/24"),
				gwRoute("9.9.9.9/32", "192.168.20.1", 4),
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := dumpMsgs(t, c.dump...)
			var got []KernelRoute
			noPanic(t, "owned", func() { got = owned(msgs) })
			sameRoutes(t, "owned", got, c.want)
		})
	}

	// The same entry built with routeMsg plus RTF_IFSCOPE.
	t.Run("routeMsg entry with RTF_IFSCOPE", func(t *testing.T) {
		var msgs []route.Message
		noPanic(t, "routeMsg", func() {
			m := entryMsg(ifaceRoute("1.0.0.1/32", utun5))
			m.Flags |= unix.RTF_IFSCOPE
			msgs = dumpMsgs(t, m)
		})
		if msgs == nil {
			return
		}
		var got []KernelRoute
		noPanic(t, "owned", func() { got = owned(msgs) })
		sameRoutes(t, "owned", got, nil)
	})
}

// design 7.2, 8: a dump with our scoped host routes gives no
// op that deletes or changes them; a dynamic /32 to the same address
// (another tunnel, the same utun or direct) is an unscoped route of its own
// and is added.
func TestDiffKeepsScoped(t *testing.T) {
	const utun5, utun6 = 15, 16
	cases := []struct {
		name string
		want []KernelRoute
		dump []*route.RouteMessage
		ops  []Op
	}{
		{name: "nothing wanted: scoped routes stay",
			dump: []*route.RouteMessage{
				scopedRoute("1.0.0.1", utun5, "utun5"),
				scopedRoute("2606:4700:4700::1001", utun5, "utun5"),
			}},
		{name: "dynamic /32 to the DNS server via another tunnel: add only",
			want: []KernelRoute{ifaceRoute("1.0.0.1/32", utun6)},
			dump: []*route.RouteMessage{scopedRoute("1.0.0.1", utun5, "utun5")},
			ops:  []Op{addOp(ifaceRoute("1.0.0.1/32", utun6))}},
		{name: "dynamic /32 to the DNS server via the same utun: add only",
			want: []KernelRoute{ifaceRoute("1.0.0.1/32", utun5)},
			dump: []*route.RouteMessage{scopedRoute("1.0.0.1", utun5, "utun5")},
			ops:  []Op{addOp(ifaceRoute("1.0.0.1/32", utun5))}},
		{name: "direct /32 to the DNS server: add only",
			want: []KernelRoute{gwRoute("1.0.0.1/32", "192.168.20.1", 4)},
			dump: []*route.RouteMessage{scopedRoute("1.0.0.1", utun5, "utun5")},
			ops:  []Op{addOp(gwRoute("1.0.0.1/32", "192.168.20.1", 4))}},
		{name: "unscoped already in place: no ops",
			want: []KernelRoute{ifaceRoute("1.0.0.1/32", utun6)},
			dump: []*route.RouteMessage{
				scopedRoute("1.0.0.1", utun5, "utun5"),
				kernelEntry("1.0.0.1/32", flagsIface, utun6, linkAddr(utun6, "utun6")),
			}},
		{name: "unscoped of ours no longer wanted: deleted, scoped stays",
			dump: []*route.RouteMessage{
				scopedRoute("1.0.0.1", utun5, "utun5"),
				kernelEntry("1.0.0.1/32", flagsIface, utun6, linkAddr(utun6, "utun6")),
			},
			ops: []Op{delOp(ifaceRoute("1.0.0.1/32", utun6))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := dumpMsgs(t, c.dump...)
			var have []KernelRoute
			noPanic(t, "owned", func() { have = owned(msgs) })
			var ops []Op
			noPanic(t, "diff", func() { ops = diff(c.want, have, nil) })
			same := len(ops) == len(c.ops)
			for i := 0; same && i < len(ops); i++ {
				same = ops[i].Type == c.ops[i].Type && normRoute(ops[i].Route) == normRoute(c.ops[i].Route)
			}
			if !same {
				t.Errorf("ops:\n%swant:\n%s", fmtOps(ops), fmtOps(c.ops))
			}
		})
	}
}
