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

// Tests follow design 5 and 6.2 (sync of the computed table with the kernel:
// only the difference, RTF_PROTO2 marks our routes, RTM_CHANGE for another
// utun or gateway, delete + add for another kind, foreign routes and endpoint
// host routes left alone) and the M4 plan ("Факты spike", "Модель",
// "Решения" 1, 3, 6, 7, 10, 11) with the doc comments of wanted, owned, diff and
// routeMsg — not the implementation.

// --- helpers ---------------------------------------------------------------

// m4NoPanic runs f and turns a panic into a test failure.
func m4NoPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// m4Iface, m4GW, m4Rej and m4Hole build kernel routes of each kind.
func m4Iface(p string, index int) KernelRoute {
	return KernelRoute{Prefix: tP(p), Kind: KindIface, Index: index}
}

func m4GW(p, gw string, index int) KernelRoute {
	return KernelRoute{Prefix: tP(p), Kind: KindGateway, Index: index, Gateway: tA(gw)}
}

func m4Rej(p string) KernelRoute  { return KernelRoute{Prefix: tP(p), Kind: KindReject} }
func m4Hole(p string) KernelRoute { return KernelRoute{Prefix: tP(p), Kind: KindBlackhole} }

// m4Unknown is a route of ours whose kind owned cannot tell (Kind 0).
func m4Unknown(p string) KernelRoute { return KernelRoute{Prefix: tP(p)} }

func m4Add(r KernelRoute) Op    { return Op{Type: OpAdd, Route: r} }
func m4Change(r KernelRoute) Op { return Op{Type: OpChange, Route: r} }
func m4Del(r KernelRoute) Op    { return Op{Type: OpDelete, Route: r} }

// m4Norm keeps what the plan prescribes for a kernel route: for reject and
// blackhole routes only Prefix and Kind (the interface is lo0, the gateway a
// loopback address, neither is part of the model), the same for a route of
// unknown kind (Kind 0: what else owned keeps of it is not specified); the
// zone of a gateway is dropped (the scope is carried by Index).
func m4Norm(r KernelRoute) KernelRoute {
	switch r.Kind {
	case KindReject, KindBlackhole, 0:
		return KernelRoute{Prefix: r.Prefix, Kind: r.Kind}
	}
	r.Gateway = r.Gateway.WithZone("")
	return r
}

// m4Less is the table order: Prefix.Addr().Compare, then Bits().
func m4Less(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// m4Sorted returns normalized routes sorted by prefix.
func m4Sorted(rs []KernelRoute) []KernelRoute {
	out := make([]KernelRoute, len(rs))
	for i, r := range rs {
		out[i] = m4Norm(r)
	}
	sort.SliceStable(out, func(i, j int) bool { return m4Less(out[i].Prefix, out[j].Prefix) })
	return out
}

func m4KindName(k Kind) string {
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

func m4Fmt(r KernelRoute) string {
	return fmt.Sprintf("%s %s idx=%d gw=%v", r.Prefix, m4KindName(r.Kind), r.Index, r.Gateway)
}

func m4FmtRoutes(rs []KernelRoute) string {
	if len(rs) == 0 {
		return "  (empty)\n"
	}
	var b strings.Builder
	for _, r := range rs {
		b.WriteString("  " + m4Fmt(r) + "\n")
	}
	return b.String()
}

func m4FmtOps(ops []Op) string {
	if len(ops) == 0 {
		return "  (empty)\n"
	}
	var b strings.Builder
	for _, op := range ops {
		b.WriteString(fmt.Sprintf("  %-6s %s\n", op.Type, m4Fmt(op.Route)))
	}
	return b.String()
}

func m4SameRoutes(t *testing.T, what string, got, want []KernelRoute) {
	t.Helper()
	g, w := m4Sorted(got), m4Sorted(want)
	equal := len(g) == len(w)
	for i := 0; equal && i < len(g); i++ {
		equal = g[i] == w[i]
	}
	if !equal {
		t.Errorf("%s mismatch\ngot:\n%swant:\n%s", what, m4FmtRoutes(g), m4FmtRoutes(w))
	}
}

// m4Dump marshals msgs into one buffer and parses it the way a routing table
// dump (sysctl NET_RT_DUMP) is read. The parsed messages carry the Type they
// were built with (RTM_ADD), not RTM_GET: owned must look at flags only.
func m4Dump(t *testing.T, msgs ...*route.RouteMessage) []route.Message {
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

// m4Mask is the netmask of p as an address.
func m4Mask(p netip.Prefix) netip.Addr {
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	a, _ := netip.AddrFromSlice(net.CIDRMask(p.Bits(), bits))
	return a
}

// --- wanted ------------------------------------------------------------------

// m4Env is a network with a utun for nl and work and gateways of both
// families; the IPv6 one is link-local, as router advertisements give it.
func m4Env() Env {
	return Env{
		Ifaces: map[string]int{"nl": 7, "work": 9},
		GW4:    Gateway{Addr: tA("192.168.20.1"), Index: 4},
		GW6:    Gateway{Addr: tA("fe80::1"), Index: 4},
	}
}

// design 6.2, plan "Модель" 1, decisions 1, 3, 6: tunnel → route on the
// tunnel's utun; direct → via the physical gateway of its family; reject →
// RTF_REJECT; endpoint host routes go to keep; a direct route without a
// gateway of its family is skipped; a tunnel without a utun is reject
// (decision 10).
func TestM4Wanted(t *testing.T) {
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
		{name: "every target, IPv4 and IPv6", env: m4Env(),
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
				m4GW("9.9.9.9/32", "192.168.20.1", 4),
				m4Iface("10.20.0.0/16", 9),
				m4Iface("192.0.2.10/32", 7),
				m4Rej("192.0.2.20/32"),
				m4Iface("198.51.100.0/24", 7),
				m4GW("2001:db8:5::/48", "fe80::1", 4),
				m4GW("2001:db8:6::9/128", "fe80::1", 4),
				m4Rej("2001:db8:7::/48"),
				m4Iface("fd00:20::/48", 9),
			}},
		// decision 6: endpoint routes are AddHost's; they go to keep only,
		// with or without a gateway.
		{name: "endpoints go to keep", env: m4Env(),
			tbl: Table{
				tAllowed("10.20.0.0/16", "work"),
				tEndpoint("203.0.113.1/32"),
				tEndpoint("2001:db8::1/128"),
			},
			want: []KernelRoute{m4Iface("10.20.0.0/16", 9)},
			keep: []string{"203.0.113.1/32", "2001:db8::1/128"}},
		{name: "endpoints without any gateway: keep, not skipped", env: Env{},
			tbl:  Table{tEndpoint("203.0.113.1/32"), tEndpoint("2001:db8::1/128")},
			keep: []string{"203.0.113.1/32", "2001:db8::1/128"}},
		// decision 3: no gateway of its family → skipped; the other family
		// and other targets are unaffected.
		{name: "no IPv4 gateway",
			env: Env{Ifaces: map[string]int{"nl": 7}, GW6: Gateway{Addr: tA("fe80::1"), Index: 4}},
			tbl: Table{direct4, tDynVia("192.0.2.10/32", "nl", 0), direct6},
			want: []KernelRoute{
				m4Iface("192.0.2.10/32", 7),
				m4GW("2001:db8:5::/48", "fe80::1", 4),
			},
			skip: []skip{{direct4, noGW}}},
		{name: "no IPv6 gateway",
			env: Env{Ifaces: map[string]int{"nl": 7}, GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl: Table{direct4, direct6, dynDirect6, tRuleRoute("2001:db8:7::/48", SourceRuleCIDR, TargetReject, "", 2)},
			want: []KernelRoute{
				m4GW("9.9.9.9/32", "192.168.20.1", 4),
				m4Rej("2001:db8:7::/48"),
			},
			skip: []skip{{direct6, noGW}, {dynDirect6, noGW}}},
		{name: "no gateways at all: tunnel and reject stay", env: Env{Ifaces: map[string]int{"nl": 7}},
			tbl: Table{
				direct4,
				tDynVia("192.0.2.10/32", "nl", 0),
				tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 2),
				direct6,
			},
			want: []KernelRoute{m4Iface("192.0.2.10/32", 7), m4Rej("192.0.2.20/32")},
			skip: []skip{{direct4, noGW}, {direct6, noGW}}},
		// design 6.2, decision 10: a tunnel without an entry in Ifaces (on,
		// but its utun is being recreated) gets reject, not a skip: the
		// traffic must not leave directly.
		{name: "tunnel without utun: reject", env: m4Env(),
			tbl: Table{
				tDynVia("192.0.2.10/32", "nl", 0),
				viaDe,
				tDynVia("192.0.2.11/32", "de", 0),
				tAllowed("fd00:30::/48", "de"),
			},
			want: []KernelRoute{
				m4Iface("192.0.2.10/32", 7),
				m4Rej("192.0.2.11/32"),
				m4Rej("198.18.0.0/15"),
				m4Rej("fd00:30::/48"),
			}},
		// design 6.2, decision 10, boundary: an entry with a non-positive
		// index means no utun, the same as a missing entry.
		{name: "tunnel with index 0: reject",
			env: Env{Ifaces: map[string]int{"nl": 7, "de": 0}, GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl: Table{
				tDynVia("192.0.2.10/32", "nl", 0),
				viaDe,
				tAllowed("fd00:30::/48", "de"),
			},
			want: []KernelRoute{
				m4Iface("192.0.2.10/32", 7),
				m4Rej("198.18.0.0/15"),
				m4Rej("fd00:30::/48"),
			}},
		{name: "tunnel with negative index: reject",
			env:  Env{Ifaces: map[string]int{"de": -1}},
			tbl:  Table{viaDe},
			want: []KernelRoute{m4Rej("198.18.0.0/15")}},
		{name: "nil Ifaces: reject", env: Env{GW4: Gateway{Addr: tA("192.168.20.1"), Index: 4}},
			tbl:  Table{direct4, viaDe},
			want: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Rej("198.18.0.0/15")}},
		// No gateway and no utun: the direct route is skipped, the tunnel
		// one is still reject.
		{name: "no gateway, no utun", env: Env{},
			tbl:  Table{direct4, viaDe},
			want: []KernelRoute{m4Rej("198.18.0.0/15")},
			skip: []skip{{direct4, noGW}}},
		{name: "empty table", env: m4Env(), tbl: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				want    []KernelRoute
				keep    map[netip.Prefix]bool
				skipped []Skip
			)
			m4NoPanic(t, "wanted", func() { want, keep, skipped = wanted(c.tbl, c.env) })

			m4SameRoutes(t, "want", want, c.want)

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

			sort.SliceStable(skipped, func(i, j int) bool { return m4Less(skipped[i].Route.Prefix, skipped[j].Route.Prefix) })
			ws := append([]skip(nil), c.skip...)
			sort.SliceStable(ws, func(i, j int) bool { return m4Less(ws[i].r.Prefix, ws[j].r.Prefix) })
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

// m4Entry builds a dump entry for r with routeMsg and sets rtm_index as the
// kernel reports it in a dump (fact 1: the utun for a route on an interface;
// the gateway's interface; lo0 for reject).
func m4Entry(r KernelRoute) *route.RouteMessage {
	m := routeMsg(unix.RTM_ADD, r, 1)
	switch r.Kind {
	case KindIface, KindGateway:
		m.Index = r.Index
	default:
		m.Index = 1 // lo0
	}
	return m
}

// m4HostEntry builds a dump entry for an M3 endpoint host route with
// hostRouteMsg (blackhole without a gateway address).
func m4HostEntry(dst string, gw Gateway) *route.RouteMessage {
	m := hostRouteMsg(unix.RTM_ADD, tA(dst), gw, 1)
	if gw.Addr.IsValid() {
		m.Index = gw.Index
	} else {
		m.Index = 1 // lo0
	}
	return m
}

// design 5, 6.2, plan "Модель" 2: owned reads our routes (RTF_PROTO2) back
// from a dump — every kind, host and network, IPv4 and IPv6 — and leaves out
// foreign routes, entries without RTAX_DST and messages of other types.
func TestM4Owned(t *testing.T) {
	gw4 := Gateway{Addr: tA("192.168.20.1"), Index: 4}
	gw6 := Gateway{Addr: tA("fe80::1"), Index: 4}
	ours := []KernelRoute{
		m4Iface("10.20.0.0/16", 9),
		m4Iface("192.0.2.10/32", 7),
		m4GW("9.9.0.0/16", "192.168.20.1", 4),
		m4GW("9.9.9.9/32", "192.168.20.1", 4),
		m4Rej("198.51.100.0/24"),
		m4Rej("192.0.2.20/32"),
		m4Iface("fd00:20::/48", 9),
		m4Iface("2001:db8:2::10/128", 7),
		m4GW("2001:db8:5::/48", "fe80::1", 4),
		m4GW("2001:db8:6::9/128", "2001:db8:ffff::1", 5),
		m4Rej("2001:db8:7::/48"),
		m4Rej("2001:db8:dead::1/128"),
	}
	hosts := []KernelRoute{
		m4GW("203.0.113.1/32", "192.168.20.1", 4),
		m4Hole("203.0.113.2/32"),
		m4GW("2001:db8::1/128", "fe80::1", 4),
		m4Hole("2001:db8::2/128"),
	}

	var (
		msgs   []route.Message
		parsed bool
	)
	m4NoPanic(t, "routeMsg", func() {
		var in []*route.RouteMessage
		for _, r := range ours {
			in = append(in, m4Entry(r))
		}
		in = append(in,
			m4HostEntry("203.0.113.1", gw4),
			m4HostEntry("203.0.113.2", Gateway{}),
			m4HostEntry("2001:db8::1", gw6),
			m4HostEntry("2001:db8::2", Gateway{}),
		)
		// A foreign route: the same message without RTF_PROTO2.
		foreign := m4Entry(m4Iface("10.30.0.0/16", 9))
		foreign.Flags &^= unix.RTF_PROTO2
		foreignHost := m4HostEntry("203.0.113.3", gw4)
		foreignHost.Flags &^= unix.RTF_PROTO2
		// An entry of ours without RTAX_DST cannot be read.
		noDst := m4Entry(m4Iface("10.40.0.0/16", 9))
		noDst.Addrs[unix.RTAX_DST] = nil
		in = append(in, foreign, foreignHost, noDst)
		msgs = m4Dump(t, in...)
		parsed = true
	})
	if !parsed {
		return
	}
	// A message of another type in the dump.
	msgs = append(msgs, &route.InterfaceMessage{Version: unix.RTM_VERSION, Type: unix.RTM_IFINFO, Index: 4, Name: "en0"})

	var got []KernelRoute
	m4NoPanic(t, "owned", func() { got = owned(msgs) })
	m4SameRoutes(t, "owned", got, append(append([]KernelRoute(nil), ours...), hosts...))
}

// Each kind on its own, so that a failure points at one kind.
func TestM4OwnedEach(t *testing.T) {
	for _, r := range []KernelRoute{
		m4Iface("10.20.0.0/16", 9),
		m4Iface("192.0.2.10/32", 7),
		m4GW("9.9.0.0/16", "192.168.20.1", 4),
		m4GW("9.9.9.9/32", "192.168.20.1", 4),
		m4Rej("198.51.100.0/24"),
		m4Rej("192.0.2.20/32"),
		m4Iface("fd00:20::/48", 9),
		m4GW("2001:db8:5::/48", "fe80::1", 4),
		m4Rej("2001:db8:7::/48"),
	} {
		t.Run(m4Fmt(r), func(t *testing.T) {
			var msgs []route.Message
			m4NoPanic(t, "routeMsg", func() { msgs = m4Dump(t, m4Entry(r)) })
			if msgs == nil {
				return
			}
			var got []KernelRoute
			m4NoPanic(t, "owned", func() { got = owned(msgs) })
			m4SameRoutes(t, "owned", got, []KernelRoute{r})
		})
	}
}

// design 6.2, fact 1: in a dump a reject or blackhole route carries lo0's
// index; owned still reports its kind (only Prefix and Kind are compared).
func TestM4OwnedLo0(t *testing.T) {
	for _, r := range []KernelRoute{
		m4Rej("198.51.100.0/24"),
		m4Rej("192.0.2.20/32"),
		m4Rej("2001:db8:7::/48"),
		m4Rej("2001:db8:dead::1/128"),
		m4Hole("203.0.113.2/32"),
		m4Hole("2001:db8::2/128"),
	} {
		t.Run(m4Fmt(r), func(t *testing.T) {
			var msgs []route.Message
			m4NoPanic(t, "routeMsg", func() {
				m := m4Entry(r)
				m.Index = 1 // lo0
				msgs = m4Dump(t, m)
			})
			if msgs == nil {
				return
			}
			var got []KernelRoute
			m4NoPanic(t, "owned", func() { got = owned(msgs) })
			m4SameRoutes(t, "owned", got, []KernelRoute{r})
		})
	}
	// The M3 endpoint blackhole as hostRouteMsg builds it, with lo0's index.
	for _, dst := range []string{"203.0.113.2", "2001:db8::2"} {
		t.Run("host blackhole "+dst, func(t *testing.T) {
			var msgs []route.Message
			m4NoPanic(t, "hostRouteMsg", func() {
				m := m4HostEntry(dst, Gateway{})
				m.Index = 1 // lo0
				msgs = m4Dump(t, m)
			})
			if msgs == nil {
				return
			}
			a := tA(dst)
			want := KernelRoute{Prefix: netip.PrefixFrom(a, a.BitLen()), Kind: KindBlackhole}
			var got []KernelRoute
			m4NoPanic(t, "owned", func() { got = owned(msgs) })
			m4SameRoutes(t, "owned", got, []KernelRoute{want})
		})
	}
}

// Only foreign or unreadable entries: nothing is ours.
func TestM4OwnedNothing(t *testing.T) {
	m4NoPanic(t, "owned(nil)", func() {
		if got := owned(nil); len(got) != 0 {
			t.Errorf("owned(nil) = %s", m4FmtRoutes(got))
		}
	})
	var msgs []route.Message
	m4NoPanic(t, "hostRouteMsg", func() {
		foreign := m4HostEntry("203.0.113.3", Gateway{Addr: tA("192.168.20.1"), Index: 4})
		foreign.Flags &^= unix.RTF_PROTO2
		msgs = m4Dump(t, foreign)
	})
	msgs = append(msgs, &route.InterfaceMessage{Version: unix.RTM_VERSION, Type: unix.RTM_IFINFO, Index: 4, Name: "en0"})
	m4NoPanic(t, "owned", func() {
		if got := owned(msgs); len(got) != 0 {
			t.Errorf("owned = %s, want none", m4FmtRoutes(got))
		}
	})
}

// --- diff --------------------------------------------------------------------

// design 6.2, plan "Модель" 3, decisions 6, 7: the ops that turn have into
// want — RTM_CHANGE for another utun or gateway of the same kind, delete +
// add for another kind, adds before deletes, keep left alone.
func TestM4Diff(t *testing.T) {
	ep4 := m4GW("203.0.113.1/32", "192.168.20.1", 4)
	hole4 := m4Hole("203.0.113.2/32")
	hole6 := m4Hole("2001:db8::2/128")
	cases := []struct {
		name string
		want []KernelRoute
		have []KernelRoute
		keep []string
		ops  []Op
	}{
		{name: "both empty"},
		{name: "equal",
			want: []KernelRoute{m4Iface("10.20.0.0/16", 9), m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Rej("198.51.100.0/24")},
			have: []KernelRoute{m4Iface("10.20.0.0/16", 9), m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Rej("198.51.100.0/24")}},
		// A dump has no particular order.
		{name: "equal, have in another order",
			want: []KernelRoute{m4Iface("10.20.0.0/16", 9), m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Rej("198.51.100.0/24")},
			have: []KernelRoute{m4Rej("198.51.100.0/24"), m4Iface("10.20.0.0/16", 9), m4GW("9.9.9.9/32", "192.168.20.1", 4)}},
		// Only Index (KindIface) or Gateway/Index (KindGateway) matter beyond
		// prefix and kind: a reject route from a dump carries lo0's index.
		{name: "reject: index not compared",
			want: []KernelRoute{m4Rej("198.51.100.0/24")},
			have: []KernelRoute{{Prefix: tP("198.51.100.0/24"), Kind: KindReject, Index: 1}}},
		{name: "only add",
			want: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Iface("10.20.0.0/16", 9), m4Rej("198.51.100.0/24")},
			ops: []Op{
				m4Add(m4GW("9.9.9.9/32", "192.168.20.1", 4)),
				m4Add(m4Iface("10.20.0.0/16", 9)),
				m4Add(m4Rej("198.51.100.0/24")),
			}},
		{name: "only delete",
			have: []KernelRoute{m4Iface("10.20.0.0/16", 9), m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Rej("198.51.100.0/24")},
			ops: []Op{
				m4Del(m4GW("9.9.9.9/32", "192.168.20.1", 4)),
				m4Del(m4Iface("10.20.0.0/16", 9)),
				m4Del(m4Rej("198.51.100.0/24")),
			}},
		// decision 7: utun → utun is an RTM_CHANGE (failover nl → de).
		{name: "change utun",
			want: []KernelRoute{m4Iface("198.51.100.0/24", 8)},
			have: []KernelRoute{m4Iface("198.51.100.0/24", 7)},
			ops:  []Op{m4Change(m4Iface("198.51.100.0/24", 8))}},
		// decision 7: gateway → gateway of a network is an RTM_CHANGE
		// (network switch).
		{name: "change gateway address of a network",
			want: []KernelRoute{m4GW("9.9.0.0/16", "10.0.1.1", 4)},
			have: []KernelRoute{m4GW("9.9.0.0/16", "192.168.20.1", 4)},
			ops:  []Op{m4Change(m4GW("9.9.0.0/16", "10.0.1.1", 4))}},
		{name: "same gateway on another interface, network",
			want: []KernelRoute{m4GW("9.9.0.0/16", "192.168.20.1", 5)},
			have: []KernelRoute{m4GW("9.9.0.0/16", "192.168.20.1", 4)},
			ops:  []Op{m4Change(m4GW("9.9.0.0/16", "192.168.20.1", 5))}},
		// design 6.2, decision 11: a host route (/32, /128) never gets an
		// RTM_CHANGE — another gateway, interface or utun is delete + add.
		{name: "host: change gateway address → delete + add",
			want: []KernelRoute{m4GW("9.9.9.9/32", "10.0.1.1", 4)},
			have: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 4)},
			ops:  []Op{m4Del(m4GW("9.9.9.9/32", "192.168.20.1", 4)), m4Add(m4GW("9.9.9.9/32", "10.0.1.1", 4))}},
		{name: "host: same gateway on another interface → delete + add",
			want: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 5)},
			have: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 4)},
			ops:  []Op{m4Del(m4GW("9.9.9.9/32", "192.168.20.1", 4)), m4Add(m4GW("9.9.9.9/32", "192.168.20.1", 5))}},
		{name: "host: change utun → delete + add",
			want: []KernelRoute{m4Iface("192.0.2.10/32", 8)},
			have: []KernelRoute{m4Iface("192.0.2.10/32", 7)},
			ops:  []Op{m4Del(m4Iface("192.0.2.10/32", 7)), m4Add(m4Iface("192.0.2.10/32", 8))}},
		{name: "host v6: change utun → delete + add",
			want: []KernelRoute{m4Iface("2001:db8:2::10/128", 8)},
			have: []KernelRoute{m4Iface("2001:db8:2::10/128", 7)},
			ops:  []Op{m4Del(m4Iface("2001:db8:2::10/128", 7)), m4Add(m4Iface("2001:db8:2::10/128", 8))}},
		{name: "host v6: change gateway → delete + add",
			want: []KernelRoute{m4GW("2001:db8:6::9/128", "fe80::2", 4)},
			have: []KernelRoute{m4GW("2001:db8:6::9/128", "fe80::1", 4)},
			ops:  []Op{m4Del(m4GW("2001:db8:6::9/128", "fe80::1", 4)), m4Add(m4GW("2001:db8:6::9/128", "fe80::2", 4))}},
		// The same host route is still no op.
		{name: "host: equal",
			want: []KernelRoute{m4GW("9.9.9.9/32", "192.168.20.1", 4), m4Iface("192.0.2.10/32", 7)},
			have: []KernelRoute{m4Iface("192.0.2.10/32", 7), m4GW("9.9.9.9/32", "192.168.20.1", 4)}},
		// decision 11: a host delete + add goes to the group of kind
		// changes, in prefix order with them, before the RTM_CHANGEs.
		{name: "host delete + add in the kind change group",
			want: []KernelRoute{
				m4Iface("10.0.0.0/16", 8),
				m4Iface("10.1.1.1/32", 8),
				m4Rej("10.9.0.0/16"),
				m4GW("10.10.10.10/32", "192.168.20.1", 4),
			},
			have: []KernelRoute{
				m4GW("10.10.10.10/32", "192.168.20.1", 5),
				m4Iface("10.9.0.0/16", 7),
				m4Iface("10.1.1.1/32", 7),
				m4Iface("10.0.0.0/16", 7),
			},
			ops: []Op{
				m4Del(m4Iface("10.1.1.1/32", 7)),
				m4Add(m4Iface("10.1.1.1/32", 8)),
				m4Del(m4Iface("10.9.0.0/16", 7)),
				m4Add(m4Rej("10.9.0.0/16")),
				m4Del(m4GW("10.10.10.10/32", "192.168.20.1", 5)),
				m4Add(m4GW("10.10.10.10/32", "192.168.20.1", 4)),
				m4Change(m4Iface("10.0.0.0/16", 8)),
			}},
		// decision 7: another kind is delete of the old and add of the new,
		// adjacent.
		{name: "kind change iface → gateway",
			want: []KernelRoute{m4GW("9.9.9.0/24", "192.168.20.1", 4)},
			have: []KernelRoute{m4Iface("9.9.9.0/24", 7)},
			ops:  []Op{m4Del(m4Iface("9.9.9.0/24", 7)), m4Add(m4GW("9.9.9.0/24", "192.168.20.1", 4))}},
		{name: "kind change gateway → reject",
			want: []KernelRoute{m4Rej("9.9.9.0/24")},
			have: []KernelRoute{m4GW("9.9.9.0/24", "192.168.20.1", 4)},
			ops:  []Op{m4Del(m4GW("9.9.9.0/24", "192.168.20.1", 4)), m4Add(m4Rej("9.9.9.0/24"))}},
		{name: "kind change reject → iface",
			want: []KernelRoute{m4Iface("9.9.9.0/24", 7)},
			have: []KernelRoute{m4Rej("9.9.9.0/24")},
			ops:  []Op{m4Del(m4Rej("9.9.9.0/24")), m4Add(m4Iface("9.9.9.0/24", 7))}},
		// decision 6: our endpoint host routes (via a gateway or blackhole)
		// are in keep: neither deleted nor changed.
		{name: "keep not deleted",
			want: []KernelRoute{m4Iface("10.20.0.0/16", 9)},
			have: []KernelRoute{ep4, hole4, m4Iface("10.20.0.0/16", 9), hole6},
			keep: []string{"203.0.113.1/32", "203.0.113.2/32", "2001:db8::2/128"}},
		{name: "keep alone, rest deleted",
			have: []KernelRoute{ep4, m4Iface("10.20.0.0/16", 9), hole4},
			keep: []string{"203.0.113.1/32", "203.0.113.2/32"},
			ops:  []Op{m4Del(m4Iface("10.20.0.0/16", 9))}},
		// A keep entry absent from the kernel is not added either.
		{name: "keep not in have: nothing",
			keep: []string{"203.0.113.1/32"}},
		// decision 6 and the doc of diff: a route of want whose prefix is in
		// keep is ignored — neither added nor changing the kept route.
		{name: "prefix in want and keep, kept route in have: nothing",
			want: []KernelRoute{m4Iface("203.0.113.1/32", 7), m4Iface("10.20.0.0/16", 9)},
			have: []KernelRoute{ep4, m4Iface("10.20.0.0/16", 9)},
			keep: []string{"203.0.113.1/32"}},
		{name: "prefix in want and keep, blackhole in have: nothing",
			want: []KernelRoute{m4Rej("203.0.113.2/32")},
			have: []KernelRoute{hole4},
			keep: []string{"203.0.113.2/32"}},
		{name: "prefix in want and keep, not in have: nothing",
			want: []KernelRoute{m4GW("203.0.113.1/32", "192.168.20.1", 4)},
			keep: []string{"203.0.113.1/32"}},
		// Outside keep a blackhole of ours is just another kind: blackhole →
		// reject is delete + add, a stray blackhole is deleted.
		{name: "blackhole → reject outside keep",
			want: []KernelRoute{m4Rej("192.0.2.30/32"), m4Rej("2001:db8:30::/48")},
			have: []KernelRoute{m4Hole("2001:db8:30::/48"), m4Hole("192.0.2.30/32")},
			ops: []Op{
				m4Del(m4Hole("192.0.2.30/32")),
				m4Add(m4Rej("192.0.2.30/32")),
				m4Del(m4Hole("2001:db8:30::/48")),
				m4Add(m4Rej("2001:db8:30::/48")),
			}},
		{name: "blackhole outside keep, not wanted: deleted",
			have: []KernelRoute{m4Hole("192.0.2.30/32")},
			ops:  []Op{m4Del(m4Hole("192.0.2.30/32"))}},
		// A route of ours of unknown kind (Kind 0 from owned) is never equal
		// to a wanted one: replaced by delete + add, or deleted.
		{name: "unknown kind, not wanted: deleted",
			want: []KernelRoute{m4Iface("10.20.0.0/16", 9)},
			have: []KernelRoute{m4Unknown("10.30.0.0/16"), m4Iface("10.20.0.0/16", 9)},
			ops:  []Op{m4Del(m4Unknown("10.30.0.0/16"))}},
		{name: "unknown kind, wanted: delete + add",
			want: []KernelRoute{m4Iface("10.30.0.0/16", 9), m4Rej("2001:db8:7::/48"), m4GW("9.9.9.9/32", "192.168.20.1", 4)},
			have: []KernelRoute{m4Unknown("2001:db8:7::/48"), m4Unknown("10.30.0.0/16"), m4Unknown("9.9.9.9/32")},
			ops: []Op{
				m4Del(m4Unknown("9.9.9.9/32")),
				m4Add(m4GW("9.9.9.9/32", "192.168.20.1", 4)),
				m4Del(m4Unknown("10.30.0.0/16")),
				m4Add(m4Iface("10.30.0.0/16", 9)),
				m4Del(m4Unknown("2001:db8:7::/48")),
				m4Add(m4Rej("2001:db8:7::/48")),
			}},
		{name: "unknown kind in keep: left alone",
			have: []KernelRoute{m4Unknown("203.0.113.1/32")},
			keep: []string{"203.0.113.1/32"}},
		{name: "IPv6",
			want: []KernelRoute{
				m4Iface("2001:db8:1::/48", 8),
				m4GW("2001:db8:5::/48", "fe80::1", 5),
				m4Rej("2001:db8:7::/48"),
				m4Iface("fd00:20::/48", 9),
			},
			have: []KernelRoute{
				m4Iface("2001:db8:1::/48", 7),
				m4GW("2001:db8:5::/48", "fe80::1", 4),
				m4Iface("2001:db8:7::/48", 7),
				m4GW("2001:db8:9::/48", "fe80::1", 4),
			},
			ops: []Op{
				m4Del(m4Iface("2001:db8:7::/48", 7)),
				m4Add(m4Rej("2001:db8:7::/48")),
				m4Change(m4Iface("2001:db8:1::/48", 8)),
				m4Change(m4GW("2001:db8:5::/48", "fe80::1", 5)),
				m4Add(m4Iface("fd00:20::/48", 9)),
				m4Del(m4GW("2001:db8:9::/48", "fe80::1", 4)),
			}},
		// plan "Модель" 3: kind changes, changes, adds, deletes; prefix order
		// within each group. Prefixes are chosen so that the group order
		// differs from the overall prefix order; have is not sorted.
		{name: "group order and prefix order",
			want: []KernelRoute{
				m4Iface("10.0.0.0/8", 7),
				m4Iface("10.0.0.0/16", 7),
				m4Iface("10.3.0.0/16", 8),
				m4GW("10.3.1.0/24", "192.168.20.1", 5),
				m4GW("10.4.0.0/16", "192.168.20.1", 4),
				m4Rej("10.5.0.0/16"),
				m4Iface("fd00:4::/48", 7),
			},
			have: []KernelRoute{
				m4Iface("fd00:1::/48", 7),
				m4Iface("10.5.0.0/16", 7),
				m4Iface("10.4.0.0/16", 7),
				m4GW("10.3.1.0/24", "192.168.20.1", 4),
				m4Iface("10.3.0.0/16", 7),
				m4Iface("10.2.0.0/16", 7),
				m4Iface("10.1.0.0/16", 7),
				m4Rej("fd00:4::/48"),
			},
			ops: []Op{
				m4Del(m4Iface("10.4.0.0/16", 7)),
				m4Add(m4GW("10.4.0.0/16", "192.168.20.1", 4)),
				m4Del(m4Iface("10.5.0.0/16", 7)),
				m4Add(m4Rej("10.5.0.0/16")),
				m4Del(m4Rej("fd00:4::/48")),
				m4Add(m4Iface("fd00:4::/48", 7)),
				m4Change(m4Iface("10.3.0.0/16", 8)),
				m4Change(m4GW("10.3.1.0/24", "192.168.20.1", 5)),
				m4Add(m4Iface("10.0.0.0/8", 7)),
				m4Add(m4Iface("10.0.0.0/16", 7)),
				m4Del(m4Iface("10.1.0.0/16", 7)),
				m4Del(m4Iface("10.2.0.0/16", 7)),
				m4Del(m4Iface("fd00:1::/48", 7)),
			}},
		// Replacing a /16 by /24s: the adds come before the delete, so the
		// traffic never leaves the tunnel (plan "Модель" 3).
		{name: "split a prefix: adds before delete",
			want: []KernelRoute{m4Iface("10.20.1.0/24", 9), m4Iface("10.20.2.0/24", 9)},
			have: []KernelRoute{m4Iface("10.20.0.0/16", 9)},
			ops: []Op{
				m4Add(m4Iface("10.20.1.0/24", 9)),
				m4Add(m4Iface("10.20.2.0/24", 9)),
				m4Del(m4Iface("10.20.0.0/16", 9)),
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
			m4NoPanic(t, "diff", func() { got = diff(c.want, c.have, keep) })
			equal := len(got) == len(c.ops)
			for i := 0; equal && i < len(got); i++ {
				equal = got[i].Type == c.ops[i].Type && m4Norm(got[i].Route) == m4Norm(c.ops[i].Route)
			}
			if !equal {
				t.Errorf("diff mismatch\ngot:\n%swant:\n%s", m4FmtOps(got), m4FmtOps(c.ops))
			}
		})
	}
}

// --- routeMsg ----------------------------------------------------------------

// Fact 1, 3, 5, decision 1 and the doc of routeMsg: flags, destination,
// netmask and gateway of the RTM_ADD / RTM_CHANGE message for each kind.
func TestM4RouteMsg(t *testing.T) {
	const always = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2
	cases := []struct {
		name string
		r    KernelRoute
	}{
		{"iface net v4", m4Iface("10.20.0.0/16", 9)},
		{"iface host v4", m4Iface("192.0.2.10/32", 7)},
		{"iface net v6", m4Iface("fd00:20::/48", 9)},
		{"iface host v6", m4Iface("2001:db8:2::10/128", 7)},
		{"gateway net v4", m4GW("9.9.0.0/16", "192.168.20.1", 4)},
		{"gateway host v4", m4GW("9.9.9.9/32", "192.168.20.1", 4)},
		{"gateway net v6", m4GW("2001:db8:5::/48", "2001:db8:ffff::1", 5)},
		{"gateway host v6 link-local", m4GW("2001:db8:6::9/128", "fe80::1", 4)},
		{"reject net v4", m4Rej("198.51.100.0/24")},
		{"reject host v4", m4Rej("192.0.2.20/32")},
		{"reject net v6", m4Rej("2001:db8:7::/48")},
		{"reject host v6", m4Rej("2001:db8:dead::1/128")},
	}
	for _, c := range cases {
		for _, typ := range []int{unix.RTM_ADD, unix.RTM_CHANGE} {
			name := c.name + " add"
			if typ == unix.RTM_CHANGE {
				name = c.name + " change"
			}
			t.Run(name, func(t *testing.T) {
				var m *route.RouteMessage
				m4NoPanic(t, "routeMsg", func() { m = routeMsg(typ, c.r, 42) })
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
					// Fact 3: the gateway is lo0's address, without RTF_GATEWAY;
					// decision 1: reject, not blackhole.
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
				// otherwise (fact 5: RTM_CHANGE always carries it).
				hasMask := len(got.Addrs) > unix.RTAX_NETMASK && got.Addrs[unix.RTAX_NETMASK] != nil
				switch {
				case host && hasMask:
					t.Errorf("host route carries RTAX_NETMASK %v", got.Addrs[unix.RTAX_NETMASK])
				case !host && !hasMask:
					t.Errorf("network route has no RTAX_NETMASK")
				case !host:
					if mask, ok := addrAt(got, unix.RTAX_NETMASK); !ok || mask != m4Mask(c.r.Prefix) {
						t.Errorf("RTAX_NETMASK = %v (%T), want %v", mask, got.Addrs[unix.RTAX_NETMASK], m4Mask(c.r.Prefix))
					}
				}

				// RTAX_GATEWAY by kind.
				if len(got.Addrs) <= unix.RTAX_GATEWAY || got.Addrs[unix.RTAX_GATEWAY] == nil {
					t.Fatalf("no RTAX_GATEWAY")
				}
				gwAddr := got.Addrs[unix.RTAX_GATEWAY]
				switch c.r.Kind {
				case KindIface:
					// Fact 1: sockaddr_dl with the utun's index.
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
					// Fact 3: to lo0 — the loopback address of the family.
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

// m4KAddr is a as a route address, without any scope.
func m4KAddr(a netip.Addr) route.Addr {
	if a.Is4() {
		return &route.Inet4Addr{IP: a.As4()}
	}
	return &route.Inet6Addr{IP: a.As16()}
}

// m4KEntry builds a dump entry (RTM_GET, as sysctl NET_RT_DUMP gives it) by
// hand, not with routeMsg: RTF_HOST and no netmask for a single IP, the
// prefix mask otherwise; flags are given in full.
func m4KEntry(p string, flags, index int, gw route.Addr) *route.RouteMessage {
	pfx := tP(p)
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = m4KAddr(pfx.Addr())
	addrs[unix.RTAX_GATEWAY] = gw
	if pfx.IsSingleIP() {
		flags |= unix.RTF_HOST
	} else {
		addrs[unix.RTAX_NETMASK] = m4KAddr(m4Mask(pfx))
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

// Flags of our routes as the kernel holds them: fact 1 (RTF_PRCLONING set by
// the kernel on a route to an interface), fact 3 (reject to lo0).
const (
	m4KIface   = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PRCLONING | unix.RTF_PROTO2
	m4KGateway = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_PROTO2
	m4KReject  = unix.RTF_UP | unix.RTF_STATIC | unix.RTF_REJECT | unix.RTF_PROTO2
	m4Lo0      = 1
)

// m4KLink is the gateway of a route to a utun in a dump: sockaddr_dl with
// the index and the name.
func m4KLink(index int, name string) route.Addr {
	return &route.LinkAddr{Index: index, Name: name}
}

// m4KScoped is a link-local IPv6 gateway with the scope embedded KAME style
// (bytes 2–3), as the kernel reports it, sin6_scope_id left 0.
func m4KScoped(a string, index int) route.Addr {
	ip := tA(a).As16()
	ip[2], ip[3] = byte(index>>8), byte(index)
	return &route.Inet6Addr{IP: ip}
}

// design 6.2 "only the difference", plan "Модель", decisions 1, 6, 10, 11 and
// the ruling of step 3: a table applied once and read back from a dump as the
// kernel reports it gives no ops on the next Sync. The dump entries are made
// by hand with what the kernel adds (RTF_PRCLONING, LinkAddr with a name,
// rtm_index of the interface, lo0 for reject, scope embedded in a link-local
// gateway), not with routeMsg.
func TestM4IdempotentKernelDump(t *testing.T) {
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
		tCIDRVia("198.18.0.0/15", "de", 0), // decision 10: no utun → reject
		tRuleRoute("198.51.100.0/24", SourceRuleCIDR, TargetReject, "", 2),
		tEndpoint("203.0.113.1/32"),
		tRuleRoute("2001:db8:5::/48", SourceRuleCIDR, TargetDirect, "", 1),
		tRuleRoute("2001:db8:6::9/128", SourceDynamic, TargetDirect, "", 1),
		tRuleRoute("2001:db8:7::/48", SourceRuleCIDR, TargetReject, "", 2),
		tAllowed("fd00:20::/48", "work"),
	}
	dump := []*route.RouteMessage{
		m4KEntry("9.9.9.0/24", m4KIface, utun5, m4KLink(utun5, "utun5")),
		m4KEntry("9.9.9.9/32", m4KGateway, en0, m4KAddr(tA("192.168.20.1"))),
		m4KEntry("10.20.0.0/16", m4KIface, utun6, m4KLink(utun6, "utun6")),
		m4KEntry("192.0.2.10/32", m4KIface, utun5, m4KLink(utun5, "utun5")),
		m4KEntry("192.0.2.20/32", m4KReject, m4Lo0, m4KAddr(tA("127.0.0.1"))),
		m4KEntry("198.18.0.0/15", m4KReject, m4Lo0, m4KAddr(tA("127.0.0.1"))),
		m4KEntry("198.51.100.0/24", m4KReject, m4Lo0, m4KAddr(tA("127.0.0.1"))),
		// The endpoint host route of M3 (keep).
		m4KEntry("203.0.113.1/32", m4KGateway, en0, m4KAddr(tA("192.168.20.1"))),
		m4KEntry("2001:db8:5::/48", m4KGateway, en0, m4KScoped("fe80::1", en0)),
		m4KEntry("2001:db8:6::9/128", m4KGateway, en0, m4KScoped("fe80::1", en0)),
		m4KEntry("2001:db8:7::/48", m4KReject, m4Lo0, m4KAddr(tA("::1"))),
		m4KEntry("fd00:20::/48", m4KIface, utun6, m4KLink(utun6, "utun6")),
		// A clone of 9.9.9.0/24 inherits RTF_PROTO2 (fact 4): not ours to
		// manage, no op.
		m4KEntry("9.9.9.10/32", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, utun5, m4KLink(utun5, "utun5")),
		// A foreign route.
		m4KEntry("192.168.20.0/24", unix.RTF_UP|unix.RTF_CLONING|unix.RTF_STATIC, en0, m4KLink(en0, "en0")),
	}

	var (
		want []KernelRoute
		keep map[netip.Prefix]bool
	)
	m4NoPanic(t, "wanted", func() { want, keep, _ = wanted(tbl, env) })
	msgs := m4Dump(t, dump...)
	var have []KernelRoute
	m4NoPanic(t, "owned", func() { have = owned(msgs) })
	var ops []Op
	m4NoPanic(t, "diff", func() { ops = diff(want, have, keep) })
	if len(ops) != 0 {
		t.Errorf("second Sync is not empty\nops:\n%swant:\n%shave:\n%s", m4FmtOps(ops), m4FmtRoutes(want), m4FmtRoutes(have))
	}
}

// --- owned: rtm_index, clones, unknown kind ----------------------------------

// Ruling of step 3: the interface of a route to a utun is rtm_index of the
// dump entry (RTM_CHANGE may change the interface apart from the gateway);
// LinkAddr.Index only when rtm_index is 0. Clones (RTF_WASCLONED) are left
// out. An entry of ours of a kind owned cannot tell is kept with Kind 0, so
// that diff replaces or deletes it.
func TestM4OwnedKernelEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry *route.RouteMessage
		want  []KernelRoute
	}{
		{name: "iface: rtm_index differs from LinkAddr.Index → rtm_index",
			entry: m4KEntry("10.20.0.0/16", m4KIface, 9, m4KLink(7, "utun3")),
			want:  []KernelRoute{m4Iface("10.20.0.0/16", 9)}},
		{name: "iface host: rtm_index differs from LinkAddr.Index → rtm_index",
			entry: m4KEntry("192.0.2.10/32", m4KIface, 9, m4KLink(7, "utun3")),
			want:  []KernelRoute{m4Iface("192.0.2.10/32", 9)}},
		{name: "iface: rtm_index 0 → LinkAddr.Index",
			entry: m4KEntry("10.20.0.0/16", m4KIface, 0, m4KLink(7, "utun3")),
			want:  []KernelRoute{m4Iface("10.20.0.0/16", 7)}},
		{name: "iface v6: rtm_index 0 → LinkAddr.Index",
			entry: m4KEntry("fd00:20::/48", m4KIface, 0, m4KLink(7, "")),
			want:  []KernelRoute{m4Iface("fd00:20::/48", 7)}},
		{name: "clone of an iface route left out",
			entry: m4KEntry("10.20.0.5/32", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, 7, m4KLink(7, "utun3"))},
		{name: "clone of a gateway route left out",
			entry: m4KEntry("9.9.1.1/32", unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_PROTO2|unix.RTF_WASCLONED, 4, m4KAddr(tA("192.168.20.1")))},
		{name: "clone v6 left out",
			entry: m4KEntry("fd00:20::5/128", unix.RTF_UP|unix.RTF_PROTO2|unix.RTF_WASCLONED, 7, m4KLink(7, "utun3"))},
		// A link gateway with RTF_GATEWAY is neither a route to an interface
		// (no RTF_GATEWAY) nor via a gateway address.
		{name: "unknown: link gateway with RTF_GATEWAY → Kind 0",
			entry: m4KEntry("10.30.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY|unix.RTF_PROTO2, 7, m4KLink(7, "utun3")),
			want:  []KernelRoute{m4Unknown("10.30.0.0/16")}},
		// An address gateway without RTF_GATEWAY, RTF_REJECT or
		// RTF_BLACKHOLE.
		{name: "unknown: address gateway without kind flags → Kind 0",
			entry: m4KEntry("10.31.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_PROTO2, 4, m4KAddr(tA("192.168.20.1"))),
			want:  []KernelRoute{m4Unknown("10.31.0.0/16")}},
		{name: "unknown host v6 → Kind 0",
			entry: m4KEntry("2001:db8:31::1/128", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_PROTO2, 4, m4KAddr(tA("2001:db8:ffff::1"))),
			want:  []KernelRoute{m4Unknown("2001:db8:31::1/128")}},
		// The same shapes without RTF_PROTO2 are foreign: left out.
		{name: "foreign of unknown shape left out",
			entry: m4KEntry("10.30.0.0/16", unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY, 7, m4KLink(7, "utun3"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := m4Dump(t, c.entry)
			var got []KernelRoute
			m4NoPanic(t, "owned", func() { got = owned(msgs) })
			m4SameRoutes(t, "owned", got, c.want)
		})
	}
}

// --- routeMsg: rtm_index -----------------------------------------------------

// Ruling of step 3 and the doc of routeMsg: rtm_index is r.Index for routes
// to an interface and via a gateway, 0 for reject.
func TestM4RouteMsgIndex(t *testing.T) {
	cases := []struct {
		r     KernelRoute
		index int
	}{
		{m4Iface("10.20.0.0/16", 9), 9},
		{m4Iface("192.0.2.10/32", 7), 7},
		{m4Iface("fd00:20::/48", 9), 9},
		{m4GW("9.9.0.0/16", "192.168.20.1", 4), 4},
		{m4GW("9.9.9.9/32", "192.168.20.1", 5), 5},
		{m4GW("2001:db8:5::/48", "fe80::1", 4), 4},
		{m4Rej("198.51.100.0/24"), 0},
		{m4Rej("2001:db8:7::/48"), 0},
	}
	for _, c := range cases {
		for _, typ := range []int{unix.RTM_ADD, unix.RTM_CHANGE} {
			t.Run(fmt.Sprintf("%s type %d", m4Fmt(c.r), typ), func(t *testing.T) {
				var m *route.RouteMessage
				m4NoPanic(t, "routeMsg", func() { m = routeMsg(typ, c.r, 1) })
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

// --- M5: scoped host routes to the DNS servers of tunnels --------------------

// m5Scoped is a scoped host route of ours to a DNS server of a tunnel
// (AddScoped, M5 plan "Модель"): RTF_HOST|RTF_IFSCOPE|RTF_PROTO2, gateway
// LinkAddr{Index} and rtm_index of the utun, as a dump gives it.
func m5Scoped(dst string, index int, name string) *route.RouteMessage {
	a := tA(dst)
	return m4KEntry(netip.PrefixFrom(a, a.BitLen()).String(),
		unix.RTF_UP|unix.RTF_STATIC|unix.RTF_IFSCOPE|unix.RTF_PROTO2, index, m4KLink(index, name))
}

// design 6.2 (scoped routes are left alone by sync), 7, M5 fact 4, decision 3:
// owned skips entries with RTF_IFSCOPE, so Sync does not see our scoped host
// routes; the unscoped routes of ours in the same dump are still read.
func TestM5OwnedSkipsScoped(t *testing.T) {
	const utun5, utun6 = 15, 16
	cases := []struct {
		name string
		dump []*route.RouteMessage
		want []KernelRoute
	}{
		{name: "scoped v4 only",
			dump: []*route.RouteMessage{m5Scoped("1.0.0.1", utun5, "utun5")}},
		{name: "scoped v6 only",
			dump: []*route.RouteMessage{m5Scoped("2606:4700:4700::1001", utun5, "utun5")}},
		{name: "one DNS server scoped on two utuns",
			dump: []*route.RouteMessage{m5Scoped("1.0.0.1", utun5, "utun5"), m5Scoped("1.0.0.1", utun6, "utun6")}},
		{name: "scoped and an unscoped route of ours to the same address",
			dump: []*route.RouteMessage{
				m5Scoped("1.0.0.1", utun5, "utun5"),
				m4KEntry("1.0.0.1/32", m4KIface, utun6, m4KLink(utun6, "utun6")),
			},
			want: []KernelRoute{m4Iface("1.0.0.1/32", utun6)}},
		{name: "scoped among routes of every kind",
			dump: []*route.RouteMessage{
				m4KEntry("9.9.9.0/24", m4KIface, utun5, m4KLink(utun5, "utun5")),
				m5Scoped("10.199.17.1", utun6, "utun6"),
				m4KEntry("198.51.100.0/24", m4KReject, m4Lo0, m4KAddr(tA("127.0.0.1"))),
				m5Scoped("1.0.0.1", utun5, "utun5"),
				m4KEntry("9.9.9.9/32", m4KGateway, 4, m4KAddr(tA("192.168.20.1"))),
			},
			want: []KernelRoute{
				m4Iface("9.9.9.0/24", utun5),
				m4Rej("198.51.100.0/24"),
				m4GW("9.9.9.9/32", "192.168.20.1", 4),
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := m4Dump(t, c.dump...)
			var got []KernelRoute
			m4NoPanic(t, "owned", func() { got = owned(msgs) })
			m4SameRoutes(t, "owned", got, c.want)
		})
	}

	// The same entry built with routeMsg plus RTF_IFSCOPE.
	t.Run("routeMsg entry with RTF_IFSCOPE", func(t *testing.T) {
		var msgs []route.Message
		m4NoPanic(t, "routeMsg", func() {
			m := m4Entry(m4Iface("1.0.0.1/32", utun5))
			m.Flags |= unix.RTF_IFSCOPE
			msgs = m4Dump(t, m)
		})
		if msgs == nil {
			return
		}
		var got []KernelRoute
		m4NoPanic(t, "owned", func() { got = owned(msgs) })
		m4SameRoutes(t, "owned", got, nil)
	})
}

// design 6.2, 7, M5 facts 3, 4: a dump with our scoped host routes gives no
// op that deletes or changes them; a dynamic /32 to the same address
// (another tunnel, the same utun or direct) is an unscoped route of its own
// and is added.
func TestM5DiffKeepsScoped(t *testing.T) {
	const utun5, utun6 = 15, 16
	cases := []struct {
		name string
		want []KernelRoute
		dump []*route.RouteMessage
		ops  []Op
	}{
		{name: "nothing wanted: scoped routes stay",
			dump: []*route.RouteMessage{
				m5Scoped("1.0.0.1", utun5, "utun5"),
				m5Scoped("2606:4700:4700::1001", utun5, "utun5"),
			}},
		{name: "dynamic /32 to the DNS server via another tunnel: add only",
			want: []KernelRoute{m4Iface("1.0.0.1/32", utun6)},
			dump: []*route.RouteMessage{m5Scoped("1.0.0.1", utun5, "utun5")},
			ops:  []Op{m4Add(m4Iface("1.0.0.1/32", utun6))}},
		{name: "dynamic /32 to the DNS server via the same utun: add only",
			want: []KernelRoute{m4Iface("1.0.0.1/32", utun5)},
			dump: []*route.RouteMessage{m5Scoped("1.0.0.1", utun5, "utun5")},
			ops:  []Op{m4Add(m4Iface("1.0.0.1/32", utun5))}},
		{name: "direct /32 to the DNS server: add only",
			want: []KernelRoute{m4GW("1.0.0.1/32", "192.168.20.1", 4)},
			dump: []*route.RouteMessage{m5Scoped("1.0.0.1", utun5, "utun5")},
			ops:  []Op{m4Add(m4GW("1.0.0.1/32", "192.168.20.1", 4))}},
		{name: "unscoped already in place: no ops",
			want: []KernelRoute{m4Iface("1.0.0.1/32", utun6)},
			dump: []*route.RouteMessage{
				m5Scoped("1.0.0.1", utun5, "utun5"),
				m4KEntry("1.0.0.1/32", m4KIface, utun6, m4KLink(utun6, "utun6")),
			}},
		{name: "unscoped of ours no longer wanted: deleted, scoped stays",
			dump: []*route.RouteMessage{
				m5Scoped("1.0.0.1", utun5, "utun5"),
				m4KEntry("1.0.0.1/32", m4KIface, utun6, m4KLink(utun6, "utun6")),
			},
			ops: []Op{m4Del(m4Iface("1.0.0.1/32", utun6))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msgs := m4Dump(t, c.dump...)
			var have []KernelRoute
			m4NoPanic(t, "owned", func() { have = owned(msgs) })
			var ops []Op
			m4NoPanic(t, "diff", func() { ops = diff(c.want, have, nil) })
			same := len(ops) == len(c.ops)
			for i := 0; same && i < len(ops); i++ {
				same = ops[i].Type == c.ops[i].Type && m4Norm(ops[i].Route) == m4Norm(c.ops[i].Route)
			}
			if !same {
				t.Errorf("ops:\n%swant:\n%s", m4FmtOps(ops), m4FmtOps(c.ops))
			}
		})
	}
}
