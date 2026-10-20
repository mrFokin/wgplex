package router

import (
	"net/netip"
	"os"
	"reflect"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Tests follow design 5 (host route to every endpoint via the physical
// gateway, blackhole without one, RTF_PROTO2 marks our routes) and the
// doc comments of hostRouteMsg and gatewayFrom from the M3 plan.

// roundTrip marshals m and parses it back the way a routing socket reader would.
func roundTrip(t *testing.T, m *route.RouteMessage) *route.RouteMessage {
	t.Helper()
	b, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		t.Fatalf("ParseRIB: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("ParseRIB returned %d messages, want 1 (is Version RTM_VERSION?)", len(msgs))
	}
	rm, ok := msgs[0].(*route.RouteMessage)
	if !ok {
		t.Fatalf("ParseRIB returned %T, want *route.RouteMessage", msgs[0])
	}
	return rm
}

// addrAt returns m.Addrs[i] as netip.Addr (zone dropped) or false.
func addrAt(m *route.RouteMessage, i int) (netip.Addr, bool) {
	if i >= len(m.Addrs) || m.Addrs[i] == nil {
		return netip.Addr{}, false
	}
	switch a := m.Addrs[i].(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP), true
	}
	return netip.Addr{}, false
}

func TestHostRouteMsg(t *testing.T) {
	const always = unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO2
	tests := []struct {
		name    string
		typ     int
		dst     string
		gw      Gateway
		flags   int // must be set
		noflags int // must be clear
		wantGW  string
	}{
		{
			name: "add IPv4 via gateway", typ: unix.RTM_ADD, dst: "203.0.113.5",
			gw:    Gateway{Addr: tA("192.168.1.1"), Index: 4},
			flags: always | unix.RTF_GATEWAY, noflags: unix.RTF_BLACKHOLE, wantGW: "192.168.1.1",
		},
		{
			name: "add IPv4 blackhole without gateway", typ: unix.RTM_ADD, dst: "203.0.113.5",
			gw:    Gateway{},
			flags: always | unix.RTF_BLACKHOLE, noflags: unix.RTF_GATEWAY,
		},
		{
			name: "add IPv6 via global gateway", typ: unix.RTM_ADD, dst: "2001:db8::5",
			gw:    Gateway{Addr: tA("2001:db8::1"), Index: 6},
			flags: always | unix.RTF_GATEWAY, noflags: unix.RTF_BLACKHOLE, wantGW: "2001:db8::1",
		},
		{
			name: "add IPv6 via link-local gateway", typ: unix.RTM_ADD, dst: "2001:db8::5",
			gw:    Gateway{Addr: tA("fe80::1"), Index: 6},
			flags: always | unix.RTF_GATEWAY, noflags: unix.RTF_BLACKHOLE, wantGW: "fe80::1",
		},
		{
			name: "add IPv6 blackhole without gateway", typ: unix.RTM_ADD, dst: "2001:db8::5",
			gw:    Gateway{},
			flags: always | unix.RTF_BLACKHOLE, noflags: unix.RTF_GATEWAY,
		},
		{
			name: "delete IPv4 via gateway", typ: unix.RTM_DELETE, dst: "198.51.100.9",
			gw:    Gateway{Addr: tA("10.0.1.1"), Index: 5},
			flags: always | unix.RTF_GATEWAY, noflags: unix.RTF_BLACKHOLE, wantGW: "10.0.1.1",
		},
		{
			name: "delete IPv4 blackhole", typ: unix.RTM_DELETE, dst: "198.51.100.9",
			gw:    Gateway{},
			flags: always | unix.RTF_BLACKHOLE, noflags: unix.RTF_GATEWAY,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const seq = 42
			m := hostRouteMsg(tt.typ, tA(tt.dst), tt.gw, seq)
			if m == nil {
				t.Fatal("hostRouteMsg returned nil")
			}
			got := roundTrip(t, m)
			if got.Version != unix.RTM_VERSION {
				t.Errorf("Version = %d, want %d", got.Version, unix.RTM_VERSION)
			}
			if got.Type != tt.typ {
				t.Errorf("Type = %d, want %d", got.Type, tt.typ)
			}
			if got.Seq != seq {
				t.Errorf("Seq = %d, want %d", got.Seq, seq)
			}
			if got.Flags&tt.flags != tt.flags {
				t.Errorf("Flags = %#x, missing %#x", got.Flags, tt.flags&^got.Flags)
			}
			if got.Flags&tt.noflags != 0 {
				t.Errorf("Flags = %#x, must not have %#x", got.Flags, tt.noflags)
			}
			dst, ok := addrAt(got, unix.RTAX_DST)
			if !ok || dst != tA(tt.dst) {
				t.Errorf("RTAX_DST = %v (present %v), want %s", dst, ok, tt.dst)
			}
			if tt.wantGW != "" {
				gw, ok := addrAt(got, unix.RTAX_GATEWAY)
				if !ok || gw != tA(tt.wantGW) {
					t.Errorf("RTAX_GATEWAY = %v (present %v), want %s", gw, ok, tt.wantGW)
				}
			}
		})
	}
}

// The gateway's address family follows dst's; IPv4 dst never gets an
// IPv6-shaped message and vice versa. Without a gateway the message still
// carries RTAX_GATEWAY: the loopback address of dst's family (doc of
// hostRouteMsg; go-dev decision 1 of M3 step 2).
func TestHostRouteMsgFamily(t *testing.T) {
	tests := []struct {
		name   string
		dst    string
		gw     Gateway
		wantGW string
	}{
		{"IPv4 blackhole", "203.0.113.5", Gateway{}, "127.0.0.1"},
		{"IPv6 blackhole", "2001:db8::5", Gateway{}, "::1"},
		{"IPv4 via gateway", "203.0.113.5", Gateway{Addr: tA("192.168.1.1"), Index: 4}, "192.168.1.1"},
		{"IPv6 via global gateway", "2001:db8::5", Gateway{Addr: tA("2001:db8::1"), Index: 6}, "2001:db8::1"},
		{"IPv6 via link-local gateway", "2001:db8::5", Gateway{Addr: tA("fe80::1"), Index: 6}, "fe80::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := unix.AF_INET
			if tA(tt.dst).Is6() {
				want = unix.AF_INET6
			}
			for _, typ := range []int{unix.RTM_ADD, unix.RTM_DELETE} {
				m := roundTrip(t, hostRouteMsg(typ, tA(tt.dst), tt.gw, 1))
				for _, i := range []int{unix.RTAX_DST, unix.RTAX_GATEWAY} {
					if len(m.Addrs) <= i || m.Addrs[i] == nil {
						t.Errorf("type %d: no address at index %d", typ, i)
						continue
					}
					if f := m.Addrs[i].Family(); f != want {
						t.Errorf("type %d: address %d family %d, want %d", typ, i, f, want)
					}
				}
				if gw, ok := addrAt(m, unix.RTAX_GATEWAY); !ok || gw != tA(tt.wantGW) {
					t.Errorf("type %d: RTAX_GATEWAY = %v (present %v), want %s", typ, gw, ok, tt.wantGW)
				}
			}
		})
	}
}

// A link-local IPv6 gateway is scoped to its interface: after a round trip
// through the routing socket format the gateway's zone is gw.Index, and the
// message is bound to that interface (doc of hostRouteMsg; go-dev decision 2
// of M3 step 2).
func TestHostRouteMsgLinkLocalScope(t *testing.T) {
	gw := Gateway{Addr: tA("fe80::1"), Index: 6}
	for _, typ := range []int{unix.RTM_ADD, unix.RTM_DELETE} {
		m := hostRouteMsg(typ, tA("2001:db8::5"), gw, 3)
		if m.Index != gw.Index {
			t.Errorf("type %d: Index = %d, want %d", typ, m.Index, gw.Index)
		}
		got := roundTrip(t, m)
		if got.Index != gw.Index {
			t.Errorf("type %d: Index after round trip = %d, want %d", typ, got.Index, gw.Index)
		}
		if len(got.Addrs) <= unix.RTAX_GATEWAY {
			t.Fatalf("type %d: no RTAX_GATEWAY", typ)
		}
		a, ok := got.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
		if !ok {
			t.Fatalf("type %d: RTAX_GATEWAY is %T, want *route.Inet6Addr", typ, got.Addrs[unix.RTAX_GATEWAY])
		}
		if a.ZoneID != gw.Index {
			t.Errorf("type %d: gateway ZoneID = %d, want %d", typ, a.ZoneID, gw.Index)
		}
		if ip := netip.AddrFrom16(a.IP); ip != tA("fe80::1") {
			t.Errorf("type %d: gateway = %v, want fe80::1", typ, ip)
		}
	}
}

// getReply builds an RTM_GET reply for the default route.
func getReply(index int, gw route.Addr, ipv6 bool) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_GATEWAY+1)
	if ipv6 {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{}
	}
	addrs[unix.RTAX_GATEWAY] = gw
	flags := unix.RTF_UP | unix.RTF_STATIC
	if _, ok := gw.(*route.LinkAddr); !ok && gw != nil {
		flags |= unix.RTF_GATEWAY
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

func TestGatewayFrom(t *testing.T) {
	tests := []struct {
		name   string
		m      *route.RouteMessage
		ifname string
		want   Gateway
	}{
		{
			name:   "IPv4 gateway on en0",
			m:      getReply(4, &route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}, false),
			ifname: "en0",
			want:   Gateway{Addr: tA("192.168.1.1"), Index: 4},
		},
		{
			name:   "IPv6 global gateway on en0",
			m:      getReply(4, &route.Inet6Addr{IP: tA("2001:db8::1").As16()}, true),
			ifname: "en0",
			want:   Gateway{Addr: tA("2001:db8::1"), Index: 4},
		},
		{
			name:   "IPv4 gateway on a utun: another VPN, no physical gateway",
			m:      getReply(17, &route.Inet4Addr{IP: [4]byte{10, 8, 0, 1}}, false),
			ifname: "utun3",
			want:   Gateway{},
		},
		{
			name:   "IPv6 gateway on a utun",
			m:      getReply(17, &route.Inet6Addr{IP: tA("fd00::1").As16()}, true),
			ifname: "utun5",
			want:   Gateway{},
		},
		{
			name:   "link gateway (interface route, e.g. PPP)",
			m:      getReply(9, &route.LinkAddr{Index: 9, Name: "ppp0"}, false),
			ifname: "ppp0",
			want:   Gateway{},
		},
		{
			name:   "link gateway on en0",
			m:      getReply(4, &route.LinkAddr{Index: 4}, false),
			ifname: "en0",
			want:   Gateway{},
		},
		{
			name:   "IPv4 loopback gateway (blackhole default)",
			m:      getReply(1, &route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}, false),
			ifname: "lo0",
			want:   Gateway{},
		},
		{
			name:   "IPv6 loopback gateway (blackhole default)",
			m:      getReply(1, &route.Inet6Addr{IP: tA("::1").As16()}, true),
			ifname: "lo0",
			want:   Gateway{},
		},
		{
			name:   "IPv4 loopback gateway address on en0",
			m:      getReply(4, &route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}, false),
			ifname: "en0",
			want:   Gateway{},
		},
		{
			name:   "IPv6 loopback gateway address on en0",
			m:      getReply(4, &route.Inet6Addr{IP: tA("::1").As16()}, true),
			ifname: "en0",
			want:   Gateway{},
		},
		{
			name:   "IPv4 unspecified gateway",
			m:      getReply(4, &route.Inet4Addr{}, false),
			ifname: "en0",
			want:   Gateway{},
		},
		{
			name:   "IPv6 unspecified gateway",
			m:      getReply(4, &route.Inet6Addr{}, true),
			ifname: "en0",
			want:   Gateway{},
		},
		{
			name:   "no gateway address",
			m:      getReply(4, nil, false),
			ifname: "en0",
			want:   Gateway{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gatewayFrom(tt.m, tt.ifname); got != tt.want {
				t.Errorf("gatewayFrom = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A link-local IPv6 gateway is only usable with its interface: Index must be
// set; the zone in Addr is not prescribed by the plan, so it is ignored here.
func TestGatewayFromLinkLocal(t *testing.T) {
	m := getReply(4, &route.Inet6Addr{IP: tA("fe80::1").As16(), ZoneID: 4}, true)
	got := gatewayFrom(m, "en0")
	if got.Addr.WithZone("") != tA("fe80::1") || got.Index != 4 {
		t.Errorf("gatewayFrom = %+v, want fe80::1 on index 4", got)
	}
}

// A gateway learned from an RTM_GET reply builds a host route that keeps it.
func TestGatewayFromToHostRoute(t *testing.T) {
	reply := roundTrip(t, getReply(4, &route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}, false))
	gw := gatewayFrom(reply, "en0")
	m := roundTrip(t, hostRouteMsg(unix.RTM_ADD, tA("203.0.113.5"), gw, 2))
	if got, ok := addrAt(m, unix.RTAX_GATEWAY); !ok || got != tA("192.168.1.1") {
		t.Errorf("RTAX_GATEWAY = %v, want 192.168.1.1", got)
	}
}

// Tests below follow design 5 and decisions 10–11 of the M3 plan: a foreign
// host route to the endpoint is an error, an on-link endpoint gets no route,
// only routes marked RTF_PROTO2 are ours (doc of classifyHost).

// tkV4 and tkV6 build route addresses; tkLink builds a link-layer gateway
// (ARP/ND entries and direct routes carry one).
func tkV4(s string) *route.Inet4Addr { return &route.Inet4Addr{IP: tA(s).As4()} }

func tkV6(s string, zone int) *route.Inet6Addr {
	return &route.Inet6Addr{IP: tA(s).As16(), ZoneID: zone}
}

func tkLink(index int, name string) *route.LinkAddr {
	return &route.LinkAddr{Index: index, Name: name}
}

// tkGet builds an RTM_GET reply with the given flags (RTF_UP is always set),
// destination, gateway and netmask (nil: absent).
func tkGet(flags int, dst, gw, mask route.Addr) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_GATEWAY] = gw
	addrs[unix.RTAX_NETMASK] = mask
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP | flags,
		Index:   4,
		Seq:     1,
		Addrs:   addrs,
	}
}

func tkStateName(s hostState) string {
	switch s {
	case hostNone:
		return "hostNone"
	case hostOwned:
		return "hostOwned"
	case hostForeign:
		return "hostForeign"
	case hostOnLink:
		return "hostOnLink"
	}
	return "hostState(?)"
}

func TestClassifyHost(t *testing.T) {
	const (
		host    = unix.RTF_HOST
		gwf     = unix.RTF_GATEWAY
		static  = unix.RTF_STATIC
		proto2  = unix.RTF_PROTO2
		cloned  = unix.RTF_WASCLONED
		llinfo  = unix.RTF_LLINFO
		bh      = unix.RTF_BLACKHOLE
		reject  = unix.RTF_REJECT
		cloning = unix.RTF_CLONING
	)
	mask24 := tkV4("255.255.255.0")
	mask0 := tkV4("0.0.0.0")
	mask64 := tkV6("ffff:ffff:ffff:ffff::", 0)
	mask1v4 := tkV4("128.0.0.0")
	mask1v6 := tkV6("8000::", 0)
	tests := []struct {
		name   string
		m      *route.RouteMessage
		dst    string
		ifname string
		want   hostState
	}{
		// design 5: no route at all.
		{"nil: no route", nil, "203.0.113.5", "", hostNone},
		{"nil with physical ifname", nil, "203.0.113.5", "en0", hostNone},

		// design 5 / decision 10: our host route (RTF_PROTO2) is replaced.
		{
			"own IPv4 host route via gateway",
			tkGet(host|gwf|static|proto2, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostOwned,
		},
		{
			"own IPv6 host route via gateway",
			tkGet(host|gwf|static|proto2, tkV6("2001:db8::5", 0), tkV6("fe80::1", 4), nil),
			"2001:db8::5", "en0", hostOwned,
		},
		{
			"own IPv4 blackhole host route",
			tkGet(host|bh|static|proto2, tkV4("203.0.113.5"), tkV4("127.0.0.1"), nil),
			"203.0.113.5", "lo0", hostOwned,
		},
		{
			"own IPv6 blackhole host route",
			tkGet(host|bh|static|proto2, tkV6("2001:db8::5", 0), tkV6("::1", 0), nil),
			"2001:db8::5", "lo0", hostOwned,
		},

		// design 5 / decision 10: a foreign host route to dst is an error.
		{
			"foreign static IPv4 host route via gateway",
			tkGet(host|gwf|static, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostForeign,
		},
		{
			"foreign static IPv6 host route via gateway",
			tkGet(host|gwf|static, tkV6("2001:db8::5", 0), tkV6("fe80::1", 4), nil),
			"2001:db8::5", "en0", hostForeign,
		},
		{
			"foreign static host route via interface en0",
			tkGet(host|static, tkV4("203.0.113.5"), tkLink(4, "en0"), nil),
			"203.0.113.5", "en0", hostForeign,
		},
		{
			"foreign host route into another VPN's utun",
			tkGet(host|static, tkV4("203.0.113.5"), tkLink(17, "utun3"), nil),
			"203.0.113.5", "utun3", hostForeign,
		},
		{
			"foreign host route via gateway on utun",
			tkGet(host|gwf|static, tkV4("203.0.113.5"), tkV4("10.8.0.1"), nil),
			"203.0.113.5", "utun3", hostForeign,
		},
		{
			"foreign host route without RTF_STATIC",
			tkGet(host|gwf, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostForeign,
		},
		{
			"foreign blackhole host route without PROTO2",
			tkGet(host|bh|static, tkV4("203.0.113.5"), tkV4("127.0.0.1"), nil),
			"203.0.113.5", "lo0", hostForeign,
		},

		// decision 11: an ARP/ND entry of dst is not foreign, dst is on-link.
		{
			"ARP entry (LLINFO|WASCLONED) on en0",
			tkGet(host|llinfo|cloned, tkV4("192.168.1.20"), tkLink(4, "en0"), nil),
			"192.168.1.20", "en0", hostOnLink,
		},
		{
			"static ARP entry (arp -s: LLINFO|STATIC) on en0",
			tkGet(host|llinfo|static, tkV4("192.168.1.20"), tkLink(4, "en0"), nil),
			"192.168.1.20", "en0", hostOnLink,
		},
		{
			"ND entry (LLINFO|WASCLONED) on en0",
			tkGet(host|llinfo|cloned, tkV6("2001:db8:1::20", 0), tkLink(4, "en0"), nil),
			"2001:db8:1::20", "en0", hostOnLink,
		},
		{
			"static ND entry (LLINFO|STATIC) on en0",
			tkGet(host|llinfo|static, tkV6("2001:db8:1::20", 0), tkLink(4, "en0"), nil),
			"2001:db8:1::20", "en0", hostOnLink,
		},
		{
			"cloned host entry without gateway on en0",
			tkGet(host|cloned, tkV4("192.168.1.20"), tkLink(4, "en0"), nil),
			"192.168.1.20", "en0", hostOnLink,
		},
		{
			"endpoint equals the gateway (its ARP entry)",
			tkGet(host|llinfo|cloned, tkV4("192.168.1.1"), tkLink(4, "en0"), nil),
			"192.168.1.1", "en0", hostOnLink,
		},
		{
			"ARP entry on bridge0",
			tkGet(host|llinfo|cloned, tkV4("192.168.2.20"), tkLink(9, "bridge0"), nil),
			"192.168.2.20", "bridge0", hostOnLink,
		},
		{
			"ARP entry with empty ifname: not physical",
			tkGet(host|llinfo|cloned, tkV4("192.168.1.20"), tkLink(4, ""), nil),
			"192.168.1.20", "", hostNone,
		},

		// doc of classifyHost: a clone via a gateway is hostNone (the kernel
		// replaces it on RTM_ADD).
		{
			"clone via gateway (UGHW)",
			tkGet(host|gwf|cloned, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"IPv6 clone via gateway (UGHW)",
			tkGet(host|gwf|cloned, tkV6("2001:db8::5", 0), tkV6("fe80::1", 4), nil),
			"2001:db8::5", "en0", hostNone,
		},

		// The best route is not a host route to dst.
		{
			"default route via gateway",
			tkGet(gwf|static, tkV4("0.0.0.0"), tkV4("192.168.1.1"), mask0),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"IPv6 default route via gateway",
			tkGet(gwf|static, tkV6("::", 0), tkV6("fe80::1", 4), tkV6("::", 0)),
			"2001:db8::5", "en0", hostNone,
		},
		{
			"network route covering dst via gateway",
			tkGet(gwf|static, tkV4("203.0.113.0"), tkV4("192.168.1.1"), mask24),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"own host route to another dst via gateway",
			tkGet(host|gwf|static|proto2, tkV4("203.0.113.6"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"foreign host route to another dst via gateway",
			tkGet(host|gwf|static, tkV4("203.0.113.6"), tkV4("192.168.1.1"), nil),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"default route into a utun",
			tkGet(gwf|static, tkV4("0.0.0.0"), tkV4("10.8.0.1"), mask0),
			"203.0.113.5", "utun3", hostNone,
		},

		// decision 11: a direct route via a physical interface is on-link.
		{
			"direct IPv4 subnet route on en0",
			tkGet(cloning, tkV4("192.168.1.0"), tkLink(4, "en0"), mask24),
			"192.168.1.20", "en0", hostOnLink,
		},
		{
			"direct IPv6 subnet route on en0",
			tkGet(cloning, tkV6("2001:db8:1::", 0), tkLink(4, "en0"), mask64),
			"2001:db8:1::20", "en0", hostOnLink,
		},
		{
			"direct subnet route on en10",
			tkGet(cloning|static, tkV4("10.1.0.0"), tkLink(12, "en10"), mask24),
			"10.1.0.20", "en10", hostOnLink,
		},
		{
			"direct subnet route on utun: not physical",
			tkGet(static, tkV4("10.8.0.0"), tkLink(17, "utun3"), mask24),
			"10.8.0.20", "utun3", hostNone,
		},
		{
			"direct subnet route on lo0: not physical",
			tkGet(static, tkV4("127.0.0.0"), tkV4("127.0.0.1"), tkV4("255.0.0.0")),
			"127.0.0.5", "lo0", hostNone,
		},
		{
			"direct subnet route with empty ifname",
			tkGet(cloning, tkV4("192.168.1.0"), tkLink(4, ""), mask24),
			"192.168.1.20", "", hostNone,
		},

		// design 5 / decision 14: the default route and its halves 0/1, 128/1
		// are not the local network even without RTF_GATEWAY on en0.
		{
			"default IPv4 route without gateway on en0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(4, "en0"), mask0),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"default IPv6 route without gateway on en0",
			tkGet(static, tkV6("::", 0), tkLink(4, "en0"), tkV6("::", 0)),
			"2001:db8::5", "en0", hostNone,
		},
		{
			"IPv4 half 0.0.0.0/1 without gateway on en0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(4, "en0"), mask1v4),
			"100.64.0.5", "en0", hostNone,
		},
		{
			"IPv4 half 128.0.0.0/1 without gateway on en0",
			tkGet(static, tkV4("128.0.0.0"), tkLink(4, "en0"), mask1v4),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"IPv6 half ::/1 without gateway on en0",
			tkGet(static, tkV6("::", 0), tkLink(4, "en0"), mask1v6),
			"2001:db8::5", "en0", hostNone,
		},
		{
			"IPv6 half 8000::/1 without gateway on en0",
			tkGet(static, tkV6("8000::", 0), tkLink(4, "en0"), mask1v6),
			"fd00::5", "en0", hostNone,
		},
		{
			"default IPv4 route without gateway on ppp0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(9, "ppp0"), mask0),
			"203.0.113.5", "ppp0", hostNone,
		},
		{
			"default IPv6 route without gateway on ppp0",
			tkGet(static, tkV6("::", 0), tkLink(9, "ppp0"), tkV6("::", 0)),
			"2001:db8::5", "ppp0", hostNone,
		},
		{
			"IPv4 half 0.0.0.0/1 on ppp0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(9, "ppp0"), mask1v4),
			"100.64.0.5", "ppp0", hostNone,
		},
		{
			"IPv4 half 128.0.0.0/1 on ppp0",
			tkGet(static, tkV4("128.0.0.0"), tkLink(9, "ppp0"), mask1v4),
			"203.0.113.5", "ppp0", hostNone,
		},
		{
			"IPv6 half ::/1 on ppp0",
			tkGet(static, tkV6("::", 0), tkLink(9, "ppp0"), mask1v6),
			"2001:db8::5", "ppp0", hostNone,
		},
		{
			"IPv6 half 8000::/1 on ppp0",
			tkGet(static, tkV6("8000::", 0), tkLink(9, "ppp0"), mask1v6),
			"fd00::5", "ppp0", hostNone,
		},
		{
			"default IPv4 route without gateway on ipsec0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(11, "ipsec0"), mask0),
			"203.0.113.5", "ipsec0", hostNone,
		},
		{
			"default IPv6 route without gateway on ipsec0",
			tkGet(static, tkV6("::", 0), tkLink(11, "ipsec0"), tkV6("::", 0)),
			"2001:db8::5", "ipsec0", hostNone,
		},
		{
			"IPv4 half 0.0.0.0/1 on ipsec0",
			tkGet(static, tkV4("0.0.0.0"), tkLink(11, "ipsec0"), mask1v4),
			"100.64.0.5", "ipsec0", hostNone,
		},
		{
			"IPv4 half 128.0.0.0/1 on ipsec0",
			tkGet(static, tkV4("128.0.0.0"), tkLink(11, "ipsec0"), mask1v4),
			"203.0.113.5", "ipsec0", hostNone,
		},
		{
			"IPv6 half ::/1 on ipsec0",
			tkGet(static, tkV6("::", 0), tkLink(11, "ipsec0"), mask1v6),
			"2001:db8::5", "ipsec0", hostNone,
		},
		{
			"IPv6 half 8000::/1 on ipsec0",
			tkGet(static, tkV6("8000::", 0), tkLink(11, "ipsec0"), mask1v6),
			"fd00::5", "ipsec0", hostNone,
		},

		// design 5 / decision 14: ppp* and ipsec* are tunnels, so their
		// host entries and direct subnets are not the local network.
		{
			"host entry (LLINFO|WASCLONED) on ppp0: not physical",
			tkGet(host|llinfo|cloned, tkV4("10.64.0.20"), tkLink(9, "ppp0"), nil),
			"10.64.0.20", "ppp0", hostNone,
		},
		{
			"host entry (LLINFO|WASCLONED) on ipsec0: not physical",
			tkGet(host|llinfo|cloned, tkV4("10.65.0.20"), tkLink(11, "ipsec0"), nil),
			"10.65.0.20", "ipsec0", hostNone,
		},
		{
			"cloned host entry without gateway on ppp0: not physical",
			tkGet(host|cloned, tkV4("10.64.0.20"), tkLink(9, "ppp0"), nil),
			"10.64.0.20", "ppp0", hostNone,
		},
		{
			"direct IPv4 subnet route on ppp0: not physical",
			tkGet(cloning, tkV4("10.64.0.0"), tkLink(9, "ppp0"), mask24),
			"10.64.0.20", "ppp0", hostNone,
		},
		{
			"direct IPv6 subnet route on ppp0: not physical",
			tkGet(cloning, tkV6("2001:db8:2::", 0), tkLink(9, "ppp0"), mask64),
			"2001:db8:2::20", "ppp0", hostNone,
		},
		{
			"direct IPv4 subnet route on ipsec0: not physical",
			tkGet(cloning, tkV4("10.65.0.0"), tkLink(11, "ipsec0"), mask24),
			"10.65.0.20", "ipsec0", hostNone,
		},
		{
			"direct IPv6 subnet route on ipsec0: not physical",
			tkGet(cloning, tkV6("2001:db8:3::", 0), tkLink(11, "ipsec0"), mask64),
			"2001:db8:3::20", "ipsec0", hostNone,
		},

		// Blackhole/reject without a gateway is not a direct route.
		{
			"blackhole subnet route on en0",
			tkGet(bh|static, tkV4("203.0.113.0"), tkLink(4, "en0"), mask24),
			"203.0.113.5", "en0", hostNone,
		},
		{
			"reject subnet route on en0",
			tkGet(reject|static, tkV4("203.0.113.0"), tkLink(4, "en0"), mask24),
			"203.0.113.5", "en0", hostNone,
		},

		// doc of classifyHost: dst compared without zone, IPv4-mapped as IPv4.
		{
			"IPv4-mapped dst, own IPv4 host route",
			tkGet(host|gwf|static|proto2, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"::ffff:203.0.113.5", "en0", hostOwned,
		},
		{
			"IPv4-mapped dst, foreign IPv4 host route",
			tkGet(host|gwf|static, tkV4("203.0.113.5"), tkV4("192.168.1.1"), nil),
			"::ffff:203.0.113.5", "en0", hostForeign,
		},
		{
			"IPv4-mapped dst, ARP entry",
			tkGet(host|llinfo|cloned, tkV4("192.168.1.20"), tkLink(4, "en0"), nil),
			"::ffff:192.168.1.20", "en0", hostOnLink,
		},
		{
			"zoned RTAX_DST, own link-local host route",
			tkGet(host|static|proto2|gwf, tkV6("fe80::5", 4), tkV6("fe80::1", 4), nil),
			"fe80::5", "en0", hostOwned,
		},
		{
			"zoned RTAX_DST, foreign link-local host route",
			tkGet(host|static, tkV6("fe80::5", 4), tkLink(4, "en0"), nil),
			"fe80::5", "en0", hostForeign,
		},
		{
			"zoned dst and zoned RTAX_DST, own host route",
			tkGet(host|static|proto2|gwf, tkV6("fe80::5", 4), tkV6("fe80::1", 4), nil),
			"fe80::5%en0", "en0", hostOwned,
		},
		{
			"zoned dst, ND entry",
			tkGet(host|llinfo|cloned, tkV6("fe80::5", 4), tkLink(4, "en0"), nil),
			"fe80::5%en0", "en0", hostOnLink,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyHost(tt.m, tA(tt.dst), tt.ifname)
			if got != tt.want {
				t.Errorf("classifyHost = %s, want %s", tkStateName(got), tkStateName(tt.want))
			}
		})
	}
}

// design 5 / decision 14: utun*, ipsec* (IKEv2), ppp* (L2TP, PPPoE) are
// tunnels and lo* is loopback; none of them is physical. Empty is not either.
func TestPhysical(t *testing.T) {
	tests := []struct {
		ifname string
		want   bool
	}{
		{"en0", true},
		{"en10", true},
		{"bridge0", true},
		{"ppp0", false},
		{"ppp1", false},
		{"ipsec0", false},
		{"ipsec3", false},
		{"utun0", false},
		{"utun8", false},
		{"lo0", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := physical(tt.ifname); got != tt.want {
			t.Errorf("physical(%q) = %v, want %v", tt.ifname, got, tt.want)
		}
	}
}

// doc of sameAddr: zone ignored, IPv4-mapped compared as IPv4.
func TestSameAddr(t *testing.T) {
	tests := []struct {
		name string
		a    route.Addr
		dst  string
		want bool
	}{
		{"IPv4 equal", tkV4("203.0.113.5"), "203.0.113.5", true},
		{"IPv4 differ", tkV4("203.0.113.6"), "203.0.113.5", false},
		{"IPv6 equal", tkV6("2001:db8::5", 0), "2001:db8::5", true},
		{"IPv6 differ", tkV6("2001:db8::6", 0), "2001:db8::5", false},
		{"zone in route address", tkV6("fe80::5", 4), "fe80::5", true},
		{"zone in dst", tkV6("fe80::5", 0), "fe80::5%en0", true},
		{"zone in both", tkV6("fe80::5", 4), "fe80::5%en1", true},
		{"zone ignored, address differs", tkV6("fe80::6", 4), "fe80::5", false},
		{"IPv4-mapped dst vs IPv4 address", tkV4("203.0.113.5"), "::ffff:203.0.113.5", true},
		{"IPv4-mapped dst vs other IPv4 address", tkV4("203.0.113.6"), "::ffff:203.0.113.5", false},
		{"IPv4-mapped IPv6 address vs IPv4 dst", tkV6("::ffff:203.0.113.5", 0), "203.0.113.5", true},
		{"IPv4 address vs IPv6 dst", tkV4("203.0.113.5"), "2001:db8::5", false},
		{"IPv6 address vs IPv4 dst", tkV6("2001:db8::5", 0), "203.0.113.5", false},
		{"IPv4-compatible IPv6 is not mapped", tkV6("::203.0.113.5", 0), "203.0.113.5", false},
		{"unspecified IPv4 address", tkV4("0.0.0.0"), "203.0.113.5", false},
		{"nil address", nil, "203.0.113.5", false},
		{"link address", tkLink(4, "en0"), "203.0.113.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameAddr(tt.a, tA(tt.dst)); got != tt.want {
				t.Errorf("sameAddr(%v, %s) = %v, want %v", tt.a, tt.dst, got, tt.want)
			}
		})
	}
}

// Tests below follow the doc of deleteMsgFrom: the RTM_DELETE is a copy of
// the kernel entry (Flags, Index, DST, NETMASK) rather than a message built
// anew, because the kernel matches only the former against our host route.

// dmMsg builds a route entry as an RTM_GET reply or a dump entry would carry it.
func dmMsg(typ, flags, index int, dst, gw, mask route.Addr) *route.RouteMessage {
	n := unix.RTAX_GATEWAY + 1
	if mask != nil {
		n = unix.RTAX_NETMASK + 1
	}
	addrs := make([]route.Addr, n)
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_GATEWAY] = gw
	if mask != nil {
		addrs[unix.RTAX_NETMASK] = mask
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   flags,
		Index:   index,
		ID:      12345,
		Seq:     777,
		Addrs:   addrs,
	}
}

// dmAddr returns m.Addrs[i] or nil when the slice is shorter.
func dmAddr(m *route.RouteMessage, i int) route.Addr {
	if i >= len(m.Addrs) {
		return nil
	}
	return m.Addrs[i]
}

func TestDeleteMsgFrom(t *testing.T) {
	const ours = unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO2
	tests := []struct {
		name string
		m    func() *route.RouteMessage // built twice: input and pristine copy
	}{
		{"ipv4 host route via gateway", func() *route.RouteMessage {
			// 0x4847: UP|GATEWAY|HOST|STATIC|PROTO2, as the kernel reports it.
			return dmMsg(unix.RTM_GET, 0x4847, 14,
				tkV4("198.51.100.7"), tkV4("192.168.1.1"), nil)
		}},
		{"ipv4 blackhole", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, ours|unix.RTF_BLACKHOLE, 1,
				tkV4("198.51.100.8"), tkV4("127.0.0.1"), nil)
		}},
		{"ipv6 blackhole", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, ours|unix.RTF_BLACKHOLE, 1,
				tkV6("2001:db8::8", 0), tkV6("::1", 0), nil)
		}},
		{"ipv4 subnet with netmask (dump entry)", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_STATIC|unix.RTF_PROTO2, 9,
				tkV4("10.20.0.0"), tkV4("192.168.1.1"), tkV4("255.255.0.0"))
		}},
		{"ipv6 subnet with netmask", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_STATIC|unix.RTF_PROTO2, 9,
				tkV6("2001:db8:1::", 0), tkV6("fe80::1", 9), tkV6("ffff:ffff:ffff:ffff::", 0))
		}},
		{"ipv6 link-local dst with zone", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, ours|unix.RTF_GATEWAY, 6,
				tkV6("fe80::abcd", 6), tkV6("fe80::1", 6), nil)
		}},
		{"ipv4 host route via link gateway", func() *route.RouteMessage {
			return dmMsg(unix.RTM_GET, ours, 5,
				tkV4("198.51.100.9"), tkLink(5, "en0"), nil)
		}},
	}
	pid := uintptr(os.Getpid())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, orig := tt.m(), tt.m()
			const seq = 4242
			d := deleteMsgFrom(m, seq)
			if d == nil {
				t.Fatal("deleteMsgFrom returned nil")
			}
			if d == m {
				t.Fatal("deleteMsgFrom returned m itself")
			}
			wantDst := dmAddr(orig, unix.RTAX_DST)
			wantMask := dmAddr(orig, unix.RTAX_NETMASK)
			check := func(stage string, d *route.RouteMessage) {
				t.Helper()
				if d.Type != unix.RTM_DELETE {
					t.Errorf("%s: Type = %d, want RTM_DELETE", stage, d.Type)
				}
				if d.Version != unix.RTM_VERSION {
					t.Errorf("%s: Version = %d, want RTM_VERSION", stage, d.Version)
				}
				if d.Flags != orig.Flags {
					t.Errorf("%s: Flags = %#x, want %#x", stage, d.Flags, orig.Flags)
				}
				if d.Index != orig.Index {
					t.Errorf("%s: Index = %d, want %d", stage, d.Index, orig.Index)
				}
				if d.Seq != seq {
					t.Errorf("%s: Seq = %d, want %d", stage, d.Seq, seq)
				}
				if d.ID != pid {
					t.Errorf("%s: ID = %d, want pid %d", stage, d.ID, pid)
				}
				if gw := dmAddr(d, unix.RTAX_GATEWAY); gw != nil {
					t.Errorf("%s: RTAX_GATEWAY = %#v, want absent", stage, gw)
				}
				if got := dmAddr(d, unix.RTAX_DST); !reflect.DeepEqual(got, wantDst) {
					t.Errorf("%s: RTAX_DST = %#v, want %#v", stage, got, wantDst)
				}
				if got := dmAddr(d, unix.RTAX_NETMASK); !reflect.DeepEqual(got, wantMask) {
					t.Errorf("%s: RTAX_NETMASK = %#v, want %#v", stage, got, wantMask)
				}
				for i := unix.RTAX_NETMASK + 1; i < len(d.Addrs); i++ {
					if d.Addrs[i] != nil {
						t.Errorf("%s: Addrs[%d] = %#v, want only DST and NETMASK", stage, i, d.Addrs[i])
					}
				}
			}
			check("built", d)
			check("round trip", roundTrip(t, d))

			if !reflect.DeepEqual(m, orig) {
				t.Errorf("m modified:\n got %#v\nwant %#v", m, orig)
			}
			// The result must not alias m.Addrs.
			for i := range d.Addrs {
				d.Addrs[i] = tkV4("203.0.113.99")
			}
			if !reflect.DeepEqual(m.Addrs, orig.Addrs) {
				t.Errorf("mutating result.Addrs changed m.Addrs:\n got %#v\nwant %#v", m.Addrs, orig.Addrs)
			}
		})
	}
}

// Tests below follow the doc of ownedTo: from a routing table dump only our
// (RTF_PROTO2) host (RTF_HOST) routes to dst are returned, in dump order.
// XNU keeps a scoped clone of the same dst next to our host route
// (UP|GATEWAY|HOST|WASCLONED|IFSCOPE|IFREF|GLOBAL), and it must be skipped.

const (
	otOurs  = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO2 // 0x4807
	otClone = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_WASCLONED |
		unix.RTF_IFSCOPE | unix.RTF_IFREF | unix.RTF_GLOBAL // 0x45020007
	otBlackhole = unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO2 | unix.RTF_BLACKHOLE
)

// otEntry builds a dump entry tagged with seq so results can be identified.
func otEntry(seq, flags, index int, dst, gw, mask route.Addr) *route.RouteMessage {
	m := dmMsg(unix.RTM_GET, flags, index, dst, gw, mask)
	m.Seq = seq
	return m
}

// otSeqs lists the Seq tags of the returned routes (nil and empty are equal).
func otSeqs(ms []*route.RouteMessage) []int {
	var s []int
	for _, m := range ms {
		if m == nil {
			s = append(s, -1)
			continue
		}
		s = append(s, m.Seq)
	}
	return s
}

// otIn reports whether m is one of msgs (same pointer).
func otIn(m *route.RouteMessage, msgs []route.Message) bool {
	for _, x := range msgs {
		if rm, ok := x.(*route.RouteMessage); ok && rm == m {
			return true
		}
	}
	return false
}

func TestOwnedTo(t *testing.T) {
	gw4 := tkV4("192.168.1.1")
	gw6 := tkV6("fe80::1", 14)
	lo := tkV4("127.0.0.1")
	tests := []struct {
		name string
		msgs []route.Message
		dst  string
		want []int // Seq tags in dump order
	}{
		{
			// manual check on M3: our 0x4807 route and the scoped clone
			name: "our host route and scoped clone of the same dst",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
				otEntry(2, otClone, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "203.0.113.5",
			want: []int{1},
		},
		{
			name: "clone first in dump, ours second",
			msgs: []route.Message{
				otEntry(1, otClone, 14, tkV4("203.0.113.5"), gw4, nil),
				otEntry(2, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "203.0.113.5",
			want: []int{2},
		},
		{
			name: "our blackhole",
			msgs: []route.Message{
				otEntry(1, otBlackhole, 1, tkV4("203.0.113.5"), lo, nil),
			},
			dst:  "203.0.113.5",
			want: []int{1},
		},
		{
			name: "foreign static host route without PROTO2",
			msgs: []route.Message{
				otEntry(1, otOurs&^unix.RTF_PROTO2, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst: "203.0.113.5",
		},
		{
			name: "our route to another dst",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV4("203.0.113.6"), gw4, nil),
			},
			dst: "203.0.113.5",
		},
		{
			name: "our subnet route to dst as network address",
			msgs: []route.Message{
				otEntry(1, otOurs&^unix.RTF_HOST, 14, tkV4("203.0.113.0"), gw4, tkV4("255.255.255.0")),
			},
			dst: "203.0.113.0",
		},
		{
			name: "two ours to one dst: unscoped and IFSCOPE, dump order",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
				otEntry(2, otClone, 14, tkV4("203.0.113.5"), gw4, nil),
				otEntry(3, otOurs|unix.RTF_IFSCOPE, 15, tkV4("203.0.113.5"), tkV4("10.0.0.1"), nil),
			},
			dst:  "203.0.113.5",
			want: []int{1, 3},
		},
		{
			name: "two ours, IFSCOPE first in dump",
			msgs: []route.Message{
				otEntry(7, otOurs|unix.RTF_IFSCOPE, 15, tkV4("203.0.113.5"), tkV4("10.0.0.1"), nil),
				otEntry(4, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "203.0.113.5",
			want: []int{7, 4},
		},
		{
			name: "IPv6 with zone in RTAX_DST, dst without zone",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV6("fe80::5", 14), gw6, nil),
				otEntry(2, otClone, 14, tkV6("fe80::5", 14), gw6, nil),
			},
			dst:  "fe80::5",
			want: []int{1},
		},
		{
			name: "IPv6 global",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV6("2001:db8::5", 0), gw6, nil),
				otEntry(2, otOurs, 14, tkV6("2001:db8::6", 0), gw6, nil),
			},
			dst:  "2001:db8::5",
			want: []int{1},
		},
		{
			name: "IPv4-mapped dst",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "::ffff:203.0.113.5",
			want: []int{1},
		},
		{
			name: "entry without RTAX_DST and with nil Addrs skipped",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, nil, gw4, nil),
				&route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, Flags: otOurs, Index: 14, Seq: 2},
				otEntry(3, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "203.0.113.5",
			want: []int{3},
		},
		{
			name: "entry with link-layer RTAX_DST skipped",
			msgs: []route.Message{
				otEntry(1, otOurs, 14, tkLink(14, "en0"), gw4, nil),
			},
			dst: "203.0.113.5",
		},
		{
			name: "non-route messages skipped",
			msgs: []route.Message{
				&route.InterfaceMessage{Version: unix.RTM_VERSION, Type: unix.RTM_IFINFO, Flags: unix.IFF_UP, Index: 14, Name: "en0"},
				&route.InterfaceAddrMessage{Version: unix.RTM_VERSION, Type: unix.RTM_NEWADDR, Index: 14},
				otEntry(1, otOurs, 14, tkV4("203.0.113.5"), gw4, nil),
			},
			dst:  "203.0.113.5",
			want: []int{1},
		},
		{
			name: "empty msgs",
			msgs: []route.Message{},
			dst:  "203.0.113.5",
		},
		{
			name: "nil msgs",
			dst:  "203.0.113.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ownedTo(tt.msgs, tA(tt.dst))
			if g := otSeqs(got); !reflect.DeepEqual(g, tt.want) {
				t.Errorf("ownedTo(%s) = Seq %v, want %v", tt.dst, g, tt.want)
			}
			for _, m := range got {
				if !otIn(m, tt.msgs) {
					t.Errorf("ownedTo returned %p, not an element of msgs", m)
				}
			}
		})
	}
}

// A dump as the kernel returns it: marshalled entries parsed by ParseRIB.
func TestOwnedToParsedDump(t *testing.T) {
	gw := tkV4("192.168.1.1")
	entries := []*route.RouteMessage{
		otEntry(1, otClone, 14, tkV4("203.0.113.5"), gw, nil),
		otEntry(2, otOurs, 14, tkV4("203.0.113.5"), gw, nil),
		otEntry(3, otOurs&^unix.RTF_PROTO2, 14, tkV4("203.0.113.5"), gw, nil),
		otEntry(4, otOurs, 14, tkV4("203.0.113.6"), gw, nil),
		otEntry(5, otBlackhole|unix.RTF_IFSCOPE, 1, tkV4("203.0.113.5"), tkV4("127.0.0.1"), nil),
		otEntry(6, otOurs&^unix.RTF_HOST, 14, tkV4("203.0.113.0"), gw, tkV4("255.255.255.0")),
	}
	var b []byte
	for _, m := range entries {
		mb, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		b = append(b, mb...)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		t.Fatalf("ParseRIB: %v", err)
	}
	if len(msgs) != len(entries) {
		t.Fatalf("ParseRIB returned %d messages, want %d", len(msgs), len(entries))
	}
	if g, want := otSeqs(ownedTo(msgs, tA("203.0.113.5"))), []int{2, 5}; !reflect.DeepEqual(g, want) {
		t.Errorf("ownedTo(203.0.113.5) = Seq %v, want %v", g, want)
	}
	if got := ownedTo(msgs, tA("203.0.113.0")); len(got) != 0 {
		t.Errorf("ownedTo(203.0.113.0) = Seq %v, want none (subnet route)", otSeqs(got))
	}
}
