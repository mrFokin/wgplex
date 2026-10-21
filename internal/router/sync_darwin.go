package router

// System layer over PF_ROUTE: syncing the computed Table with the kernel
// (design 7.2). Sync keeps no state: each call reads our routes (RTF_PROTO2)
// from a dump of the kernel table, compares them with the wanted ones and
// applies the difference. The pure parts (wanted, owned, diff, routeMsg) are
// tested without root; the helpers of kernel_darwin.go are reused.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// SyncError is the error of Sync when some ops failed: the prefixes of the
// failed routes and the joined errors. A failed dump is a plain error: then
// nothing was synced.
type SyncError struct {
	Failed []netip.Prefix
	Err    error
}

func (e *SyncError) Error() string { return e.Err.Error() }

func (e *SyncError) Unwrap() error { return e.Err }

// Env is what Sync needs to turn Table targets into kernel routes.
type Env struct {
	Ifaces map[string]int // tunnel name → interface index of its utun
	GW4    Gateway        // physical gateway for direct IPv4 routes; zero Addr: none
	GW6    Gateway        // the same for IPv6
}

// Kind is the kind of a kernel route of ours. The zero Kind is unknown: an
// entry of ours in a dump whose form owned does not recognize; it is never
// wanted, so Sync deletes or replaces it.
type Kind int

const (
	KindIface     Kind = iota + 1 // via a utun: RTAX_GATEWAY = LinkAddr{Index}, no RTF_GATEWAY
	KindGateway                   // via a physical gateway: RTF_GATEWAY
	KindReject                    // RTF_REJECT to lo0 (127.0.0.1 / ::1)
	KindBlackhole                 // RTF_BLACKHOLE to lo0; only endpoint routes of M3, never wanted by Sync
)

// KernelRoute is a route of ours (RTF_PROTO2) as the kernel holds it.
// A single-IP Prefix is a host route (RTF_HOST, no netmask).
type KernelRoute struct {
	Prefix  netip.Prefix
	Kind    Kind
	Index   int        // KindIface: utun interface index; KindGateway: interface of the gateway; unknown kind: m.Index of the dump entry
	Gateway netip.Addr // KindGateway
}

// String formats r for logs: "10.0.0.0/8 → if#7", "1.2.3.4/32 → 192.168.1.1",
// "198.51.100.0/24 reject", "1.2.3.4/32 blackhole".
func (r KernelRoute) String() string {
	switch r.Kind {
	case KindIface:
		return fmt.Sprintf("%s → if#%d", r.Prefix, r.Index)
	case KindGateway:
		return fmt.Sprintf("%s → %s", r.Prefix, r.Gateway)
	case KindReject:
		return r.Prefix.String() + " reject"
	case KindBlackhole:
		return r.Prefix.String() + " blackhole"
	}
	return fmt.Sprintf("%s kind %d", r.Prefix, int(r.Kind))
}

// OpType is the type of a change to the kernel table.
type OpType string

const (
	OpAdd    OpType = "add"
	OpChange OpType = "change"
	OpDelete OpType = "delete"
)

// Op is one change to the kernel table.
type Op struct {
	Type  OpType
	Route KernelRoute // the new route; for OpDelete the deleted one
}

// Reasons of Skip.
const (
	reasonNoGateway = "no physical gateway"
	reasonForeign   = "a route not added by wgplex exists"
)

// Skip is a route of the table that is not in the kernel, and why.
type Skip struct {
	Route  Route
	Reason string // "no physical gateway", "a route not added by wgplex exists"
}

// Sync makes our routes in the kernel (RTF_PROTO2) equal to t under env: it
// dumps our routes, computes the difference (diff) and applies it. Entries of
// t with SourceEndpoint and our host routes to those addresses are left alone
// (AddHost/DeleteHost manage them). Ops are applied one by one: an OpAdd that
// fails with EEXIST (a route not added by wgplex on the prefix) goes to the
// skipped routes and the foreign route is left untouched; other errors are
// collected and the remaining ops still run. Not safe for concurrent use with
// itself or with AddHost/DeleteHost: the daemon serializes them. Returns the
// applied ops, the skipped routes and, when some ops failed, a *SyncError
// with their prefixes (a prefix may repeat) and the joined errors.
//
// An OpDelete is an RTM_DELETE copied from the dump entry (deleteMsgFrom);
// ESRCH there is not an error (the route went away after the dump) and the op
// counts as applied. When the OpDelete of a kind change fails, its OpAdd is
// not tried: our old route is still in place and would give EEXIST.
// A failed dump returns the error and no ops. RTM_CHANGE is sent only for
// network routes: diff never gives an OpChange of a host route, and Sync
// reports one as an error without writing it.
//
// Scoped routes (RTF_IFSCOPE) are not ours for Sync: owned skips them, so
// scoped host routes of ours to the DNS servers of tunnels (AddScoped,
// design 7.2, 8) are never changed or deleted here; they go away with their
// utun.
//
// keep comes from t alone: our host route to an endpoint that t lacks is
// deleted like any other route of ours. Between AddHost and the tunnel being
// Up (its endpoints not yet in t) the caller either puts those endpoints in t
// as SourceEndpoint entries or does not call Sync.
func Sync(t Table, env Env) ([]Op, []Skip, error) {
	var (
		have    []KernelRoute
		entries = map[netip.Prefix]*route.RouteMessage{} // dump entry of each route in have
	)
	for _, af := range []int{unix.AF_INET, unix.AF_INET6} {
		msgs, err := dumpRoutes(af)
		if err != nil {
			return nil, nil, fmt.Errorf("dump routes: %w", err)
		}
		for _, msg := range msgs {
			m, ok := msg.(*route.RouteMessage)
			if !ok {
				continue
			}
			if r, ok := ownedRoute(m); ok {
				have = append(have, r)
				if _, dup := entries[r.Prefix]; !dup {
					entries[r.Prefix] = m
				}
			}
		}
	}
	want, keep, skipped := wanted(t, env)

	byPrefix := make(map[netip.Prefix]Route, len(t))
	for _, r := range t {
		byPrefix[r.Prefix] = r
	}
	var (
		applied      []Op
		errs         []error
		failed       []netip.Prefix
		failedDelete = map[netip.Prefix]bool{}
	)
	for _, op := range diff(want, have, keep) {
		p := op.Route.Prefix
		var err error
		switch op.Type {
		case OpAdd:
			if failedDelete[p] {
				continue // the delete of this kind change failed and is reported
			}
			err = write(routeMsg(unix.RTM_ADD, op.Route, int(seq.Add(1))))
			if errors.Is(err, unix.EEXIST) {
				skipped = append(skipped, Skip{Route: byPrefix[p], Reason: reasonForeign})
				continue
			}
		case OpChange:
			if p.IsSingleIP() {
				// Without a netmask the kernel would change the longest match.
				errs = append(errs, fmt.Errorf("route %s %s: change of a host route", op.Type, op.Route))
				failed = append(failed, p)
				continue
			}
			err = write(routeMsg(unix.RTM_CHANGE, op.Route, int(seq.Add(1))))
		case OpDelete:
			err = write(deleteMsgFrom(entries[p], int(seq.Add(1))))
			if errors.Is(err, unix.ESRCH) {
				err = nil
			}
			if err != nil {
				failedDelete[p] = true
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("route %s %s: %w", op.Type, op.Route, err))
			failed = append(failed, p)
			continue
		}
		applied = append(applied, op)
	}
	if len(errs) > 0 {
		return applied, skipped, &SyncError{Failed: failed, Err: errors.Join(errs...)}
	}
	return applied, skipped, nil
}

// LocalNets returns the subnets of addresses on physical interfaces (physical),
// from net.Interfaces; no root needed. Prefixes are masked and listed once.
// IPv6 link-local subnets (fe80::/10) are left out: every interface has one,
// they are scoped to it, and the table never holds link-local prefixes.
func LocalNets() ([]netip.Prefix, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var res []netip.Prefix
	for _, ifi := range ifs {
		if !physical(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ifi.Name, err)
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits == 0 {
				continue // non-contiguous mask
			}
			if ip.Is4In6() && bits == 128 {
				ones -= 96
			}
			ip = ip.Unmap()
			if ip.Is6() && ip.IsLinkLocalUnicast() {
				continue
			}
			p := netip.PrefixFrom(ip, ones).Masked()
			if p.IsValid() && !slices.Contains(res, p) {
				res = append(res, p)
			}
		}
	}
	return res, nil
}

// wanted turns t into kernel routes under env: TargetTunnel → KindIface with
// env.Ifaces[r.Tunnel]; TargetDirect → KindGateway via GW4/GW6 by family;
// TargetReject → KindReject. SourceEndpoint entries go to keep, not to want.
// A tunnel without a utun (missing from Ifaces or a non-positive index) gets
// KindReject, so its traffic does not go direct (design 7.2); a direct route
// without a gateway of its family goes to skipped.
func wanted(t Table, env Env) (want []KernelRoute, keep map[netip.Prefix]bool, skipped []Skip) {
	keep = map[netip.Prefix]bool{}
	for _, r := range t {
		k := KernelRoute{Prefix: r.Prefix}
		switch {
		case r.Source == SourceEndpoint:
			keep[r.Prefix] = true
			continue
		case r.Target == TargetTunnel:
			idx, ok := env.Ifaces[r.Tunnel]
			if !ok || idx <= 0 {
				k.Kind = KindReject
				break
			}
			k.Kind, k.Index = KindIface, idx
		case r.Target == TargetDirect:
			gw := env.GW6
			if r.Prefix.Addr().Is4() {
				gw = env.GW4
			}
			if !gw.Addr.IsValid() {
				skipped = append(skipped, Skip{Route: r, Reason: reasonNoGateway})
				continue
			}
			k.Kind, k.Index, k.Gateway = KindGateway, gw.Index, gw.Addr.WithZone("")
		case r.Target == TargetReject:
			k.Kind = KindReject
		default:
			continue // unknown target: nothing to put in the kernel
		}
		want = append(want, k)
	}
	return want, keep, skipped
}

// owned returns our routes (RTF_PROTO2) among msgs, a routing table dump.
// Entries without a readable prefix (no RTAX_DST, a non-contiguous netmask)
// are left out; an entry whose kind it does not recognize (no gateway, an
// unknown gateway form or flags) is returned with the zero Kind, so that Sync
// removes it rather than not seeing it.
//
// Cloned entries (RTF_WASCLONED) are left out too: the kernel clones our
// network routes per destination with RTF_PROTO2 inherited, and removes the
// clones together with the parent route.
//
// Scoped entries (RTF_IFSCOPE) are left out as well: our scoped host routes
// to the DNS servers of tunnels (AddScoped) are not part of the Table.
func owned(msgs []route.Message) []KernelRoute {
	var res []KernelRoute
	for _, msg := range msgs {
		if m, ok := msg.(*route.RouteMessage); ok {
			if r, ok := ownedRoute(m); ok {
				res = append(res, r)
			}
		}
	}
	return res
}

// ownedRoute reads m as a route of ours; false when it is not ours
// (no RTF_PROTO2, a clone, a scoped route) or has no readable prefix (see owned). The kind:
// RTF_REJECT → KindReject, RTF_BLACKHOLE → KindBlackhole (both with an
// address gateway, the loopback), RTF_GATEWAY with an address gateway →
// KindGateway (Index = m.Index), a link gateway without those flags →
// KindIface (Index = m.Index, the interface the traffic goes to; the link's
// index when m.Index is 0); anything else → the zero Kind with Index =
// m.Index. The prefix length is that of the address for RTF_HOST, else of a
// contiguous RTAX_NETMASK.
func ownedRoute(m *route.RouteMessage) (KernelRoute, bool) {
	if m.Flags&unix.RTF_PROTO2 == 0 || m.Flags&(unix.RTF_WASCLONED|unix.RTF_IFSCOPE) != 0 || len(m.Addrs) <= unix.RTAX_DST {
		return KernelRoute{}, false
	}
	var dst netip.Addr
	switch a := m.Addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		dst = netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		dst = netip.AddrFrom16(a.IP) // ParseRIB moved a KAME scope out of IP
	default:
		return KernelRoute{}, false
	}
	bits := dst.BitLen()
	if m.Flags&unix.RTF_HOST == 0 {
		bits = maskBits(m)
		if bits < 0 || bits > dst.BitLen() {
			return KernelRoute{}, false
		}
	}
	r := KernelRoute{Prefix: netip.PrefixFrom(dst, bits).Masked()}
	unknown := KernelRoute{Prefix: r.Prefix, Index: m.Index}
	var gwAddr route.Addr
	if len(m.Addrs) > unix.RTAX_GATEWAY {
		gwAddr = m.Addrs[unix.RTAX_GATEWAY]
	}
	switch gw := gwAddr.(type) {
	case *route.Inet4Addr, *route.Inet6Addr:
		switch {
		case m.Flags&unix.RTF_REJECT != 0:
			r.Kind = KindReject
		case m.Flags&unix.RTF_BLACKHOLE != 0:
			r.Kind = KindBlackhole
		case m.Flags&unix.RTF_GATEWAY != 0:
			r.Kind, r.Index = KindGateway, m.Index
			if g4, ok := gw.(*route.Inet4Addr); ok {
				r.Gateway = netip.AddrFrom4(g4.IP)
			} else {
				r.Gateway = netip.AddrFrom16(gw.(*route.Inet6Addr).IP)
			}
		default:
			return unknown, true // an address gateway without a known flag
		}
	case *route.LinkAddr:
		if m.Flags&(unix.RTF_GATEWAY|unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
			return unknown, true
		}
		r.Kind, r.Index = KindIface, m.Index
		if r.Index == 0 {
			r.Index = gw.Index
		}
	default:
		return unknown, true
	}
	return r, true
}

// diff returns the ops that turn have into want, keep being left alone.
// Same network prefix and kind but another Index (KindIface) or Gateway/Index
// (KindGateway: the same gateway address on another interface after a network
// switch) is an OpChange; another kind (the unknown one of have included) or
// such a change of a host route (single-IP prefix) is OpDelete + OpAdd:
// RTM_CHANGE without a netmask would hit the longest match. KindReject and
// KindBlackhole routes match on Prefix and Kind alone (sameRoute). Routes of have
// that are neither in want nor in keep are deleted. Order: replacements
// (delete then add, adjacent), changes, adds, deletes; prefix order within
// each group. Equal want and have give no ops.
//
// A route of want whose prefix is in keep is ignored; of several routes with
// the same prefix in want or in have, the first one counts.
func diff(want, have []KernelRoute, keep map[netip.Prefix]bool) []Op {
	want, wantBy := uniqueSorted(want)
	have, haveBy := uniqueSorted(have)

	var kinds, changes, adds, deletes []Op
	for _, w := range want {
		if keep[w.Prefix] {
			continue
		}
		h, ok := haveBy[w.Prefix]
		switch {
		case !ok:
			adds = append(adds, Op{Type: OpAdd, Route: w})
		case sameRoute(h, w):
		case h.Kind == w.Kind && !w.Prefix.IsSingleIP():
			changes = append(changes, Op{Type: OpChange, Route: w})
		default:
			kinds = append(kinds, Op{Type: OpDelete, Route: h}, Op{Type: OpAdd, Route: w})
		}
	}
	for _, h := range have {
		if _, ok := wantBy[h.Prefix]; !ok && !keep[h.Prefix] {
			deletes = append(deletes, Op{Type: OpDelete, Route: h})
		}
	}
	return slices.Concat(kinds, changes, adds, deletes)
}

// sameRoute reports whether a and b are the same route for diff: equal Prefix
// and Kind, plus Index for KindIface and Gateway and Index for KindGateway.
// Index and Gateway of other kinds (lo0 of a reject route in a dump) do not
// count.
func sameRoute(a, b KernelRoute) bool {
	if a.Prefix != b.Prefix || a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindIface:
		return a.Index == b.Index
	case KindGateway:
		return a.Index == b.Index && a.Gateway == b.Gateway
	}
	return true
}

// uniqueSorted returns rs without later duplicates of a prefix, sorted in
// Table order, and the routes by prefix.
func uniqueSorted(rs []KernelRoute) ([]KernelRoute, map[netip.Prefix]KernelRoute) {
	by := make(map[netip.Prefix]KernelRoute, len(rs))
	var out []KernelRoute
	for _, r := range rs {
		if _, dup := by[r.Prefix]; dup {
			continue
		}
		by[r.Prefix] = r
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b KernelRoute) int { return comparePrefix(a.Prefix, b.Prefix) })
	return out, by
}

// routeMsg builds an RTM_ADD / RTM_CHANGE message for r: RTF_UP|RTF_STATIC|
// RTF_PROTO2, RTF_HOST for a single IP (no netmask) and RTAX_NETMASK otherwise;
// KindIface: LinkAddr{Index}; KindGateway: RTF_GATEWAY + inetAddr(Gateway,
// Index); KindReject: RTF_REJECT + loopback of r's family. OpDelete uses
// deleteMsgFrom on the dump entry.
//
// The prefix keeps its family: an IPv4-mapped IPv6 prefix stays IPv6, as the
// kernel and owned see it. m.Index is r.Index for KindIface and KindGateway
// (informational: without RTF_IFSCOPE the kernel picks the interface by the
// gateway), 0 otherwise.
func routeMsg(typ int, r KernelRoute, seq int) *route.RouteMessage {
	m := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   make([]route.Addr, unix.RTAX_NETMASK+1),
	}
	a := r.Prefix.Addr()
	is4 := a.Is4()
	if is4 {
		m.Addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: a.As4()}
	} else {
		m.Addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: a.As16()}
	}
	switch {
	case r.Prefix.IsSingleIP():
		m.Flags |= unix.RTF_HOST
	case is4:
		m.Addrs[unix.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte(net.CIDRMask(r.Prefix.Bits(), 32))}
	default:
		m.Addrs[unix.RTAX_NETMASK] = &route.Inet6Addr{IP: [16]byte(net.CIDRMask(r.Prefix.Bits(), 128))}
	}
	lo := netip.IPv6Loopback()
	if is4 {
		lo = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	switch r.Kind {
	case KindIface:
		m.Index = r.Index
		m.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: r.Index}
	case KindGateway:
		m.Flags |= unix.RTF_GATEWAY
		m.Index = r.Index
		m.Addrs[unix.RTAX_GATEWAY] = inetAddr(r.Gateway, r.Index)
	case KindReject:
		m.Flags |= unix.RTF_REJECT
		m.Addrs[unix.RTAX_GATEWAY] = inetAddr(lo, 0)
	case KindBlackhole:
		m.Flags |= unix.RTF_BLACKHOLE
		m.Addrs[unix.RTAX_GATEWAY] = inetAddr(lo, 0)
	}
	return m
}
