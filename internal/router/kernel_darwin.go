package router

// System layer over PF_ROUTE: host routes to tunnel endpoints (design 6).
// Syncing router.Table with the kernel is in sync_darwin.go.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Gateway is the physical default gateway. Zero Addr: there is none
// (no default route, or it points to a link or a utun).
type Gateway struct {
	Addr  netip.Addr
	Index int // interface index
}

// seq numbers routing socket messages of this process.
var seq atomic.Int32

// DefaultGateway returns the gateway of the IPv4 (or, with ipv6, IPv6) default
// route via RTM_GET; no root needed.
func DefaultGateway(ipv6 bool) (Gateway, error) {
	var dst, mask route.Addr = &route.Inet4Addr{}, &route.Inet4Addr{}
	if ipv6 {
		dst, mask = &route.Inet6Addr{}, &route.Inet6Addr{}
	}
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_NETMASK] = mask // exact match: 0.0.0.0/1 of another VPN is not "default"
	req := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP | unix.RTF_GATEWAY,
		ID:      uintptr(os.Getpid()),
		Seq:     int(seq.Add(1)),
		Addrs:   addrs,
	}
	reply, err := get(req)
	if errors.Is(err, unix.ESRCH) {
		return Gateway{}, nil // no default route
	}
	if err != nil {
		return Gateway{}, fmt.Errorf("default route: %w", err)
	}
	var ifname string
	if ifi, err := net.InterfaceByIndex(reply.Index); err == nil {
		ifname = ifi.Name
	}
	return gatewayFrom(reply, ifname), nil
}

// AddHost adds a host route to dst via gw, marked RTF_PROTO2; a blackhole
// route when gw has no Addr (design 6). In order:
//   - our unscoped host routes to dst (RTF_PROTO2, not RTF_IFSCOPE) are found
//     in a dump of the routing table (ownedTo) and removed as DeleteHost does (an error if one is still
//     there afterwards). The dump, not RTM_GET, is used because RTM_GET may
//     answer with a scoped clone (RTF_WASCLONED|RTF_IFSCOPE) that XNU creates
//     for the tunnel's own UDP traffic, hiding our route;
//   - then dst is looked up (RTM_GET) and classified (classifyHost);
//   - on-link (a direct subnet route or host entry via a physical interface,
//     including dst equal to the gateway): adds nothing and returns
//     added=false with a nil error, dst is already reached directly;
//     DeleteHost then removes nothing either. An old route of ours to an
//     endpoint that has become on-link is thus removed, not replaced;
//   - a host route to dst not marked RTF_PROTO2: returns an error wrapping
//     errForeignRoute and leaves the route alone;
//   - otherwise: adds the route. The kernel itself replaces cloned entries
//     (ARP/ND, per-host clones) on RTM_ADD, so EEXIST here means a non-cloned
//     route to dst; it is reported as errForeignRoute. This also covers a
//     foreign host route hidden behind a scoped clone in the RTM_GET reply:
//     it has the same (unscoped) key as ours, so RTM_ADD fails with EEXIST
//     and the route is left alone.
//
// added is true only when the route (via gw or blackhole) is now in the
// kernel; with a non-nil error it is false.
func AddHost(dst netip.Addr, gw Gateway) (added bool, err error) {
	if err := deleteOwnedTo(dst); err != nil {
		return false, fmt.Errorf("replace route %s: %w", dst, err)
	}
	cur, ifname, err := lookupHost(dst)
	if err != nil {
		return false, fmt.Errorf("add route %s: %w", dst, err)
	}
	switch classifyHost(cur, dst, ifname) {
	case hostOnLink:
		return false, nil
	case hostForeign:
		return false, fmt.Errorf("add route %s: %w", dst, errForeignRoute)
	}
	err = write(hostRouteMsg(unix.RTM_ADD, dst, gw, int(seq.Add(1))))
	if errors.Is(err, unix.EEXIST) {
		err = errForeignRoute
	}
	if err != nil {
		return false, fmt.Errorf("add route %s: %w", dst, err)
	}
	return true, nil
}

// errForeignRoute: a route to the endpoint exists that wgplex did not add.
var errForeignRoute = errors.New("a host route not added by wgplex exists, left untouched")

// DeleteHost removes our host routes to dst: host routes to exactly dst
// marked RTF_PROTO2 and not RTF_IFSCOPE, found in a dump of the routing table
// of dst's family (ownedTo). Foreign, cloned and on-link routes and our scoped
// routes (AddScoped) are never touched; with no such route of ours to dst it
// does nothing and returns nil.
//
// The dump is used instead of RTM_GET because, while the tunnel's UDP traffic
// flows, XNU keeps a scoped clone of the default route to dst
// (RTF_WASCLONED|RTF_IFSCOPE) and RTM_GET may return it instead of our route.
//
// Each entry is deleted with an RTM_DELETE copied from it (deleteMsgFrom);
// ESRCH alone is not an error (the route went away after the dump): the table
// is dumped again instead, and an unscoped route of ours to dst still present
// is an error. A nil error means no unscoped route of ours to dst is left.
func DeleteHost(dst netip.Addr) error {
	if err := deleteOwnedTo(dst); err != nil {
		return fmt.Errorf("delete route %s: %w", dst, err)
	}
	return nil
}

// AddScoped adds our scoped host route (RTF_IFSCOPE|RTF_PROTO2) to dst via the
// interface index: sockets bound to it (IP_BOUND_IF) reach dst through it
// whatever the unscoped table says (design 8). An existing scoped route of
// ours to dst on that interface is replaced (found with ownedTo, which
// returns scoped routes too). Removed with the interface; AddHost and
// DeleteHost leave it alone.
//
// The gateway is LinkAddr{Index: index} and rtm_index is index. A scoped and
// an unscoped route to the same prefix are different entries, so an unscoped
// route to dst (ours or foreign) does not conflict with it. Sync ignores
// RTF_IFSCOPE entries and never touches these routes.
func AddScoped(dst netip.Addr, index int) error {
	if index <= 0 {
		return fmt.Errorf("add scoped route %s: bad interface index %d", dst, index)
	}
	dst = dst.Unmap().WithZone("")
	af := unix.AF_INET6
	if dst.Is4() {
		af = unix.AF_INET
	}
	msgs, err := dumpRoutes(af)
	if err != nil {
		return fmt.Errorf("add scoped route %s: %w", dst, err)
	}
	for _, m := range ownedTo(msgs, dst) {
		if m.Flags&unix.RTF_IFSCOPE == 0 || m.Index != index {
			continue
		}
		if err := write(deleteMsgFrom(m, int(seq.Add(1)))); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("replace scoped route %s: %w", dst, err)
		}
	}
	if err := write(scopedRouteMsg(dst, index, int(seq.Add(1)))); err != nil {
		return fmt.Errorf("add scoped route %s: %w", dst, err)
	}
	return nil
}

// scopedRouteMsg builds the RTM_ADD of AddScoped: RTF_UP|RTF_STATIC|RTF_HOST|
// RTF_IFSCOPE|RTF_PROTO2, gateway LinkAddr{Index: index}, rtm_index = index
// (with RTF_IFSCOPE the kernel scopes the route to rtm_index).
func scopedRouteMsg(dst netip.Addr, index, seq int) *route.RouteMessage {
	m := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_HOST | unix.RTF_IFSCOPE | unix.RTF_PROTO2,
		Index:   index,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   make([]route.Addr, unix.RTAX_GATEWAY+1),
	}
	m.Addrs[unix.RTAX_DST] = inetAddr(dst, 0)
	m.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: index}
	return m
}

// deleteOwnedTo does the work of DeleteHost (errors without the dst prefix).
// Our scoped routes (RTF_IFSCOPE, AddScoped) are skipped: they belong to
// AddScoped, and an endpoint of one tunnel equal to a DNS server of another
// must not lose that server's scoped route.
func deleteOwnedTo(dst netip.Addr) error {
	af := unix.AF_INET6
	if dst.Unmap().Is4() {
		af = unix.AF_INET
	}
	msgs, err := dumpRoutes(af)
	if err != nil {
		return err
	}
	owned := unscoped(ownedTo(msgs, dst))
	if len(owned) == 0 {
		return nil
	}
	var errs []error
	for _, m := range owned {
		if err := write(deleteMsgFrom(m, int(seq.Add(1)))); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("RTM_DELETE: %w", err))
		}
	}
	msgs, err = dumpRoutes(af)
	if err != nil {
		errs = append(errs, fmt.Errorf("after RTM_DELETE: %w", err))
	} else if len(unscoped(ownedTo(msgs, dst))) > 0 {
		errs = append(errs, fmt.Errorf("route to %s still present after RTM_DELETE", dst))
	}
	return errors.Join(errs...)
}

// ownedTo returns the routes among msgs (a routing table dump) that are
// ours (RTF_PROTO2) host routes (RTF_HOST) to dst; RTAX_DST is compared
// with sameAddr. Non-route messages and entries without RTAX_DST are skipped.
func ownedTo(msgs []route.Message, dst netip.Addr) []*route.RouteMessage {
	var owned []*route.RouteMessage
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if !ok || m.Flags&unix.RTF_PROTO2 == 0 || m.Flags&unix.RTF_HOST == 0 {
			continue
		}
		if len(m.Addrs) <= unix.RTAX_DST || m.Addrs[unix.RTAX_DST] == nil || !sameAddr(m.Addrs[unix.RTAX_DST], dst) {
			continue
		}
		owned = append(owned, m)
	}
	return owned
}

// unscoped returns the routes of ms without RTF_IFSCOPE.
func unscoped(ms []*route.RouteMessage) []*route.RouteMessage {
	var res []*route.RouteMessage
	for _, m := range ms {
		if m.Flags&unix.RTF_IFSCOPE == 0 {
			res = append(res, m)
		}
	}
	return res
}

// dumpRoutes returns the routing table of address family af (AF_INET,
// AF_INET6) via sysctl NET_RT_DUMP; no root needed.
func dumpRoutes(af int) ([]route.Message, error) {
	b, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	return route.ParseRIB(route.RIBTypeRoute, b)
}

// deleteMsgFrom builds the RTM_DELETE for the route described by m, an
// RTM_GET reply or a dump entry: Version RTM_VERSION, Type RTM_DELETE,
// Flags and Index copied from m, ID = pid, Seq = seq, Addrs with only
// RTAX_DST and (when m has one) RTAX_NETMASK copied from m — no gateway.
//
// The copied flags and index keep RTF_IFSCOPE routes (M4) addressable.
func deleteMsgFrom(m *route.RouteMessage, seq int) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	if len(m.Addrs) > unix.RTAX_DST {
		addrs[unix.RTAX_DST] = m.Addrs[unix.RTAX_DST]
	}
	if len(m.Addrs) > unix.RTAX_NETMASK {
		addrs[unix.RTAX_NETMASK] = m.Addrs[unix.RTAX_NETMASK]
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_DELETE,
		Flags:   m.Flags,
		Index:   m.Index,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
}

// lookupHost returns the kernel's best (longest-prefix) route to dst via
// RTM_GET, no root needed, and the name of its interface; a nil message
// without error when there is no route at all.
func lookupHost(dst netip.Addr) (*route.RouteMessage, string, error) {
	addrs := make([]route.Addr, unix.RTAX_DST+1)
	addrs[unix.RTAX_DST] = inetAddr(dst, 0)
	req := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP | unix.RTF_HOST,
		ID:      uintptr(os.Getpid()),
		Seq:     int(seq.Add(1)),
		Addrs:   addrs,
	}
	reply, err := get(req)
	if errors.Is(err, unix.ESRCH) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("lookup: %w", err)
	}
	var ifname string
	if ifi, err := net.InterfaceByIndex(reply.Index); err == nil {
		ifname = ifi.Name
	}
	return reply, ifname, nil
}

// hostState is what the RTM_GET reply for an endpoint means to AddHost.
type hostState int

const (
	hostNone    hostState = iota // nothing in the way: add our route
	hostOwned                    // our host route to dst (RTF_PROTO2)
	hostForeign                  // a non-cloned host route to dst without RTF_PROTO2
	hostOnLink                   // dst is reached directly via a physical interface
)

// classifyHost classifies m, the RTM_GET reply for dst (nil: no route);
// ifname is the name of the interface m.Index. In order:
//   - a host route (RTF_HOST) whose RTAX_DST is dst: hostOwned with
//     RTF_PROTO2; otherwise hostForeign, unless it is a cloned entry
//     (RTF_WASCLONED or RTF_LLINFO: ARP/ND and per-host clones, which the
//     kernel replaces on RTM_ADD) — then the next rule decides;
//   - a route without RTF_GATEWAY, RTF_BLACKHOLE and RTF_REJECT via a
//     physical interface that is either a host entry (RTF_HOST: the ARP/ND
//     entry of dst, also when dst is the gateway itself) or a subnet route
//     whose RTAX_NETMASK is a contiguous mask longer than /1: hostOnLink;
//   - anything else: hostNone. This includes a route without a gateway that
//     is the default (/0) or its halves 0/1, 128/1, ::/1, 8000::/1 — on ppp*,
//     on a link (link#N, en0 without RTF_GATEWAY) or anywhere else — and a
//     non-host route with a missing or non-contiguous netmask; also a route
//     via a gateway, a route into a non-physical interface, no route.
//
// dst is compared without its zone, IPv4-mapped addresses as IPv4.
func classifyHost(m *route.RouteMessage, dst netip.Addr, ifname string) hostState {
	if m == nil {
		return hostNone
	}
	if m.Flags&unix.RTF_HOST != 0 && len(m.Addrs) > unix.RTAX_DST && sameAddr(m.Addrs[unix.RTAX_DST], dst) {
		if m.Flags&unix.RTF_PROTO2 != 0 {
			return hostOwned
		}
		if m.Flags&(unix.RTF_WASCLONED|unix.RTF_LLINFO) == 0 {
			return hostForeign
		}
	}
	if m.Flags&(unix.RTF_GATEWAY|unix.RTF_BLACKHOLE|unix.RTF_REJECT) != 0 || !physical(ifname) {
		return hostNone
	}
	if m.Flags&unix.RTF_HOST != 0 || maskBits(m) > 1 {
		return hostOnLink
	}
	return hostNone
}

// maskBits returns the prefix length of the RTAX_NETMASK of m; -1 when it is
// missing, not an inet address or not contiguous.
func maskBits(m *route.RouteMessage) int {
	if len(m.Addrs) <= unix.RTAX_NETMASK {
		return -1
	}
	var b []byte
	switch a := m.Addrs[unix.RTAX_NETMASK].(type) {
	case *route.Inet4Addr:
		b = a.IP[:]
	case *route.Inet6Addr:
		b = a.IP[:]
	default:
		return -1
	}
	ones, bits := net.IPMask(b).Size()
	if bits == 0 {
		return -1 // non-contiguous
	}
	return ones
}

// physical reports whether ifname names a physical interface: not empty and
// not utun*, ipsec* (IKEv2), ppp* (L2TP, PPPoE) or lo* (design 6).
func physical(ifname string) bool {
	if ifname == "" {
		return false
	}
	for _, p := range []string{"utun", "ipsec", "ppp", "lo"} {
		if strings.HasPrefix(ifname, p) {
			return false
		}
	}
	return true
}

// sameAddr reports whether the route address a is dst, ignoring the zone
// and comparing IPv4-mapped addresses as IPv4.
func sameAddr(a route.Addr, dst netip.Addr) bool {
	dst = dst.Unmap().WithZone("")
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP) == dst
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP).Unmap() == dst
	}
	return false
}

// hostRouteMsg builds a typ (RTM_ADD, RTM_DELETE) message for the host route
// to dst via gw: RTF_HOST|RTF_STATIC|RTF_PROTO2, plus RTF_GATEWAY with a
// gateway address or RTF_BLACKHOLE without one.
//
// The kernel requires a gateway for RTM_ADD, so a blackhole route goes to the
// loopback address of dst's family (as in wg-quick). A link-local IPv6
// gateway carries gw.Index both in sin6_scope_id and, KAME style, in bytes
// 2–3 of the address. route(8) sends only bytes 2–3 with sin6_scope_id = 0:
// that form is the fallback if the manual check shows RTM_ADD rejecting this
// one.
//
// m.Index is informational: without RTF_IFSCOPE the kernel ignores rtm_index
// and picks the interface by the gateway.
//
// Only RTM_ADD is sent this way: a route is deleted with an RTM_DELETE
// copied from its dump entry (deleteMsgFrom).
func hostRouteMsg(typ int, dst netip.Addr, gw Gateway, seq int) *route.RouteMessage {
	m := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_PROTO2,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   make([]route.Addr, unix.RTAX_GATEWAY+1),
	}
	m.Addrs[unix.RTAX_DST] = inetAddr(dst, 0)
	if gw.Addr.IsValid() {
		m.Flags |= unix.RTF_GATEWAY
		m.Index = gw.Index
		m.Addrs[unix.RTAX_GATEWAY] = inetAddr(gw.Addr, gw.Index)
	} else {
		m.Flags |= unix.RTF_BLACKHOLE
		lo := netip.IPv6Loopback()
		if dst.Unmap().Is4() {
			lo = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
		m.Addrs[unix.RTAX_GATEWAY] = inetAddr(lo, 0)
	}
	return m
}

// inetAddr converts a to a route address; index is the scope of a
// link-local IPv6 address (embedded KAME style and in ZoneID).
func inetAddr(a netip.Addr, index int) route.Addr {
	a = a.Unmap()
	if a.Is4() {
		return &route.Inet4Addr{IP: a.As4()}
	}
	r := &route.Inet6Addr{IP: a.As16()}
	if index > 0 && (a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast()) {
		binary.BigEndian.PutUint16(r.IP[2:4], uint16(index))
		r.ZoneID = index
	}
	return r
}

// gatewayFrom reads the gateway from an RTM_GET reply; ifname is the name of
// m.Index (a non-physical interface — utun*, ipsec*, ppp*, lo*, unknown —
// a link or a loopback gateway → zero Gateway).
func gatewayFrom(m *route.RouteMessage, ifname string) Gateway {
	if !physical(ifname) || len(m.Addrs) <= unix.RTAX_GATEWAY {
		return Gateway{}
	}
	var a netip.Addr
	switch g := m.Addrs[unix.RTAX_GATEWAY].(type) {
	case *route.Inet4Addr:
		a = netip.AddrFrom4(g.IP)
	case *route.Inet6Addr:
		// ParseRIB already moved a KAME-embedded scope into ZoneID;
		// the scope is kept as Index.
		a = netip.AddrFrom16(g.IP).Unmap()
	default: // *route.LinkAddr: the default route points to a link
		return Gateway{}
	}
	if a.IsUnspecified() || a.IsLoopback() {
		return Gateway{}
	}
	return Gateway{Addr: a, Index: m.Index}
}

// addrString formats a route address for error messages.
func addrString(a route.Addr) string {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP).String()
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP).String()
	}
	return "?"
}

// write sends m to a routing socket; the kernel reports the result of
// RTM_ADD/RTM_DELETE as the error of write(2).
func write(m *route.RouteMessage) error {
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.Shutdown(fd, unix.SHUT_RD) // replies are not read
	_, err = unix.Write(fd, b)
	return err
}

// getTimeout bounds waiting for the kernel's reply to one RTM_GET.
const getTimeout = 2 * time.Second

// get sends an RTM_GET request and returns the kernel's reply to it, waiting
// at most getTimeout in total.
func get(m *route.RouteMessage) (*route.RouteMessage, error) {
	b, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, b); err != nil {
		return nil, err
	}
	// The routing socket also carries other processes' messages: wait for
	// ours, under one deadline for the whole loop.
	deadline := time.Now().Add(getTimeout)
	buf := make([]byte, 2048)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, errors.New("no reply from the routing socket")
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return nil, err
		}
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue // the deadline check above decides
		}
		if err != nil {
			return nil, err
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			continue
		}
		for _, msg := range msgs {
			r, ok := msg.(*route.RouteMessage)
			if ok && r.Type == m.Type && r.ID == m.ID && r.Seq == m.Seq {
				if r.Err != nil {
					return nil, r.Err
				}
				return r, nil
			}
		}
	}
}
