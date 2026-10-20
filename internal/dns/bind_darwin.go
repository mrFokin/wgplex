package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// boundDialer returns a dialer whose sockets are bound to the interface
// (IP_BOUND_IF or IPV6_BOUND_IF by the address family); index 0: unbound.
// Binding alone needs a scoped route to the server (router.AddScoped,
// design 7).
func boundDialer(index int) *net.Dialer {
	d := &net.Dialer{}
	if index <= 0 {
		return d
	}
	d.Control = func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			// network is "udp4", "udp6", "tcp4" or "tcp6" here.
			if strings.HasSuffix(network, "6") {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
	return d
}

// TunnelResolver resolves via servers through the interface index (sockets
// bound by boundDialer): for the HTTP check host (design 8). The servers are
// tried in order: successive dials take them in turn, so the resolver's
// retries reach the next server. Scoped routes to them are the caller's. No
// servers: every lookup fails.
func TunnelResolver(servers []netip.Addr, index int) *net.Resolver {
	servers = slices.Clone(servers)
	var next atomic.Uint32
	d := boundDialer(index)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if len(servers) == 0 {
				return nil, errors.New("no tunnel DNS servers")
			}
			s := servers[int(next.Add(1)-1)%len(servers)]
			return d.DialContext(ctx, network, net.JoinHostPort(s.Unmap().String(), strconv.Itoa(int(upstreamPort))))
		},
	}
}
