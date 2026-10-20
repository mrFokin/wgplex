package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/mrFokin/wgplex/internal/config"
)

// Resolver resolves endpoint host names; *net.Resolver satisfies it. A custom
// one is needed once the daemon is the system DNS itself (M5).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolveEndpoints resolves Peer.Endpoint of every peer (index = peer index).
// An IP literal is used as is; a host name gives its first IPv4 address, or the
// first IPv6 one when there is no IPv4. IPv4-mapped addresses are unmapped;
// zones are rejected. A peer without Endpoint gets the zero AddrPort.
func ResolveEndpoints(ctx context.Context, r Resolver, peers []config.Peer) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, len(peers))
	for i, p := range peers {
		if p.Endpoint == "" {
			continue
		}
		ap, err := resolveEndpoint(ctx, r, p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("peer %d: endpoint %q: %w", i+1, p.Endpoint, err)
		}
		out[i] = ap
	}
	return out, nil
}

// resolveEndpoint resolves one host:port.
func resolveEndpoint(ctx context.Context, r Resolver, s string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid port %q", portStr)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		if addr, err = lookup(ctx, r, host); err != nil {
			return netip.AddrPort{}, err
		}
	}
	if addr.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("address %s has a zone", addr)
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// lookup returns the first IPv4 address of host, or its first IPv6 one when
// there is no IPv4.
func lookup(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			return a, nil
		}
		if a.Is6() && !v6.IsValid() {
			v6 = a
		}
	}
	if !v6.IsValid() {
		return netip.Addr{}, fmt.Errorf("no addresses for %s", host)
	}
	return v6, nil
}

// HasHostnames reports whether some peer endpoint is a host name, not an IP
// literal (design 10: such endpoints are resolved again).
func HasHostnames(peers []config.Peer) bool {
	for _, p := range peers {
		if p.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			continue // not resolvable either; validation rejects it
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return true
		}
	}
	return false
}
