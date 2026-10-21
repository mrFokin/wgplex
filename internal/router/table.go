package router

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/mrFokin/wgplex/internal/config"
)

// Build computes the routing table (design 7.1, 7.2) from the config, tunnel
// states, rule decisions made by SelectRules and the current dynamic addresses.
//
// Candidates by source:
//  1. endpoints of every Up tunnel: /32 or /128, TargetDirect;
//  2. AllowedIPs of every [Peer] of an Up tunnel with routes: config:
//     TargetTunnel, whether the tunnel is alive or not (design 7.2);
//  3. per rule, the CIDRs of its services and its Dynamic addresses:
//     rule on a tunnel: TargetTunnel; empty via: TargetDirect;
//     Fallback with block: TargetReject; Fallback with default: no routes
//     (design 7.3). A /128 from Dynamic is dropped when the rule's tunnel has
//     no IPv6 address in Address (design 7.1 item 4). A Dynamic with a rule
//     index out of range is ignored.
//
// An IPv6 prefix with TargetTunnel (a service CIDR or AllowedIPs) of a tunnel
// without an IPv6 address in Address becomes TargetReject with an empty
// Tunnel, Source and Rule unchanged (design 7.2): the kernel does not accept
// an IPv6 route to an interface without an IPv6 address, and the traffic must
// not go directly.
//
// Equal prefixes from several candidates (design 7.2): endpoint > rules
// (earlier rule wins) > AllowedIPs (earlier tunnel wins). Different prefixes
// are neither merged nor collapsed: longest-prefix match is left to the kernel.
//
// The result has one route per prefix, sorted by prefix, and does not depend
// on map iteration order.
//
// A rule without an entry in rules (len(rules) < len(cfg.Rules)) contributes
// no routes. An empty table is returned as nil.
func Build(cfg *config.Config, tunnels map[string]TunnelState, rules []RuleState, dynamic []Dynamic) Table {
	var t Table
	seen := map[netip.Prefix]bool{}
	// add keeps the first candidate for a prefix: callers add candidates in
	// priority order (design 7.2).
	add := func(r Route) {
		if !r.Prefix.IsValid() || seen[r.Prefix] {
			return
		}
		seen[r.Prefix] = true
		t = append(t, r)
	}

	// 1. Endpoints of Up tunnels, in config order for determinism.
	for _, tun := range cfg.Tunnels {
		st := tunnels[tun.Name]
		if !st.Up {
			continue
		}
		for _, a := range st.Endpoints {
			add(Route{Prefix: hostPrefix(a), Target: TargetDirect, Source: SourceEndpoint, Rule: -1})
		}
	}

	// 3. Rules, in rule order (earlier rule wins).
	dynByRule := make([][]netip.Addr, len(cfg.Rules))
	for _, d := range dynamic {
		if d.Rule >= 0 && d.Rule < len(cfg.Rules) {
			dynByRule[d.Rule] = append(dynByRule[d.Rule], d.Addr)
		}
	}
	for i, rule := range cfg.Rules {
		if i >= len(rules) {
			break
		}
		rs := rules[i]
		var base Route
		switch {
		case rs.Fallback && rule.Fallback == config.FallbackBlock:
			base = Route{Target: TargetReject}
		case rs.Fallback:
			continue // fallback: default, the rest of the table decides
		case rs.Tunnel != "":
			base = Route{Target: TargetTunnel, Tunnel: rs.Tunnel}
		default:
			base = Route{Target: TargetDirect} // empty via
		}
		base.Rule = i
		dropV6 := base.Target == TargetTunnel && !hasIPv6(cfg, rs.Tunnel)
		for _, name := range rule.Services {
			for _, p := range cfg.Services[name].CIDRs {
				r := base
				r.Prefix, r.Source = p, SourceRuleCIDR
				if dropV6 && p.Addr().Is6() {
					r.Target, r.Tunnel = TargetReject, ""
				}
				add(r)
			}
		}
		for _, a := range dynByRule[i] {
			a = a.Unmap()
			if dropV6 && a.Is6() {
				continue
			}
			r := base
			r.Prefix, r.Source = hostPrefix(a), SourceDynamic
			add(r)
		}
	}

	// 2. AllowedIPs of Up tunnels with routes: config, in tunnel order.
	for _, tun := range cfg.Tunnels {
		if tun.Routes != config.RoutesConfig || !tunnels[tun.Name].Up {
			continue
		}
		v6 := hasIPv6(cfg, tun.Name)
		for _, peer := range tun.WG.Peers {
			for _, p := range peer.AllowedIPs {
				r := Route{Prefix: p, Target: TargetTunnel, Tunnel: tun.Name, Source: SourceAllowedIPs, Rule: -1}
				if !v6 && p.Addr().Is6() {
					r.Target, r.Tunnel = TargetReject, ""
				}
				add(r)
			}
		}
	}

	slices.SortFunc(t, func(a, b Route) int { return comparePrefix(a.Prefix, b.Prefix) })
	return t
}

// comparePrefix orders prefixes as in a Table: by address, then by length.
func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

// hostPrefix returns the /32 or /128 for a; IPv4-mapped IPv6 addresses are
// unmapped and zones dropped. An invalid address gives an invalid prefix.
func hostPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen())
}

// hasIPv6 reports whether the named tunnel has an IPv6 address in its .conf
// Address (design 7.1 item 4).
func hasIPv6(cfg *config.Config, name string) bool {
	for _, tun := range cfg.Tunnels {
		if tun.Name != name {
			continue
		}
		for _, p := range tun.WG.Addresses {
			if p.Addr().Is6() && !p.Addr().Is4In6() {
				return true
			}
		}
	}
	return false
}
