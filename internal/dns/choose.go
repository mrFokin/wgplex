package dns

import (
	"net/netip"
	"strings"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Choice is where a query goes (design 8).
type Choice struct {
	Rule     int    // index in cfg.Rules whose domain matched; -1: none
	Tunnel   string // tunnel to query through; "": the system upstream
	Block    bool   // fallback: block, answer NODATA (design 7.3)
	DropAAAA bool   // ipv6_filter and the rule's tunnel has no IPv6 Address (design 8)
}

// Choose picks the upstream for name (design 8), without side effects:
//
//  1. the rule by MatchDomainFunc, skipping rules in fallback: default
//     (useRule);
//  2. a rule in fallback: block → Block, NODATA for any query type;
//  3. a rule on a tunnel → that tunnel; DropAAAA with cfg.IPv6Filter and no
//     IPv6 prefix in the tunnel's Address;
//  4. a rule with an empty via → the system upstream (Tunnel "");
//  5. else the dns_domains of the tunnels in ifaces: the longest zone, ties
//     by tunnel order; Rule is -1;
//  6. else the system upstream, Rule -1.
//
// rules is the SelectRules result for cfg; ifaces holds the tunnels that have
// a utun (tunnel name → interface index; only membership matters here). name
// is compared case-insensitively, a trailing dot is ignored.
func Choose(cfg *config.Config, rules []router.RuleState, ifaces map[string]int, name string) Choice {
	if i, ok := cfg.MatchDomainFunc(name, useRule(cfg, rules)); ok {
		c := Choice{Rule: i}
		switch rs := rules[i]; {
		case rs.Fallback:
			c.Block = true // fallback: default never matches (useRule)
		case rs.Tunnel != "":
			c.Tunnel = rs.Tunnel
			c.DropAAAA = cfg.IPv6Filter && !hasIPv6(findTunnel(cfg, rs.Tunnel))
		}
		return c
	}

	name = strings.TrimSuffix(strings.ToLower(name), ".")
	c := Choice{Rule: -1}
	best := 0
	for _, t := range cfg.Tunnels {
		if _, ok := ifaces[t.Name]; !ok {
			continue
		}
		for _, z := range t.DNSDomains {
			// Only a strictly longer zone wins: ties go to the earlier tunnel.
			if len(z.Name) > best && (name == z.Name || strings.HasSuffix(name, "."+z.Name)) {
				best, c.Tunnel = len(z.Name), t.Name
			}
		}
	}
	return c
}

// findTunnel returns the tunnel of cfg named name; nil: none.
func findTunnel(cfg *config.Config, name string) *config.Tunnel {
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Name == name {
			return &cfg.Tunnels[i]
		}
	}
	return nil
}

// hasIPv6 reports whether t (nil: none) has an IPv6 prefix in its Address.
func hasIPv6(t *config.Tunnel) bool {
	if t == nil {
		return false
	}
	for _, p := range t.WG.Addresses {
		if a := p.Addr(); a.Is6() && !a.Is4In6() {
			return true
		}
	}
	return false
}

// Servers returns the DNS servers of t: DNS from its .conf, else 1.1.1.1 (design 8).
func Servers(t *config.Tunnel) []netip.Addr {
	if len(t.WG.DNS) > 0 {
		return append([]netip.Addr(nil), t.WG.DNS...)
	}
	return []netip.Addr{defaultServer}
}

// defaultServer is the DNS server of a tunnel without DNS in its .conf.
var defaultServer = netip.AddrFrom4([4]byte{1, 1, 1, 1})

// useRule reports whether rule i takes part in domain matching: not in
// fallback: default (Wirefork M5 decision 1). Shared by Choose and Dynamics.List.
// A rule in fallback: block or with an empty via takes part; a rule without
// an entry in rules does not (router.Build gives it no routes either).
func useRule(cfg *config.Config, rules []router.RuleState) func(int) bool {
	return func(i int) bool {
		if i >= len(rules) {
			return false // no decision for the rule: it routes nothing (router.Build)
		}
		return !rules[i].Fallback || cfg.Rules[i].Fallback != config.FallbackDefault
	}
}
