package router

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests in this file follow docs/design.md sections 5.1, 6.1–6.3, 7, 8, 9.1 and
// the M2 plan (docs/plans/m2-router.md, "Алгоритм", "Решения", "Готово, когда"),
// not the implementation. Addresses are documentation/private ranges, except the
// telegram CIDRs taken verbatim from the design 9.1 example.

// --- helpers ---------------------------------------------------------------

func tP(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func tA(s string) netip.Addr   { return netip.MustParseAddr(s) }

func tPs(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = tP(s)
	}
	return out
}

func tAs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = tA(s)
	}
	return out
}

// tTun is a tunnel with interface addresses and one [Peer] per AllowedIPs list.
func tTun(name string, mode config.RouteMode, addrs []string, peers ...[]string) config.Tunnel {
	tun := config.Tunnel{Name: name, Routes: mode, WG: config.WGConfig{Addresses: tPs(addrs...)}}
	for _, allowed := range peers {
		tun.WG.Peers = append(tun.WG.Peers, config.Peer{AllowedIPs: tPs(allowed...)})
	}
	return tun
}

// tRule is a rule over the given services.
func tRule(via []string, fb config.Fallback, services ...string) config.Rule {
	return config.Rule{Services: services, Via: via, Fallback: fb}
}

// tCIDRs is a service with CIDRs only.
func tCIDRs(ss ...string) config.Service { return config.Service{CIDRs: tPs(ss...)} }

// tDomains is a service with domains only.
func tDomains(ss ...string) config.Service {
	s := config.Service{}
	for _, d := range ss {
		s.Domains = append(s.Domains, config.Domain{Name: d})
	}
	return s
}

func tDynA(a string, rule int) Dynamic { return Dynamic{Addr: tA(a), Rule: rule} }

// Expected routes by source.
func tEndpoint(p string) Route {
	return Route{Prefix: tP(p), Target: TargetDirect, Source: SourceEndpoint, Rule: -1}
}
func tAllowed(p, tunnel string) Route {
	return Route{Prefix: tP(p), Target: TargetTunnel, Tunnel: tunnel, Source: SourceAllowedIPs, Rule: -1}
}
func tRuleRoute(p string, src Source, target Target, tunnel string, rule int) Route {
	return Route{Prefix: tP(p), Target: target, Tunnel: tunnel, Source: src, Rule: rule}
}
func tCIDRVia(p, tunnel string, rule int) Route {
	return tRuleRoute(p, SourceRuleCIDR, TargetTunnel, tunnel, rule)
}
func tDynVia(p, tunnel string, rule int) Route {
	return tRuleRoute(p, SourceDynamic, TargetTunnel, tunnel, rule)
}

// tBuild calls Build, turns a panic into a test failure and checks the table
// invariants that hold for every input (design 6.2, plan "Сигнатуры").
func tBuild(t *testing.T, cfg *config.Config, tunnels map[string]TunnelState, rules []RuleState, dyn []Dynamic) Table {
	t.Helper()
	var tbl Table
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Build panicked: %v", r)
			}
		}()
		tbl = Build(cfg, tunnels, rules, dyn)
	}()
	tCheckInvariants(t, tbl)
	return tbl
}

// tLess is the table order from the plan: Prefix.Addr().Compare, then Bits().
func tLess(a, b Route) bool {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c < 0
	}
	return a.Prefix.Bits() < b.Prefix.Bits()
}

// tCheckInvariants: one route per prefix, sorted, Tunnel only for TargetTunnel,
// Rule -1 for endpoint/allowed-ips and a rule index otherwise.
func tCheckInvariants(t *testing.T, tbl Table) {
	t.Helper()
	seen := map[netip.Prefix]bool{}
	for i, r := range tbl {
		if seen[r.Prefix] {
			t.Errorf("prefix %s appears more than once (one route per prefix):\n%s", r.Prefix, tFmtTable(tbl))
		}
		seen[r.Prefix] = true
		if i > 0 && !tLess(tbl[i-1], r) {
			t.Errorf("table not sorted at %d: %s before %s", i, tbl[i-1].Prefix, r.Prefix)
		}
		if (r.Target == TargetTunnel) != (r.Tunnel != "") {
			t.Errorf("%s: Target %q with Tunnel %q (Tunnel is set for TargetTunnel only)", r.Prefix, r.Target, r.Tunnel)
		}
		switch r.Source {
		case SourceEndpoint, SourceAllowedIPs:
			if r.Rule != -1 {
				t.Errorf("%s: Source %q with Rule %d, want -1", r.Prefix, r.Source, r.Rule)
			}
		case SourceRuleCIDR, SourceDynamic:
			if r.Rule < 0 {
				t.Errorf("%s: Source %q with Rule %d, want a rule index", r.Prefix, r.Source, r.Rule)
			}
		default:
			t.Errorf("%s: unknown Source %q", r.Prefix, r.Source)
		}
	}
}

func tFmtRoute(r Route) string {
	return fmt.Sprintf("%-22s %-6s %-5s %-11s rule=%d", r.Prefix, r.Target, r.Tunnel, r.Source, r.Rule)
}

func tFmtTable(tbl Table) string {
	if len(tbl) == 0 {
		return "  (empty)"
	}
	var b strings.Builder
	for _, r := range tbl {
		b.WriteString("  " + tFmtRoute(r) + "\n")
	}
	return b.String()
}

// tSameTable compares tables entry by entry; an empty table matches nil or empty.
func tSameTable(t *testing.T, got, want Table) {
	t.Helper()
	equal := len(got) == len(want)
	for i := 0; equal && i < len(got); i++ {
		equal = got[i] == want[i]
	}
	if !equal {
		t.Errorf("table mismatch\ngot:\n%swant:\n%s", tFmtTable(got), tFmtTable(want))
	}
}

// tFind returns the route for prefix p.
func tFind(tbl Table, p string) (Route, bool) {
	for _, r := range tbl {
		if r.Prefix == tP(p) {
			return r, true
		}
	}
	return Route{}, false
}

// --- design 6.1 item 1: endpoints --------------------------------------------

// design 5, 6.1 item 1, 6.2: every Up tunnel gets direct host routes to its
// endpoints (/32 or /128), whatever its routes mode and even when dead.
// A tunnel that is not Up (or missing from the map) contributes nothing.
func TestBuildEndpoints(t *testing.T) {
	cfg := &config.Config{Tunnels: []config.Tunnel{
		tTun("cfg", config.RoutesConfig, []string{"10.66.0.2/32"}),
		tTun("rul", config.RoutesRules, []string{"10.67.0.2/32"}),
	}}
	cases := []struct {
		name    string
		tunnels map[string]TunnelState
		want    Table
	}{
		{name: "alive, v4 and v6, both modes", tunnels: map[string]TunnelState{
			"cfg": {Up: true, Alive: true, Endpoints: tAs("203.0.113.1", "2001:db8::1")},
			"rul": {Up: true, Alive: true, Endpoints: tAs("203.0.113.2")},
		}, want: Table{tEndpoint("203.0.113.1/32"), tEndpoint("203.0.113.2/32"), tEndpoint("2001:db8::1/128")}},
		// design 6.2, decision 7: kept while the tunnel is enabled, even if dead.
		{name: "dead but Up", tunnels: map[string]TunnelState{
			"rul": {Up: true, Alive: false, Endpoints: tAs("203.0.113.2")},
		}, want: Table{tEndpoint("203.0.113.2/32")}},
		// design 6.2: removed when the tunnel is disabled.
		{name: "not Up", tunnels: map[string]TunnelState{
			"rul": {Up: false, Alive: true, Endpoints: tAs("203.0.113.2")},
		}, want: nil},
		{name: "missing from map", tunnels: map[string]TunnelState{}, want: nil},
		{name: "Up without resolved endpoints", tunnels: map[string]TunnelState{"rul": tUp}, want: nil},
		// Two tunnels behind one server: one host route for the shared endpoint.
		{name: "shared endpoint", tunnels: map[string]TunnelState{
			"cfg": {Up: true, Alive: true, Endpoints: tAs("203.0.113.9")},
			"rul": {Up: true, Alive: true, Endpoints: tAs("203.0.113.9")},
		}, want: Table{tEndpoint("203.0.113.9/32")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tSameTable(t, tBuild(t, cfg, c.tunnels, nil, nil), c.want)
		})
	}
}

// --- design 5.1, 6.1 item 2: AllowedIPs ------------------------------------

// design 5.1, 6.1 item 2, 6.2: AllowedIPs of every [Peer] go into the table only
// for Up tunnels with routes: config, alive or dead; routes: rules never.
// design 6.2 (M4 decision 2): work has no IPv6 Address, so its IPv6
// AllowedIPs become reject (Source and Rule unchanged).
func TestBuildAllowedIPs(t *testing.T) {
	cfg := &config.Config{Tunnels: []config.Tunnel{
		tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"},
			[]string{"10.20.0.0/16", "10.0.0.1/32"},
			[]string{"172.20.0.0/14", "fd00:20::/48"}),
		tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}, []string{"0.0.0.0/0", "::/0"}),
	}}
	workAll := Table{
		tAllowed("10.0.0.1/32", "work"),
		tAllowed("10.20.0.0/16", "work"),
		tAllowed("172.20.0.0/14", "work"),
		tRuleRoute("fd00:20::/48", SourceAllowedIPs, TargetReject, "", -1),
	}
	cases := []struct {
		name    string
		tunnels map[string]TunnelState
		want    Table
	}{
		{name: "config tunnel alive, all peers", tunnels: map[string]TunnelState{"work": tUp}, want: workAll},
		// Decision 7: a dead tunnel keeps its AllowedIPs (no leak around it).
		{name: "config tunnel dead", tunnels: map[string]TunnelState{"work": tDead}, want: workAll},
		{name: "config tunnel not Up", tunnels: map[string]TunnelState{"work": tOff}, want: nil},
		{name: "config tunnel missing", tunnels: map[string]TunnelState{}, want: nil},
		// design 5.1: routes: rules AllowedIPs are only a crypto filter.
		{name: "rules tunnel alive", tunnels: map[string]TunnelState{"nl": tUp}, want: nil},
		{name: "both", tunnels: map[string]TunnelState{"work": tUp, "nl": tUp}, want: workAll},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tSameTable(t, tBuild(t, cfg, c.tunnels, nil, nil), c.want)
		})
	}
}

// --- design 6.1 items 3, 4; 6.3: rule routes and their targets --------------

// design 6.3 + decisions 2, 3: the target of rule routes (service CIDRs and
// Dynamic addresses) follows the RuleState.
func TestBuildRuleTargets(t *testing.T) {
	cases := []struct {
		name     string
		via      []string
		fallback config.Fallback
		state    RuleState
		want     Table
	}{
		{name: "rule on a tunnel", via: []string{"nl", "de"}, fallback: config.FallbackDefault, state: tOn("de"),
			want: Table{
				tCIDRVia("192.0.2.0/24", "de", 0),
				tDynVia("198.51.100.7/32", "de", 0),
			}},
		// design 6.3, decision 2: empty via → explicit direct routes.
		{name: "empty via: direct", via: nil, fallback: config.FallbackDefault, state: RuleState{},
			want: Table{
				tRuleRoute("192.0.2.0/24", SourceRuleCIDR, TargetDirect, "", 0),
				tRuleRoute("198.51.100.7/32", SourceDynamic, TargetDirect, "", 0),
			}},
		// design 6.3: fallback block → reject for CIDRs and known IPs.
		{name: "fallback block: reject", via: []string{"nl", "de"}, fallback: config.FallbackBlock, state: tFallback,
			want: Table{
				tRuleRoute("192.0.2.0/24", SourceRuleCIDR, TargetReject, "", 0),
				tRuleRoute("198.51.100.7/32", SourceDynamic, TargetReject, "", 0),
			}},
		// design 6.3, decision 3: fallback default → no routes for the rule.
		{name: "fallback default: no routes", via: []string{"nl", "de"}, fallback: config.FallbackDefault, state: tFallback,
			want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Tunnels: []config.Tunnel{
					tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}, []string{"0.0.0.0/0"}),
					tTun("de", config.RoutesRules, []string{"10.89.0.2/32"}, []string{"0.0.0.0/0"}),
				},
				Services: map[string]config.Service{
					"cidrs":   tCIDRs("192.0.2.0/24"),
					"domains": tDomains("example.com"),
				},
				Rules: []config.Rule{tRule(c.via, c.fallback, "cidrs", "domains")},
			}
			tunnels := map[string]TunnelState{"nl": tDead, "de": tUp}
			if c.state.Fallback {
				tunnels = map[string]TunnelState{"nl": tDead, "de": tDead}
			}
			got := tBuild(t, cfg, tunnels, []RuleState{c.state}, []Dynamic{tDynA("198.51.100.7", 0)})
			tSameTable(t, got, c.want)
		})
	}
}

// design 6.1 item 3: CIDRs of every service of a rule are routed, from all services.
func TestBuildRuleSeveralServices(t *testing.T) {
	cfg := &config.Config{
		Tunnels: []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"})},
		Services: map[string]config.Service{
			"a": tCIDRs("192.0.2.0/25", "198.51.100.0/24"),
			"b": tCIDRs("203.0.113.128/25"),
		},
		Rules: []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "a", "b")},
	}
	got := tBuild(t, cfg, map[string]TunnelState{"nl": tUp}, []RuleState{tOn("nl")}, nil)
	tSameTable(t, got, Table{
		tCIDRVia("192.0.2.0/25", "nl", 0),
		tCIDRVia("198.51.100.0/24", "nl", 0),
		tCIDRVia("203.0.113.128/25", "nl", 0),
	})
}

// --- design 6.2: equal prefixes ----------------------------------------------

// design 6.2 + decisions 1, 4: on an equal prefix, endpoint > rules (earlier
// rule wins) > AllowedIPs (earlier tunnel wins).
func TestBuildEqualPrefixPriority(t *testing.T) {
	// Tunnels: work and home (routes: config), nl and de (routes: rules).
	tunnels := []config.Tunnel{
		tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"}, []string{"10.20.0.0/16", "192.0.2.5/32", "203.0.113.1/32"}),
		tTun("home", config.RoutesConfig, []string{"10.77.0.2/32"}, []string{"10.20.0.0/16", "192.168.1.0/24"}),
		tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}),
		tTun("de", config.RoutesRules, []string{"10.89.0.2/32"}),
	}
	allUp := map[string]TunnelState{"work": tUp, "home": tUp, "nl": tUp, "de": tUp}

	cases := []struct {
		name     string
		services map[string]config.Service
		rules    []config.Rule
		states   []RuleState
		tunnels  map[string]TunnelState // nil: allUp
		dyn      []Dynamic
		prefix   string
		want     Route
	}{
		// design 6.2: AllowedIPs of different tunnels — tunnel order in the config.
		{name: "allowed-ips vs allowed-ips: earlier tunnel", prefix: "10.20.0.0/16",
			want: tAllowed("10.20.0.0/16", "work")},
		{name: "allowed-ips: later tunnel when earlier is down", prefix: "10.20.0.0/16",
			tunnels: map[string]TunnelState{"home": tUp},
			want:    tAllowed("10.20.0.0/16", "home")},

		// decision 1: rules beat AllowedIPs regardless of tunnel order.
		{name: "rule cidr vs allowed-ips: rule", prefix: "10.20.0.0/16",
			services: map[string]config.Service{"s": tCIDRs("10.20.0.0/16")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tOn("nl")},
			want:     tCIDRVia("10.20.0.0/16", "nl", 0)},
		// design 6.2 consequence: dynamic /32 overrides a matching AllowedIPs address.
		{name: "dynamic vs allowed-ips /32: rule", prefix: "192.0.2.5/32",
			services: map[string]config.Service{"s": tDomains("example.com")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tOn("nl")},
			dyn:      []Dynamic{tDynA("192.0.2.5", 0)},
			want:     tDynVia("192.0.2.5/32", "nl", 0)},
		// decision 2: empty via (direct) beats AllowedIPs.
		{name: "direct rule vs allowed-ips: direct", prefix: "192.168.1.0/24",
			services: map[string]config.Service{"s": tCIDRs("192.168.1.0/24")},
			rules:    []config.Rule{tRule(nil, config.FallbackDefault, "s")},
			states:   []RuleState{{}},
			want:     tRuleRoute("192.168.1.0/24", SourceRuleCIDR, TargetDirect, "", 0)},
		// decision 1: reject (fallback block) beats AllowedIPs.
		{name: "reject rule vs allowed-ips: reject", prefix: "192.0.2.5/32",
			services: map[string]config.Service{"s": tDomains("example.com")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackBlock, "s")},
			states:   []RuleState{tFallback},
			dyn:      []Dynamic{tDynA("192.0.2.5", 0)},
			want:     tRuleRoute("192.0.2.5/32", SourceDynamic, TargetReject, "", 0)},
		// decision 3: fallback default has no routes, AllowedIPs decides.
		{name: "fallback default vs allowed-ips: allowed-ips", prefix: "10.20.0.0/16",
			services: map[string]config.Service{"s": tCIDRs("10.20.0.0/16")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tFallback},
			want:     tAllowed("10.20.0.0/16", "work")},

		// design 6.2: between rules — rule order.
		{name: "rule cidr vs rule cidr: earlier rule", prefix: "198.51.100.0/24",
			services: map[string]config.Service{"a": tCIDRs("198.51.100.0/24"), "b": tCIDRs("198.51.100.0/24")},
			rules: []config.Rule{
				tRule([]string{"de"}, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tOn("de"), tOn("nl")},
			want:   tCIDRVia("198.51.100.0/24", "de", 0)},
		{name: "rule cidr vs rule cidr: earlier rule is direct", prefix: "198.51.100.0/24",
			services: map[string]config.Service{"a": tCIDRs("198.51.100.0/24"), "b": tCIDRs("198.51.100.0/24")},
			rules: []config.Rule{
				tRule(nil, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{{}, tOn("nl")},
			want:   tRuleRoute("198.51.100.0/24", SourceRuleCIDR, TargetDirect, "", 0)},
		// design 6.2: shared CDN address from two rules — the earlier rule,
		// regardless of the order of Dynamic entries.
		{name: "shared dynamic: earlier rule", prefix: "198.51.100.9/32",
			services: map[string]config.Service{"a": tDomains("a.example"), "b": tDomains("b.example")},
			rules: []config.Rule{
				tRule([]string{"de"}, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tOn("de"), tOn("nl")},
			dyn:    []Dynamic{tDynA("198.51.100.9", 1), tDynA("198.51.100.9", 0)},
			want:   tDynVia("198.51.100.9/32", "de", 0)},
		// Rule CIDR /32 of an earlier rule vs Dynamic of a later one: rule order.
		{name: "rule cidr /32 vs later rule dynamic: earlier rule", prefix: "198.51.100.9/32",
			services: map[string]config.Service{"a": tDomains("a.example"), "b": tCIDRs("198.51.100.9/32")},
			rules: []config.Rule{
				tRule([]string{"de"}, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tOn("de"), tOn("nl")},
			dyn:    []Dynamic{tDynA("198.51.100.9", 0)},
			want:   tDynVia("198.51.100.9/32", "de", 0)},
		{name: "dynamic of later rule vs earlier rule cidr: earlier rule", prefix: "198.51.100.9/32",
			services: map[string]config.Service{"a": tCIDRs("198.51.100.9/32"), "b": tDomains("b.example")},
			rules: []config.Rule{
				tRule([]string{"de"}, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tOn("de"), tOn("nl")},
			dyn:    []Dynamic{tDynA("198.51.100.9", 1)},
			want:   tCIDRVia("198.51.100.9/32", "de", 0)},
		// decision 3: an earlier rule in fallback default has no candidates, so
		// the later rule's route stands.
		{name: "earlier rule in fallback default: later rule", prefix: "198.51.100.0/24",
			services: map[string]config.Service{"a": tCIDRs("198.51.100.0/24"), "b": tCIDRs("198.51.100.0/24")},
			rules: []config.Rule{
				tRule([]string{"fi"}, config.FallbackDefault, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tFallback, tOn("nl")},
			want:   tCIDRVia("198.51.100.0/24", "nl", 1)},
		// An earlier rule in fallback block rejects; the later rule loses.
		{name: "earlier rule in fallback block: reject", prefix: "198.51.100.0/24",
			services: map[string]config.Service{"a": tCIDRs("198.51.100.0/24"), "b": tCIDRs("198.51.100.0/24")},
			rules: []config.Rule{
				tRule([]string{"fi"}, config.FallbackBlock, "a"),
				tRule([]string{"nl"}, config.FallbackDefault, "b"),
			},
			states: []RuleState{tFallback, tOn("nl")},
			want:   tRuleRoute("198.51.100.0/24", SourceRuleCIDR, TargetReject, "", 0)},

		// design 6.2: host route to an endpoint beats everything.
		{name: "endpoint vs allowed-ips", prefix: "203.0.113.1/32",
			tunnels: map[string]TunnelState{"work": tUp, "nl": {Up: true, Alive: true, Endpoints: tAs("203.0.113.1")}},
			want:    tEndpoint("203.0.113.1/32")},
		{name: "endpoint vs rule cidr", prefix: "203.0.113.7/32",
			services: map[string]config.Service{"s": tCIDRs("203.0.113.7/32")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tOn("nl")},
			tunnels:  map[string]TunnelState{"nl": tUp, "de": {Up: true, Alive: true, Endpoints: tAs("203.0.113.7")}},
			want:     tEndpoint("203.0.113.7/32")},
		{name: "endpoint vs dynamic", prefix: "203.0.113.7/32",
			services: map[string]config.Service{"s": tDomains("example.com")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tOn("nl")},
			tunnels:  map[string]TunnelState{"nl": tUp, "de": {Up: true, Alive: true, Endpoints: tAs("203.0.113.7")}},
			dyn:      []Dynamic{tDynA("203.0.113.7", 0)},
			want:     tEndpoint("203.0.113.7/32")},
		// The endpoint of the rule's own tunnel must not be routed into that tunnel.
		{name: "own endpoint vs dynamic", prefix: "203.0.113.8/32",
			services: map[string]config.Service{"s": tDomains("example.com")},
			rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			states:   []RuleState{tOn("nl")},
			tunnels:  map[string]TunnelState{"nl": {Up: true, Alive: true, Endpoints: tAs("203.0.113.8")}},
			dyn:      []Dynamic{tDynA("203.0.113.8", 0)},
			want:     tEndpoint("203.0.113.8/32")},
		{name: "endpoint vs reject", prefix: "203.0.113.7/32",
			services: map[string]config.Service{"s": tCIDRs("203.0.113.7/32")},
			rules:    []config.Rule{tRule([]string{"fi"}, config.FallbackBlock, "s")},
			states:   []RuleState{tFallback},
			tunnels:  map[string]TunnelState{"de": {Up: true, Alive: false, Endpoints: tAs("203.0.113.7")}},
			want:     tEndpoint("203.0.113.7/32")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{Tunnels: tunnels, Services: c.services, Rules: c.rules}
			ts := c.tunnels
			if ts == nil {
				ts = allUp
			}
			tbl := tBuild(t, cfg, ts, c.states, c.dyn)
			got, ok := tFind(tbl, c.prefix)
			if !ok {
				t.Fatalf("no route for %s:\n%s", c.prefix, tFmtTable(tbl))
			}
			if got != c.want {
				t.Errorf("route for %s:\n  got  %s\n  want %s", c.prefix, tFmtRoute(got), tFmtRoute(c.want))
			}
		})
	}
}

// design 6.2: different prefixes are neither merged nor collapsed —
// longest-prefix match is the kernel's job.
func TestBuildDifferentPrefixesKept(t *testing.T) {
	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"},
				[]string{"10.0.0.0/8", "192.0.2.0/25", "192.0.2.128/25"}),
			tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}),
		},
		Services: map[string]config.Service{
			"s":   tCIDRs("10.1.0.0/16", "10.0.0.0/9"),
			"dom": tDomains("example.com"),
		},
		Rules: []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s", "dom")},
	}
	tunnels := map[string]TunnelState{"work": tUp, "nl": tUp}
	got := tBuild(t, cfg, tunnels, []RuleState{tOn("nl")}, []Dynamic{tDynA("10.1.2.3", 0)})
	tSameTable(t, got, Table{
		tAllowed("10.0.0.0/8", "work"),
		tCIDRVia("10.0.0.0/9", "nl", 0),
		tCIDRVia("10.1.0.0/16", "nl", 0),
		tDynVia("10.1.2.3/32", "nl", 0),
		tAllowed("192.0.2.0/25", "work"),
		tAllowed("192.0.2.128/25", "work"),
	})
}

// --- design 6.1 item 4, 6.2, 7: IPv6 -----------------------------------------

// design 6.1 item 4, 7: a dynamic /128 is routed only when the rule's tunnel
// has an IPv6 address in Address. design 6.2, M4 decision 2 (replaces M2
// decision 8): an IPv6 service CIDR goes via the tunnel only when it has an
// IPv6 address, otherwise it becomes reject.
func TestBuildIPv6(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string // Address of the rule's tunnel
		want  Table
	}{
		{name: "tunnel without IPv6", addrs: []string{"10.88.0.2/32"}, want: Table{
			tDynVia("192.0.2.10/32", "nl", 0),
			tRuleRoute("2001:db8:1::/48", SourceRuleCIDR, TargetReject, "", 0),
		}},
		{name: "tunnel with IPv6", addrs: []string{"10.88.0.2/32", "fd00:88::2/64"}, want: Table{
			tDynVia("192.0.2.10/32", "nl", 0),
			tCIDRVia("2001:db8:1::/48", "nl", 0),
			tDynVia("2001:db8:2::10/128", "nl", 0),
		}},
		{name: "tunnel with IPv6 only", addrs: []string{"fd00:88::2/128"}, want: Table{
			tDynVia("192.0.2.10/32", "nl", 0),
			tCIDRVia("2001:db8:1::/48", "nl", 0),
			tDynVia("2001:db8:2::10/128", "nl", 0),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Tunnels: []config.Tunnel{tTun("nl", config.RoutesRules, c.addrs, []string{"0.0.0.0/0", "::/0"})},
				Services: map[string]config.Service{
					"v6":  tCIDRs("2001:db8:1::/48"),
					"dom": tDomains("example.com"),
				},
				Rules: []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "v6", "dom")},
			}
			dyn := []Dynamic{tDynA("2001:db8:2::10", 0), tDynA("192.0.2.10", 0)}
			got := tBuild(t, cfg, map[string]TunnelState{"nl": tUp}, []RuleState{tOn("nl")}, dyn)
			tSameTable(t, got, c.want)
		})
	}
}

// design 6.1 item 4: the /128 check is per rule tunnel — a rule moved to a
// tunnel without IPv6 loses its /128, one on a tunnel with IPv6 keeps it.
func TestBuildIPv6PerTunnel(t *testing.T) {
	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			tTun("nl", config.RoutesRules, []string{"10.88.0.2/32", "fd00:88::2/64"}),
			tTun("de", config.RoutesRules, []string{"10.89.0.2/32"}),
		},
		Services: map[string]config.Service{"a": tDomains("a.example"), "b": tDomains("b.example")},
		Rules: []config.Rule{
			tRule([]string{"nl", "de"}, config.FallbackDefault, "a"),
			tRule([]string{"de", "nl"}, config.FallbackDefault, "b"),
		},
	}
	dyn := []Dynamic{tDynA("2001:db8::a", 0), tDynA("2001:db8::b", 1)}
	got := tBuild(t, cfg, map[string]TunnelState{"nl": tUp, "de": tUp}, []RuleState{tOn("nl"), tOn("de")}, dyn)
	tSameTable(t, got, Table{tDynVia("2001:db8::a/128", "nl", 0)})
}

// design 6.1 item 4, decision 9: a /128 from Dynamic is dropped only for the
// tunnel target; direct (empty via) and reject (fallback: block) routes keep it
// even when no tunnel has an IPv6 Address.
func TestBuildIPv6NoTunnelTarget(t *testing.T) {
	cases := []struct {
		name     string
		via      []string
		fallback config.Fallback
		state    RuleState
		want     Table
	}{
		// design 6.1 item 4: empty via → direct, /128 always set.
		{name: "empty via: direct keeps /128", via: nil, fallback: config.FallbackDefault, state: RuleState{},
			want: Table{
				tRuleRoute("192.0.2.10/32", SourceDynamic, TargetDirect, "", 0),
				tRuleRoute("2001:db8:2::10/128", SourceDynamic, TargetDirect, "", 0),
			}},
		// design 6.1 item 4: fallback block → reject, /128 always set.
		{name: "fallback block: reject keeps /128", via: []string{"nl"}, fallback: config.FallbackBlock, state: tFallback,
			want: Table{
				tRuleRoute("192.0.2.10/32", SourceDynamic, TargetReject, "", 0),
				tRuleRoute("2001:db8:2::10/128", SourceDynamic, TargetReject, "", 0),
			}},
		// Contrast: the same input on a tunnel without IPv6 drops the /128.
		{name: "tunnel without IPv6 drops /128", via: []string{"nl"}, fallback: config.FallbackBlock, state: tOn("nl"),
			want: Table{tDynVia("192.0.2.10/32", "nl", 0)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}, []string{"0.0.0.0/0"})},
				Services: map[string]config.Service{"dom": tDomains("example.com")},
				Rules:    []config.Rule{tRule(c.via, c.fallback, "dom")},
			}
			tunnels := map[string]TunnelState{"nl": tUp}
			if c.state.Fallback {
				tunnels = map[string]TunnelState{"nl": tDead}
			}
			dyn := []Dynamic{tDynA("2001:db8:2::10", 0), tDynA("192.0.2.10", 0)}
			tSameTable(t, tBuild(t, cfg, tunnels, []RuleState{c.state}, dyn), c.want)
		})
	}
}

// decision 10: the same address as a /32 service CIDR and as a Dynamic of the
// same rule yields one route with Source rule-cidr and the rule index.
func TestBuildCIDRAndDynamicSameAddr(t *testing.T) {
	cases := []struct {
		name     string
		via      []string
		fallback config.Fallback
		state    RuleState
		want     Route
	}{
		{name: "tunnel", via: []string{"nl"}, fallback: config.FallbackDefault, state: tOn("nl"),
			want: tCIDRVia("198.51.100.7/32", "nl", 1)},
		{name: "direct", via: nil, fallback: config.FallbackDefault, state: RuleState{},
			want: tRuleRoute("198.51.100.7/32", SourceRuleCIDR, TargetDirect, "", 1)},
		{name: "reject", via: []string{"nl"}, fallback: config.FallbackBlock, state: tFallback,
			want: tRuleRoute("198.51.100.7/32", SourceRuleCIDR, TargetReject, "", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Tunnels: []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"})},
				Services: map[string]config.Service{
					"other": tCIDRs("192.0.2.0/24"),
					"svc":   {CIDRs: tPs("198.51.100.7/32"), Domains: []config.Domain{{Name: "example.com"}}},
				},
				// Rule 0 is unrelated, so the expected Rule index is not 0 by chance.
				Rules: []config.Rule{
					tRule(nil, config.FallbackDefault, "other"),
					tRule(c.via, c.fallback, "svc"),
				},
			}
			tunnels := map[string]TunnelState{"nl": tUp}
			if c.state.Fallback {
				tunnels = map[string]TunnelState{"nl": tDead}
			}
			got := tBuild(t, cfg, tunnels, []RuleState{{}, c.state}, []Dynamic{tDynA("198.51.100.7", 1)})
			tSameTable(t, got, Table{
				tRuleRoute("192.0.2.0/24", SourceRuleCIDR, TargetDirect, "", 0),
				c.want,
			})
		})
	}
}

// decision 11: IPv4-mapped endpoint and Dynamic addresses are unmapped to IPv4
// /32 routes; a mapped Dynamic on a tunnel without IPv6 is not dropped as /128.
func TestBuildIPv4Mapped(t *testing.T) {
	cfg := &config.Config{
		Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"})},
		Services: map[string]config.Service{"dom": tDomains("example.com")},
		Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "dom")},
	}
	cases := []struct {
		name      string
		endpoints []netip.Addr
		dyn       []Dynamic
		want      Table
	}{
		{name: "mapped endpoint", endpoints: tAs("::ffff:203.0.113.1"),
			want: Table{tEndpoint("203.0.113.1/32")}},
		{name: "mapped dynamic on tunnel without IPv6", dyn: []Dynamic{tDynA("::ffff:198.51.100.7", 0)},
			want: Table{tDynVia("198.51.100.7/32", "nl", 0)}},
		{name: "both", endpoints: tAs("::ffff:203.0.113.1"), dyn: []Dynamic{tDynA("::ffff:198.51.100.7", 0)},
			want: Table{tDynVia("198.51.100.7/32", "nl", 0), tEndpoint("203.0.113.1/32")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tunnels := map[string]TunnelState{"nl": {Up: true, Alive: true, Endpoints: c.endpoints}}
			tSameTable(t, tBuild(t, cfg, tunnels, []RuleState{tOn("nl")}, c.dyn), c.want)
		})
	}
}

// --- Dynamic input edge cases -------------------------------------------------

// plan "Алгоритм": a Dynamic with a rule index out of range is ignored; the rest
// of the table is unaffected.
func TestBuildDynamicBadRuleIndex(t *testing.T) {
	cfg := &config.Config{
		Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"})},
		Services: map[string]config.Service{"dom": tDomains("example.com")},
		Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "dom")},
	}
	dyn := []Dynamic{
		tDynA("192.0.2.1", -1),
		tDynA("192.0.2.2", 1),
		tDynA("192.0.2.3", 100),
		tDynA("192.0.2.4", 0),
	}
	got := tBuild(t, cfg, map[string]TunnelState{"nl": tUp}, []RuleState{tOn("nl")}, dyn)
	tSameTable(t, got, Table{tDynVia("192.0.2.4/32", "nl", 0)})
}

// One route per prefix: the same Dynamic address reported twice for a rule
// (e.g. by two domains of the rule) yields a single route.
func TestBuildDynamicDuplicates(t *testing.T) {
	cfg := &config.Config{
		Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"})},
		Services: map[string]config.Service{"dom": tDomains("a.example", "b.example")},
		Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "dom")},
	}
	dyn := []Dynamic{tDynA("192.0.2.4", 0), tDynA("192.0.2.4", 0)}
	got := tBuild(t, cfg, map[string]TunnelState{"nl": tUp}, []RuleState{tOn("nl")}, dyn)
	tSameTable(t, got, Table{tDynVia("192.0.2.4/32", "nl", 0)})
}

// --- order and determinism ----------------------------------------------------

func TestBuildEmpty(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.Config
		tunnels map[string]TunnelState
	}{
		{name: "empty config", cfg: &config.Config{}},
		{name: "nothing up", cfg: &config.Config{Tunnels: []config.Tunnel{
			tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"}, []string{"10.0.0.0/8"}),
		}}, tunnels: map[string]TunnelState{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tBuild(t, c.cfg, c.tunnels, nil, nil); len(got) != 0 {
				t.Errorf("want empty table, got:\n%s", tFmtTable(got))
			}
		})
	}
}

// plan "Сигнатуры": sorted by Prefix.Addr().Compare, then Bits(); IPv4 before IPv6.
// work has no IPv6 Address: its IPv6 AllowedIPs are reject (design 6.2, M4
// decision 2); the order is the same.
func TestBuildSortOrder(t *testing.T) {
	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"},
				[]string{"fd00:1::/64", "10.0.0.0/16", "192.0.2.0/24", "10.0.0.0/8", "fd00::/16", "10.0.0.0/24"}),
		},
	}
	tunnels := map[string]TunnelState{"work": {Up: true, Alive: true, Endpoints: tAs("2001:db8::1", "203.0.113.1")}}
	got := tBuild(t, cfg, tunnels, nil, nil)
	tSameTable(t, got, Table{
		tAllowed("10.0.0.0/8", "work"),
		tAllowed("10.0.0.0/16", "work"),
		tAllowed("10.0.0.0/24", "work"),
		tAllowed("192.0.2.0/24", "work"),
		tEndpoint("203.0.113.1/32"),
		tEndpoint("2001:db8::1/128"),
		tRuleRoute("fd00::/16", SourceAllowedIPs, TargetReject, "", -1),
		tRuleRoute("fd00:1::/64", SourceAllowedIPs, TargetReject, "", -1),
	})
}

// plan "Готово, когда": the result does not depend on map iteration order or
// on the order of Dynamic entries.
func TestBuildDeterministic(t *testing.T) {
	cfg := &config.Config{Services: map[string]config.Service{}}
	tunnels := map[string]TunnelState{}
	// Many routes: config tunnels with overlapping AllowedIPs and endpoints, so
	// that map iteration order would show.
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("t%d", i)
		cfg.Tunnels = append(cfg.Tunnels, tTun(name, config.RoutesConfig, []string{fmt.Sprintf("10.%d.0.2/32", 100+i)},
			[]string{"10.20.0.0/16", fmt.Sprintf("10.30.%d.0/24", i)}, []string{"172.16.0.0/12"}))
		tunnels[name] = TunnelState{Up: true, Alive: i%2 == 0, Endpoints: tAs(fmt.Sprintf("203.0.113.%d", i+1), "203.0.113.100")}
	}
	var states []RuleState
	for i := 0; i < 6; i++ {
		svc := fmt.Sprintf("s%d", i)
		cfg.Services[svc] = config.Service{
			Domains: []config.Domain{{Name: svc + ".example"}},
			CIDRs:   tPs("198.51.100.0/24", fmt.Sprintf("192.0.2.%d/32", i)),
		}
		cfg.Rules = append(cfg.Rules, tRule([]string{fmt.Sprintf("t%d", i)}, config.FallbackBlock, svc))
		if i%3 == 2 {
			states = append(states, tFallback)
		} else {
			states = append(states, tOn(fmt.Sprintf("t%d", i)))
		}
	}
	var dyn []Dynamic
	for i := 0; i < 6; i++ {
		dyn = append(dyn, tDynA("192.0.2.200", i), tDynA(fmt.Sprintf("192.0.2.%d", 100+i), i))
	}

	first := tBuild(t, cfg, tunnels, states, dyn)
	if len(first) == 0 {
		t.Fatal("empty table")
	}
	rng := rand.New(rand.NewSource(1))
	for run := 0; run < 30; run++ {
		shuffled := append([]Dynamic(nil), dyn...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		// A fresh map each run: different insertion and iteration order.
		ts := map[string]TunnelState{}
		for _, k := range rng.Perm(len(cfg.Tunnels)) {
			name := fmt.Sprintf("t%d", k)
			ts[name] = tunnels[name]
		}
		got := tBuild(t, cfg, ts, states, shuffled)
		tSameTable(t, got, first)
		if t.Failed() {
			t.Fatalf("run %d differs", run)
		}
	}
	// Spot-check the expected winners on the contested prefixes.
	for p, want := range map[string]Route{
		"10.20.0.0/16":     tAllowed("10.20.0.0/16", "t0"),
		"172.16.0.0/12":    tAllowed("172.16.0.0/12", "t0"),
		"198.51.100.0/24":  tCIDRVia("198.51.100.0/24", "t0", 0),
		"192.0.2.200/32":   tDynVia("192.0.2.200/32", "t0", 0),
		"192.0.2.2/32":     tRuleRoute("192.0.2.2/32", SourceRuleCIDR, TargetReject, "", 2),
		"203.0.113.100/32": tEndpoint("203.0.113.100/32"),
	} {
		got, ok := tFind(first, p)
		if !ok {
			t.Errorf("no route for %s", p)
			continue
		}
		if got != want {
			t.Errorf("route for %s:\n  got  %s\n  want %s", p, tFmtRoute(got), tFmtRoute(want))
		}
	}
}

// --- design 9.1: the example, end to end ----------------------------------------

// tExampleCfg is the design 9.1 config with work/home AllowedIPs and addresses
// filled in as the M1 tests do.
func tExampleCfg() *config.Config {
	return &config.Config{
		IPv6Filter: true,
		Tunnels: []config.Tunnel{
			tTun("work", config.RoutesConfig, []string{"10.200.0.2/32"}, []string{"10.20.0.0/16", "10.0.0.1/32"}),
			tTun("home", config.RoutesConfig, []string{"10.77.0.2/32"}, []string{"192.168.1.0/24"}, []string{"192.168.2.0/24"}),
			tTun("nl", config.RoutesRules, []string{"10.88.0.2/32"}, []string{"0.0.0.0/0"}),
			tTun("de", config.RoutesRules, []string{"10.89.0.2/32"}, []string{"0.0.0.0/0"}),
		},
		Services: map[string]config.Service{
			"youtube":  tDomains("youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com"),
			"ai":       tDomains("openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google.com"),
			"telegram": tCIDRs("91.108.4.0/22", "149.154.160.0/20"),
		},
		Rules: []config.Rule{
			tRule([]string{"nl", "de"}, config.FallbackDefault, "youtube", "telegram"),
			tRule([]string{"nl", "de"}, config.FallbackBlock, "ai"),
		},
	}
}

// design 9.1 scenarios from plan "Готово, когда": SelectRules feeds Build over
// a sequence of tunnel states (home has autostart: false and stays off).
func TestBuildExampleScenarios(t *testing.T) {
	cfg := tExampleCfg()
	work := TunnelState{Up: true, Alive: true, Endpoints: tAs("203.0.113.10")}
	nlUp := TunnelState{Up: true, Alive: true, Endpoints: tAs("203.0.113.21")}
	nlDead := TunnelState{Up: true, Alive: false, Endpoints: tAs("203.0.113.21")}
	deUp := TunnelState{Up: true, Alive: true, Endpoints: tAs("203.0.113.22")}
	deDead := TunnelState{Up: true, Alive: false, Endpoints: tAs("203.0.113.22")}

	// youtube (rule 0) and ai (rule 1) addresses from DNS; the /128 is dropped
	// because nl and de have no IPv6 address.
	dyn := []Dynamic{
		tDynA("192.0.2.10", 0),
		tDynA("2001:db8::10", 0),
		tDynA("192.0.2.20", 1),
	}
	common := Table{
		tAllowed("10.0.0.1/32", "work"),
		tAllowed("10.20.0.0/16", "work"),
	}
	endpoints := Table{
		tEndpoint("203.0.113.10/32"),
		tEndpoint("203.0.113.21/32"),
		tEndpoint("203.0.113.22/32"),
	}
	via := func(tunnel string) Table {
		tbl := append(Table{}, common...)
		tbl = append(tbl,
			tCIDRVia("91.108.4.0/22", tunnel, 0),
			tCIDRVia("149.154.160.0/20", tunnel, 0),
			tDynVia("192.0.2.10/32", tunnel, 0),
			tDynVia("192.0.2.20/32", tunnel, 1),
		)
		return append(tbl, endpoints...)
	}
	bothDead := append(append(Table{}, common...),
		// youtube/telegram: fallback default → no routes; ai: fallback block → reject.
		tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 1),
	)
	bothDead = append(bothDead, endpoints...)

	steps := []struct {
		name      string
		tunnels   map[string]TunnelState
		wantRules []RuleState
		want      Table
	}{
		{"all alive", map[string]TunnelState{"work": work, "nl": nlUp, "de": deUp},
			[]RuleState{tOn("nl"), tOn("nl")}, via("nl")},
		// design 8: nl dead → rules move to de; nl endpoint stays (decision 7).
		{"nl dead", map[string]TunnelState{"work": work, "nl": nlDead, "de": deUp},
			[]RuleState{tOn("de"), tOn("de")}, via("de")},
		// design 6.3: no return to nl.
		{"nl revived", map[string]TunnelState{"work": work, "nl": nlUp, "de": deUp},
			[]RuleState{tOn("de"), tOn("de")}, via("de")},
		{"nl and de dead", map[string]TunnelState{"work": work, "nl": nlDead, "de": deDead},
			[]RuleState{tFallback, tFallback}, bothDead},
	}
	var prev []RuleState
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			rules := tSelect(t, cfg, s.tunnels, prev)
			if len(rules) != len(s.wantRules) {
				t.Fatalf("SelectRules len = %d, want %d", len(rules), len(s.wantRules))
			}
			for i := range rules {
				if rules[i] != s.wantRules[i] {
					t.Errorf("rule %d = %+v, want %+v", i, rules[i], s.wantRules[i])
				}
			}
			tSameTable(t, tBuild(t, cfg, s.tunnels, rules, dyn), s.want)
			prev = rules
		})
		if prev == nil {
			t.Fatalf("%s: cannot continue the sequence", s.name)
		}
	}

	// design 6.3: nl and de disabled by the user behave like dead for rules,
	// but their endpoints go away (design 6.2).
	t.Run("nl and de disabled", func(t *testing.T) {
		ts := map[string]TunnelState{"work": work}
		rules := tSelect(t, cfg, ts, nil)
		want := append(append(Table{}, common...),
			tRuleRoute("192.0.2.20/32", SourceDynamic, TargetReject, "", 1),
			tEndpoint("203.0.113.10/32"),
		)
		tSameTable(t, tBuild(t, cfg, ts, rules, dyn), want)
	})

	// home enabled: both peers' AllowedIPs and its endpoints are added.
	t.Run("home enabled", func(t *testing.T) {
		ts := map[string]TunnelState{
			"work": work, "nl": nlUp, "de": deUp,
			"home": {Up: true, Alive: true, Endpoints: tAs("198.51.100.7", "198.51.100.8")},
		}
		rules := tSelect(t, cfg, ts, nil)
		got := tBuild(t, cfg, ts, rules, dyn)
		for _, want := range []Route{
			tAllowed("192.168.1.0/24", "home"),
			tAllowed("192.168.2.0/24", "home"),
			tEndpoint("198.51.100.7/32"),
			tEndpoint("198.51.100.8/32"),
		} {
			r, ok := tFind(got, want.Prefix.String())
			if !ok || r != want {
				t.Errorf("want %s, got %v (found=%v)\n%s", tFmtRoute(want), tFmtRoute(r), ok, tFmtTable(got))
			}
		}
		if len(got) != len(via("nl"))+4 {
			t.Errorf("len = %d, want %d:\n%s", len(got), len(via("nl"))+4, tFmtTable(got))
		}
	})
}

// --- design 6.2, M4 decision 2: IPv6 via a tunnel without IPv6 ----------------

// m4Reject is the reject route an IPv6 tunnel-target prefix becomes when its
// tunnel has no IPv6 address: Tunnel empty, Source and Rule unchanged.
func m4Reject(p string, src Source, rule int) Route {
	return tRuleRoute(p, src, TargetReject, "", rule)
}

// design 6.2 (M4 decision 2): an IPv6 prefix with target "tunnel" (a service
// CIDR or AllowedIPs of a routes: config tunnel) becomes reject when the
// tunnel has no IPv6 address in Address; with one it goes via the tunnel.
// IPv4 prefixes and non-tunnel targets are not affected.
func TestM4BuildIPv6WithoutAddress(t *testing.T) {
	v4only := []string{"10.88.0.2/32"}
	dual := []string{"10.88.0.2/32", "fd00:88::2/64"}
	v6only := []string{"fd00:88::2/128"}
	cases := []struct {
		name    string
		cfg     *config.Config
		tunnels map[string]TunnelState
		rules   []RuleState
		want    Table
	}{
		{
			name: "service CIDR, tunnel without IPv6: reject",
			cfg: &config.Config{
				Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, v4only, []string{"0.0.0.0/0", "::/0"})},
				Services: map[string]config.Service{"s": tCIDRs("198.51.100.0/24", "2001:db8:1::/48")},
				Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			},
			tunnels: map[string]TunnelState{"nl": tUp},
			rules:   []RuleState{tOn("nl")},
			want: Table{
				tCIDRVia("198.51.100.0/24", "nl", 0),
				m4Reject("2001:db8:1::/48", SourceRuleCIDR, 0),
			},
		},
		{
			name: "service CIDR, tunnel with IPv6: tunnel",
			cfg: &config.Config{
				Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, dual, []string{"0.0.0.0/0", "::/0"})},
				Services: map[string]config.Service{"s": tCIDRs("198.51.100.0/24", "2001:db8:1::/48")},
				Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			},
			tunnels: map[string]TunnelState{"nl": tUp},
			rules:   []RuleState{tOn("nl")},
			want: Table{
				tCIDRVia("198.51.100.0/24", "nl", 0),
				tCIDRVia("2001:db8:1::/48", "nl", 0),
			},
		},
		{
			name: "service CIDR, tunnel with IPv6 only: tunnel",
			cfg: &config.Config{
				Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, v6only)},
				Services: map[string]config.Service{"s": tCIDRs("2001:db8:1::/48")},
				Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			},
			tunnels: map[string]TunnelState{"nl": tUp},
			rules:   []RuleState{tOn("nl")},
			want:    Table{tCIDRVia("2001:db8:1::/48", "nl", 0)},
		},
		{
			// The Rule index of the reject route is the rule's own (here 1).
			name: "rule index kept",
			cfg: &config.Config{
				Tunnels: []config.Tunnel{
					tTun("nl", config.RoutesRules, dual),
					tTun("de", config.RoutesRules, v4only),
				},
				Services: map[string]config.Service{"a": tCIDRs("2001:db8:a::/48"), "b": tCIDRs("2001:db8:b::/48")},
				Rules: []config.Rule{
					tRule([]string{"nl"}, config.FallbackDefault, "a"),
					tRule([]string{"de"}, config.FallbackDefault, "b"),
				},
			},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp},
			rules:   []RuleState{tOn("nl"), tOn("de")},
			want: Table{
				tCIDRVia("2001:db8:a::/48", "nl", 0),
				m4Reject("2001:db8:b::/48", SourceRuleCIDR, 1),
			},
		},
		{
			// design 6.2: a dead tunnel keeps its AllowedIPs; the IPv6 ones are
			// reject either way. Not ::/0: design 9.2 forbids it with routes: config.
			name: "AllowedIPs, config tunnel without IPv6: reject",
			cfg: &config.Config{Tunnels: []config.Tunnel{
				tTun("work", config.RoutesConfig, v4only, []string{"10.20.0.0/16", "fd00:20::/48", "fd00::/8"}),
			}},
			tunnels: map[string]TunnelState{"work": tDead},
			want: Table{
				tAllowed("10.20.0.0/16", "work"),
				m4Reject("fd00::/8", SourceAllowedIPs, -1),
				m4Reject("fd00:20::/48", SourceAllowedIPs, -1),
			},
		},
		{
			name: "AllowedIPs, config tunnel with IPv6: tunnel",
			cfg: &config.Config{Tunnels: []config.Tunnel{
				tTun("work", config.RoutesConfig, dual, []string{"10.20.0.0/16", "fd00:20::/48"}),
			}},
			tunnels: map[string]TunnelState{"work": tUp},
			want: Table{
				tAllowed("10.20.0.0/16", "work"),
				tAllowed("fd00:20::/48", "work"),
			},
		},
		{
			// design 6.2: between AllowedIPs the earlier tunnel wins; work
			// (no IPv6) is first, so the prefix is reject from allowed-ips.
			name: "equal AllowedIPs, first tunnel without IPv6",
			cfg: &config.Config{Tunnels: []config.Tunnel{
				tTun("work", config.RoutesConfig, v4only, []string{"fd00:20::/48"}),
				tTun("home", config.RoutesConfig, dual, []string{"fd00:20::/48"}),
			}},
			tunnels: map[string]TunnelState{"work": tUp, "home": tUp},
			want:    Table{m4Reject("fd00:20::/48", SourceAllowedIPs, -1)},
		},
		{
			name: "equal AllowedIPs, first tunnel with IPv6",
			cfg: &config.Config{Tunnels: []config.Tunnel{
				tTun("home", config.RoutesConfig, dual, []string{"fd00:20::/48"}),
				tTun("work", config.RoutesConfig, v4only, []string{"fd00:20::/48"}),
			}},
			tunnels: map[string]TunnelState{"work": tUp, "home": tUp},
			want:    Table{tAllowed("fd00:20::/48", "home")},
		},
		{
			// Only the tunnel target is affected: empty via stays direct.
			name: "empty via: IPv6 CIDR stays direct",
			cfg: &config.Config{
				Tunnels:  []config.Tunnel{tTun("nl", config.RoutesRules, v4only)},
				Services: map[string]config.Service{"s": tCIDRs("2001:db8:1::/48")},
				Rules:    []config.Rule{tRule(nil, config.FallbackDefault, "s")},
			},
			tunnels: map[string]TunnelState{"nl": tUp},
			rules:   []RuleState{{}},
			want:    Table{tRuleRoute("2001:db8:1::/48", SourceRuleCIDR, TargetDirect, "", 0)},
		},
		{
			// design 6.2: a rule beats AllowedIPs on the same prefix; the rule's
			// tunnel has no IPv6, so the prefix is reject even though the
			// AllowedIPs tunnel has IPv6.
			name: "rule beats AllowedIPs, rule tunnel without IPv6",
			cfg: &config.Config{
				Tunnels: []config.Tunnel{
					tTun("work", config.RoutesConfig, dual, []string{"fd00:20::/48"}),
					tTun("nl", config.RoutesRules, v4only),
				},
				Services: map[string]config.Service{"s": tCIDRs("fd00:20::/48")},
				Rules:    []config.Rule{tRule([]string{"nl"}, config.FallbackDefault, "s")},
			},
			tunnels: map[string]TunnelState{"work": tUp, "nl": tUp},
			rules:   []RuleState{tOn("nl")},
			want:    Table{m4Reject("fd00:20::/48", SourceRuleCIDR, 0)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tSameTable(t, tBuild(t, c.cfg, c.tunnels, c.rules, nil), c.want)
		})
	}
}
