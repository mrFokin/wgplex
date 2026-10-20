// Package router computes the routing table from the config, tunnel states and
// dynamic addresses from DNS (design 6) and applies routes to the kernel.
//
// The computation (router.go, rules.go, table.go) is pure logic: no root,
// network or system calls; so is overlap.go, which finds routes overlapping
// local networks (design 16). kernel_darwin.go is the system layer over
// PF_ROUTE: the default gateway and host routes to endpoints (design 5).
// sync_darwin.go syncs the computed table with the kernel (design 6.2).
package router

import "net/netip"

// TunnelState is the runtime state of one tunnel, supplied by the daemon.
type TunnelState struct {
	// Up: enabled by its toggle. A tunnel without a utun (failed to start) is
	// Up with Alive false and no entry in Env.Ifaces: its routes become reject.
	Up        bool
	Alive     bool         // health verdict (design 8); ignored when !Up
	Endpoints []netip.Addr // resolved peer endpoints (design 5, 6.1 item 1)
}

// RuleState is the routing decision for one rule (index = index in Config.Rules).
type RuleState struct {
	Tunnel   string // tunnel serving the rule; "" when direct (empty via) or in fallback
	Fallback bool   // no tunnel from via is usable, Rule.Fallback applies (design 6.3)
}

// Dynamic is an address from a DNS answer for a domain of a rule (design 6.1 item 4, 7).
type Dynamic struct {
	Addr netip.Addr
	Rule int // index in Config.Rules
}

// Target is where a route sends traffic.
type Target string // "tunnel" | "direct" | "reject"

const (
	TargetTunnel Target = "tunnel" // via Route.Tunnel
	TargetDirect Target = "direct" // via the physical gateway, bypassing tunnels
	TargetReject Target = "reject" // reject route (fallback: block)
)

// Source is the origin of a route (design 6.1); for diagnostics only, not sent to the kernel.
type Source string

const (
	SourceEndpoint   Source = "endpoint"    // host route to a peer endpoint
	SourceAllowedIPs Source = "allowed-ips" // tunnel with routes: config
	SourceRuleCIDR   Source = "rule-cidr"   // CIDR of a service in a rule
	SourceDynamic    Source = "dynamic"     // address from a DNS answer
)

// Route is one entry of the computed table.
type Route struct {
	Prefix netip.Prefix
	Target Target
	Tunnel string // TargetTunnel only
	Source Source // for diag.routes / wgplex explain (design 12)
	Rule   int    // index in Config.Rules for rule sources, -1 otherwise
}

// Table is the computed routing table: one route per prefix, sorted by prefix.
type Table []Route
