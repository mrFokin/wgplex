// Package config parses and validates the wgplex configuration:
// wgplex.yaml plus the WireGuard .conf files it references (design 10).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
)

// mainFile is the main config file name (design 10.1).
const mainFile = "wgplex.yaml"

// Load parses and validates the config. files maps a base file name
// ("wgplex.yaml", "work.conf") to its content — on M1 sent by the client
// (solution 5 of the plan, the Wirefork delivery; in M2 the daemon reads
// the directory itself, design 10.2).
// On failure err is Errors with every problem found.
//
// Other *.yaml files besides wgplex.yaml are ignored with a warning (design 10.1).
// Normalizations that keep the config usable (non-canonical CIDRs, services unused
// by any rule, ignored wg-quick fields, non-IP DNS values) are reported in warnings
// (design 6, 10.1). On error cfg is nil.
//
// A missing wgplex.yaml or a YAML syntax/strictness error is reported alone,
// since nothing else can be checked without it. Files that are neither *.yaml
// nor referenced by a tunnel are ignored silently.
func Load(files map[string][]byte) (cfg *Config, warnings []string, err error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name != mainFile && path.Ext(name) == ".yaml" {
			warnings = append(warnings, fmt.Sprintf("%s: ignored, the main file is %s", name, mainFile))
		}
	}

	data, ok := files[mainFile]
	if !ok {
		return nil, warnings, Errors{errors.New(mainFile + " not found")}
	}
	raw, err := parseYAML(data)
	if err != nil {
		return nil, warnings, Errors{fmt.Errorf("%s: %w", mainFile, err)}
	}
	cfg, ws, errs := build(raw, files)
	warnings = append(warnings, ws...)
	if len(errs) > 0 {
		return nil, warnings, Errors(errs)
	}
	return cfg, warnings, nil
}

// Errors collects every validation problem found by Load (design 10.1).
// It implements error.
type Errors []error

// Error joins all messages, one per line.
func (e Errors) Error() string {
	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "\n")
}

// Config is a validated and normalized configuration (design 10.1).
type Config struct {
	IPv6Filter bool
	Tunnels    []Tunnel // order = priority (design 7.2)
	Services   map[string]Service
	Rules      []Rule // order = tie-break (design 7.4)
}

// NeedsDNS reports whether the resolver has work for c (design 8, Wirefork M10
// decision 11): a rule names a service with domains, or a tunnel has
// dns_domains. Without either the system DNS is left alone.
// A service with domains named by no rule does not count. A nil c needs
// nothing.
func (c *Config) NeedsDNS() bool {
	if c == nil {
		return false
	}
	for _, t := range c.Tunnels {
		if len(t.DNSDomains) > 0 {
			return true
		}
	}
	for _, r := range c.Rules {
		for _, name := range r.Services {
			if len(c.Services[name].Domains) > 0 {
				return true
			}
		}
	}
	return false
}

// RouteMode selects which routes a tunnel contributes to the routing table (design 6.1).
type RouteMode string // "config" | "rules"

const (
	// RoutesConfig: AllowedIPs go into the routing table.
	RoutesConfig RouteMode = "config"
	// RoutesRules: only addresses from rules are routed; AllowedIPs is only a crypto filter.
	RoutesRules RouteMode = "rules"
)

// Tunnel is one WireGuard tunnel from wgplex.yaml with its parsed .conf (design 6, 10.1).
type Tunnel struct {
	Name       string
	Routes     RouteMode
	Autostart  bool
	DNSDomains []Domain
	Check      netip.Addr // zero: no ping
	CheckURL   string     // "": no HTTP check; at most one of Check, CheckURL is set
	WG         WGConfig
}

// WGConfig is a parsed WireGuard .conf file (design 6).
type WGConfig struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int // 0: default
	ListenPort int // 0: random
	Peers      []Peer
}

// Peer is one [Peer] section of a .conf file; a file may have several (design 6).
type Peer struct {
	PublicKey           Key
	PresharedKey        Key    // zero: none
	Endpoint            string // host:port, resolved when the tunnel starts
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int // seconds, 0: off
}

// Service is a named set of domains and CIDRs referenced by rules (design 7.3, 10.1).
type Service struct {
	Domains []Domain
	CIDRs   []netip.Prefix
}

// Domain is a normalized domain pattern (design 7.4): a suffix match by default,
// an exact match when written as "=name".
type Domain struct {
	Name  string // lowercase, no trailing dot
	Exact bool   // "=google.com"
}

// Fallback is what a rule does when none of its via tunnels is up (design 7.3).
type Fallback string // "default" | "block"

const (
	// FallbackDefault sends traffic via the system default route.
	FallbackDefault Fallback = "default"
	// FallbackBlock blocks traffic: NODATA for domains, reject routes for addresses.
	FallbackBlock Fallback = "block"
)

// Rule routes the listed services via the first enabled and alive tunnel (design 7.3).
type Rule struct {
	Services []string
	Via      []string // empty: always direct
	Fallback Fallback
}
