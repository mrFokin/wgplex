// Package rpc is the JSON-RPC 2.0 interface of the wgplex daemon (design 14): wire
// types, the server over the unix socket with the peer uid check, and the
// pure builders of status.get and diag.* replies from a daemon snapshot.
//
// No reply type carries a key, public ones included (design 10.1).
package rpc

import "time"

const (
	Path = "/rpc" // the JSON-RPC endpoint

	// JSON-RPC error codes of the daemon (decision 5).
	CodeConfigInvalid = 1 // config.reload: the config directory failed to load; data: ConfigErrorData
	CodeNoConfig      = 2 // tunnel.setEnabled before the first successful config load
	CodeUnknownTunnel = 3 // the tunnel name is not in the config
	CodeTunnelStart   = 4 // tunnel.setEnabled true: the tunnel failed to start
)

// ReloadResult is the result of config.reload (design 14): the config is
// applied.
type ReloadResult struct {
	Warnings []string      `json:"warnings"`          // config load and blockedDNSWarnings
	Tunnels  []TunnelError `json:"tunnels,omitempty"` // enabled tunnels that failed to start
}

// TunnelError is a tunnel that failed to start.
type TunnelError struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

// ConfigErrorData is the data of a CodeConfigInvalid error.
type ConfigErrorData struct {
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// SetEnabledParams are the params of tunnel.setEnabled; tunnel.disableAll
// takes no params; both return null.
type SetEnabledParams struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Status is the result of status.get (no params).
type Status struct {
	Configured   bool           `json:"configured"`              // a config has been applied
	Icon         string         `json:"icon"`                    // "off" | "on" | "warn" (decision 4)
	ConfigErrors []string       `json:"config_errors,omitempty"` // last failed config reload; cleared by the next successful one
	Warnings     []string       `json:"warnings,omitempty"`      // of the applied config
	Tunnels      []TunnelStatus `json:"tunnels"`                 // config order
	Rules        []RuleStatus   `json:"rules"`                   // config order
}

// TunnelStatus is one tunnel of Status.
type TunnelStatus struct {
	Name       string       `json:"name"`
	Enabled    bool         `json:"enabled"`
	State      string       `json:"state"`               // "off" | "starting" | "up" | "dead" | "error"
	Error      string       `json:"error,omitempty"`     // State "error"
	Interface  string       `json:"interface,omitempty"` // utunN
	Addresses  []string     `json:"addresses,omitempty"` // Address of the .conf
	Routes     string       `json:"routes"`              // "config" | "rules"
	RouteCount int          `json:"route_count"`         // table routes with Target tunnel via it
	Peers      []PeerStatus `json:"peers,omitempty"`     // .conf order; State "up" or "dead"
	Reason     string       `json:"reason,omitempty"`    // State "dead": why
	Check      *CheckStatus `json:"check,omitempty"`     // check set, State "up"/"dead"
}

// CheckStatus is the active check: ping of the check address or GET of the check URL.
type CheckStatus struct {
	Addr   string    `json:"addr"`             // the check address or URL
	LastOK time.Time `json:"last_ok,omitzero"` // zero: never
	RTTMs  float64   `json:"rtt_ms,omitempty"` // of the last successful check
	Fails  int       `json:"fails"`            // consecutive
}

// PeerStatus is one peer of a running tunnel; its public key is not shown.
type PeerStatus struct {
	Endpoint      string    `json:"endpoint"`                // as in the .conf ("" if none)
	Resolved      string    `json:"resolved,omitempty"`      // addr:port in use
	LastHandshake time.Time `json:"last_handshake,omitzero"` // zero: never
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
}

// RuleStatus is one rule of Status.
type RuleStatus struct {
	Index      int      `json:"index"` // in Config.Rules, from 0
	Services   []string `json:"services"`
	Via        []string `json:"via"`
	Fallback   string   `json:"fallback"`         // configured: "default" | "block"
	Tunnel     string   `json:"tunnel,omitempty"` // serving tunnel; "": direct or in fallback
	InFallback bool     `json:"in_fallback"`
	Degraded   bool     `json:"degraded"` // via non-empty and not on via[0] (design 14, the rule fields of status.get)
}

// ExplainParams are the params of diag.explain.
type ExplainParams struct {
	Query string `json:"query"` // domain or IP
}

// Explanation is the result of diag.explain.
type Explanation struct {
	Query string `json:"query"` // normalized: lowercase, no trailing dot; IP unmapped
	Kind  string `json:"kind"`  // "domain" | "ip"

	// Kind "domain": dns.Choose (design 7.4, 8).
	Rule     *RuleStatus `json:"rule,omitempty"`     // the matched rule (Choice.Rule)
	Skipped  *RuleStatus `json:"skipped,omitempty"`  // MatchDomain winner in fallback: default, passed over (Wirefork M5 decision 1)
	Upstream string      `json:"upstream,omitempty"` // tunnel name, "system" or "block"
	Zone     string      `json:"zone,omitempty"`     // dns_domains zone that chose the tunnel
	Servers  []string    `json:"servers,omitempty"`  // DNS servers of the tunnel upstream
	DropAAAA bool        `json:"drop_aaaa,omitempty"`
	Addrs    []string    `json:"addrs,omitempty"` // dynamic addresses of the name now

	// Kind "ip": the table route matching it (longest prefix); nil: none, the
	// system default route. Rule is set too when the route comes from a rule.
	Route *RouteInfo `json:"route,omitempty"`
}

// Routes is the result of diag.routes (no params).
type Routes struct {
	Routes    []RouteInfo `json:"routes"`               // the last synced table, by prefix
	SyncError string      `json:"sync_error,omitempty"` // of the last Sync
}

// RouteInfo is one route of the table.
type RouteInfo struct {
	Prefix  string   `json:"prefix"`
	Target  string   `json:"target"` // "tunnel" | "direct" | "reject"
	Tunnel  string   `json:"tunnel,omitempty"`
	Source  string   `json:"source"`            // router.Source
	Rule    int      `json:"rule"`              // index in Config.Rules; -1: none
	Names   []string `json:"names,omitempty"`   // Source dynamic: names whose answers gave the address
	Skipped string   `json:"skipped,omitempty"` // not in the kernel: router.Skip.Reason
}
