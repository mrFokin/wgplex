package rpc

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/tunnel"
)

// State is a snapshot of the daemon for status.get and diag.*.
type State struct {
	Cfg          *config.Config           // nil: no config applied yet
	Warnings     []string                 // of the applied config
	ConfigErrors []string                 // of the last failed apply (start or config.reload)
	Tunnels      map[string]TunnelRuntime // enabled tunnels by name
	Rules        []router.RuleState
	Table        router.Table // the last synced table
	Skips        []router.Skip
	SyncErr      error
	Pairs        []dns.Pair     // dynamic (name, address) pairs
	Ifaces       map[string]int // tunnel → utun index, as given to dns.Server
	Paused       bool           // daemon.pause (design 12): no tunnel is up
	// Switches is the effective toggle by tunnel of Cfg: the toggle of
	// state.json or, without one, autostart (design 11). It is Enabled of
	// status.get, kept on pause; Tunnels is what actually runs.
	Switches map[string]bool
	DNSError string // the system DNS capture failed: why; "": fine (icon warn)
	// BlockSnapshot: no config is applied, but the block snapshot of the
	// last applied one is enforced (design 9.1).
	BlockSnapshot bool
}

// TunnelRuntime is an enabled tunnel: starting (Starting), running
// (Interface set) or failed (Err set).
type TunnelRuntime struct {
	Interface string
	Err       string
	Starting  bool               // being brought up: Up, not Alive, no utun yet
	Endpoints []netip.AddrPort   // index = peer index
	Peers     []tunnel.PeerStats // index = peer index; nil when not running
	Dead      bool               // running, but health says Dead (design 9)
	Reason    string             // Dead: why
	Check     *CheckStatus       // check set and running; nil otherwise
}

// Tunnel states of TunnelStatus.
const (
	stateOff      = "off"
	stateStarting = "starting"
	stateUp       = "up"
	stateDead     = "dead"
	stateError    = "error"
)

// StatusOf builds the status.get reply from s. Tunnels and rules go in config
// order. Enabled of a tunnel is its toggle (s.Switches), kept on pause; its
// State is "off" when not in s.Tunnels, "starting" when Starting (no Error),
// "error" when its Err is set, "dead" (with Reason) when running but Dead,
// "up" otherwise; Check comes with "up" and "dead". RouteCount counts the
// TargetTunnel routes of s.Table via the tunnel, whatever its state. A rule
// gets Reason by ruleReason. Icon by the priority of design 14: "warn" with
// no config or a DNS capture error; else "paused" on pause; else "warn" with
// config errors or a tunnel in "error" or "dead" ("starting" is not); else
// "on" when some tunnel is up; else "off". ConfigErrorCount and WarningCount
// are set here; APIVersion, Version, CanControl, ControlGroup, ConfigDir and
// LogPath are left to Serve.
func StatusOf(s *State) Status {
	st := Status{
		Configured:       s.Cfg != nil,
		BlockSnapshot:    s.BlockSnapshot,
		Paused:           s.Paused,
		ConfigErrors:     s.ConfigErrors,
		ConfigErrorCount: len(s.ConfigErrors),
		Warnings:         s.Warnings,
		WarningCount:     len(s.Warnings),
		Tunnels:          []TunnelStatus{},
		Rules:            []RuleStatus{},
	}
	var up, broken bool
	if s.Cfg != nil {
		for _, t := range s.Cfg.Tunnels {
			ts := tunnelStatus(s, &t)
			switch ts.State {
			case stateUp:
				up = true
			case stateError, stateDead:
				broken = true
			}
			st.Tunnels = append(st.Tunnels, ts)
		}
		for i := range s.Cfg.Rules {
			st.Rules = append(st.Rules, ruleStatus(s, i))
		}
	}
	switch {
	case s.Cfg == nil || s.DNSError != "":
		st.Icon = "warn"
	case s.Paused:
		st.Icon = "paused"
	case len(s.ConfigErrors) > 0 || broken:
		st.Icon = "warn"
	case up:
		st.Icon = "on"
	default:
		st.Icon = "off"
	}
	return st
}

// tunnelStatus builds the status of t.
func tunnelStatus(s *State, t *config.Tunnel) TunnelStatus {
	ts := TunnelStatus{
		Name:    t.Name,
		State:   stateOff,
		Routes:  string(t.Routes),
		Enabled: s.Switches[t.Name],
	}
	for _, p := range t.WG.Addresses {
		ts.Addresses = append(ts.Addresses, p.String())
	}
	for _, r := range s.Table {
		if r.Target == router.TargetTunnel && r.Tunnel == t.Name {
			ts.RouteCount++
		}
	}
	rt, ok := s.Tunnels[t.Name]
	if !ok {
		return ts
	}
	if rt.Starting {
		ts.State = stateStarting
		return ts
	}
	if rt.Err != "" {
		ts.State, ts.Error = stateError, rt.Err
		return ts
	}
	ts.State, ts.Interface = stateUp, rt.Interface
	if rt.Dead {
		ts.State, ts.Reason = stateDead, rt.Reason
	}
	if rt.Check != nil {
		c := *rt.Check
		ts.Check = &c
	}
	for i, p := range t.WG.Peers {
		ps := PeerStatus{Endpoint: p.Endpoint}
		if i < len(rt.Endpoints) && rt.Endpoints[i].IsValid() {
			ps.Resolved = rt.Endpoints[i].String()
		}
		if i < len(rt.Peers) {
			ps.LastHandshake = rt.Peers[i].LastHandshake
			ps.RxBytes = rt.Peers[i].RxBytes
			ps.TxBytes = rt.Peers[i].TxBytes
		}
		ts.Peers = append(ts.Peers, ps)
	}
	return ts
}

// ruleStatus builds the status of rule i of s.Cfg with its decision from
// s.Rules (none: neither on a tunnel nor in fallback) and its Reason.
func ruleStatus(s *State, i int) RuleStatus {
	r := s.Cfg.Rules[i]
	rs := RuleStatus{
		Index:    i,
		Services: append([]string{}, r.Services...),
		Via:      append([]string{}, r.Via...),
		Fallback: string(r.Fallback),
	}
	if i < len(s.Rules) {
		rs.Tunnel = s.Rules[i].Tunnel
		rs.InFallback = s.Rules[i].Fallback
	}
	rs.Degraded = len(r.Via) > 0 && rs.Tunnel != r.Via[0]
	rs.Reason = ruleReason(s, i)
	return rs
}

// ruleReason returns Reason of rule i of s.Cfg (design 14; plan M3,
// decision 6): "" unless the rule is degraded (in fallback, or with via and
// not on via[0]). Paused: "paused". Otherwise, among the via tunnels above
// the serving one (all of via in fallback): one switched on (Switches) but
// dead, failed or not up gives "dead"; else (all switched off) "disabled".
func ruleReason(s *State, i int) string {
	via := s.Cfg.Rules[i].Via
	var serving string
	if i < len(s.Rules) {
		serving = s.Rules[i].Tunnel
	}
	if len(via) == 0 || serving == via[0] {
		return ""
	}
	if s.Paused {
		return "paused"
	}
	above := via
	if k := slices.Index(via, serving); serving != "" && k >= 0 {
		above = via[:k]
	}
	for _, name := range above {
		if s.Switches[name] {
			return "dead"
		}
	}
	return "disabled"
}

// Explain explains q (a domain or an IP); an invalid q is a jrpc Invalid params error.
// A domain goes through dns.Choose with s.Rules and s.Ifaces (design 7.4, 8),
// its Addrs come from s.Pairs. An IP gets the longest-prefix route of s.Table,
// with Skipped from s.Skips and, for a dynamic route, Names from s.Pairs; a
// tunnel route without a utun is shown as "reject", as in RoutesOf.
func Explain(s *State, q string) (Explanation, error) {
	q = strings.TrimSpace(q)
	if a, err := netip.ParseAddr(q); err == nil && a.Zone() == "" {
		return explainIP(s, a.Unmap()), nil
	}
	name := strings.TrimSuffix(strings.ToLower(q), ".")
	if !validDomain(name) {
		return Explanation{}, jrpc.NewErrorInvalidParams(nil)
	}
	return explainDomain(s, name), nil
}

// explainDomain explains the normalized domain name.
func explainDomain(s *State, name string) Explanation {
	e := Explanation{Query: name, Kind: "domain", Upstream: "system"}
	for _, p := range s.Pairs {
		if p.Name == name {
			e.Addrs = append(e.Addrs, p.Addr.String())
		}
	}
	cfg := s.Cfg
	if cfg == nil {
		return e
	}
	c := dns.Choose(cfg, s.Rules, s.Ifaces, name)
	if c.Rule >= 0 {
		rs := ruleStatus(s, c.Rule)
		e.Rule = &rs
	}
	// The best match by domain alone, passed over by Choose because it is
	// in fallback: default.
	if i, ok := cfg.MatchDomain(name); ok && i != c.Rule && i < len(s.Rules) &&
		s.Rules[i].Fallback && cfg.Rules[i].Fallback == config.FallbackDefault {
		rs := ruleStatus(s, i)
		e.Skipped = &rs
	}
	switch {
	case c.Block:
		e.Upstream = "block"
	case c.Tunnel != "":
		e.Upstream = c.Tunnel
		t := findTunnel(cfg, c.Tunnel)
		if t == nil {
			break
		}
		for _, a := range dns.Servers(t) {
			e.Servers = append(e.Servers, a.String())
		}
		if c.Rule < 0 {
			e.Zone = zoneOf(t, name)
		}
	}
	e.DropAAAA = c.DropAAAA
	return e
}

// explainIP explains the address a (unmapped).
func explainIP(s *State, a netip.Addr) Explanation {
	e := Explanation{Query: a.String(), Kind: "ip"}
	best := -1
	for i, r := range s.Table {
		if r.Prefix.Contains(a) && (best < 0 || r.Prefix.Bits() > s.Table[best].Prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return e
	}
	ri := routeInfo(s, s.Table[best])
	e.Route = &ri
	if r := s.Table[best].Rule; r >= 0 && s.Cfg != nil && r < len(s.Cfg.Rules) {
		rs := ruleStatus(s, r)
		e.Rule = &rs
	}
	return e
}

// RoutesOf builds the diag.routes reply: s.Table by prefix, Names of dynamic
// routes from s.Pairs, Skipped from s.Skips, SyncError from s.SyncErr. A
// TargetTunnel route of a tunnel without a utun index in s.Ifaces (starting
// or failed) is shown as Target "reject" with its Tunnel kept: so it is in
// the kernel. Explain shows an IP route the same way.
func RoutesOf(s *State) Routes {
	res := Routes{Routes: make([]RouteInfo, 0, len(s.Table))}
	for _, r := range s.Table {
		res.Routes = append(res.Routes, routeInfo(s, r))
	}
	if s.SyncErr != nil {
		res.SyncError = s.SyncErr.Error()
	}
	return res
}

// routeInfo converts r, with Names and Skipped from s.
func routeInfo(s *State, r router.Route) RouteInfo {
	ri := RouteInfo{
		Prefix: r.Prefix.String(),
		Target: string(r.Target),
		Tunnel: r.Tunnel,
		Source: string(r.Source),
		Rule:   r.Rule,
	}
	if r.Target == router.TargetTunnel && s.Ifaces[r.Tunnel] <= 0 {
		ri.Target = string(router.TargetReject)
	}
	if r.Source == router.SourceDynamic && r.Prefix.IsSingleIP() {
		for _, p := range s.Pairs {
			if p.Addr == r.Prefix.Addr() {
				ri.Names = append(ri.Names, p.Name)
			}
		}
	}
	for _, sk := range s.Skips {
		if sk.Route.Prefix == r.Prefix {
			ri.Skipped = sk.Reason
			break
		}
	}
	return ri
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

// zoneOf returns the longest dns_domains zone of t that name (normalized)
// is in; "": none.
func zoneOf(t *config.Tunnel, name string) string {
	var best string
	for _, z := range t.DNSDomains {
		if len(z.Name) > len(best) && (name == z.Name || strings.HasSuffix(name, "."+z.Name)) {
			best = z.Name
		}
	}
	return best
}

// validDomain reports whether name (lowercase, no trailing dot) is a domain
// name: labels of 1–63 letters, digits, '-' or '_', 253 bytes at most.
func validDomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
