package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/health"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/rpc"
	"github.com/mrFokin/wgplex/internal/state"
	"github.com/mrFokin/wgplex/internal/tunnel"
)

const (
	// resolveTimeout bounds resolving the endpoints of all the tunnels one
	// call brings up: they are resolved in parallel, well within the 60 s
	// of the CLI.
	resolveTimeout = 10 * time.Second
	expireEvery    = time.Minute    // how often expired dynamic addresses are dropped
	dnsAddr        = "127.0.0.1:53" // the resolver of the daemon (design 8)
)

// errStopping is the error of a mutating call after shutdown has begun; the
// client gets it as Internal error.
var errStopping = errors.New("wgplex daemon is stopping")

// daemon is the state of the wgplex daemon and the system calls on it (manual check
// only). opMu orders the mutating calls (apply, SetEnabled, DisableAll,
// expire, the health tick, netwatch events, shutdown); mu guards the state
// and Sync, which the resolver calls too (Server.Sync). Lock order: opMu → mu → Server.mu. Endpoints are
// resolved under opMu without mu, so DNS answers do not wait for them. mu is
// always released by defer, so a panic under it does not hang the daemon.
//
// A tunnel is enabled when it is in tunnels: running (tun set), being
// brought up (starting) or failed (err set). A tunnel that is not running is
// Up but not Alive for the router: its AllowedIPs become reject and rules
// pass it over.
//
// Every endpoint host route of ours is in hosts until DeleteHost; syncNow
// puts all of them into the table as endpoint routes, so Sync never removes
// one of a tunnel being brought up or stopped.
type daemon struct {
	opMu     sync.Mutex
	closed   bool // under opMu: shutdown has begun, mutating calls fail
	captured bool // under opMu: the DNS capture succeeded and is not released
	// toggles (under opMu) are the explicit tunnel toggles of state.json
	// (design 11), written to statePath.
	toggles state.State
	// stateDirty (under opMu): the last write of toggles failed, so the
	// next toggle writes even when unchanged, and the warning stateWarning
	// stays in warnings (across replan too) until a write succeeds.
	stateDirty   bool
	stateWarning string
	mu           sync.Mutex

	ctx       context.Context // done at stop: endpoint resolving gives up
	srv       *dns.Server
	log       *slog.Logger
	dir       string        // the config directory (config.LoadDir)
	statePath string        // state.json
	logFile   *rotatingFile // nil: not logging to a file; its group follows control_group

	// Under mu.
	cfg       *config.Config // nil: no config applied yet
	warnings  []string       // of cfg
	cfgErrs   []string       // of the last failed apply; nil after a successful one
	tunnels   map[string]*runTunnel
	hosts     map[netip.Addr]*hostRoute
	gws       map[bool]router.Gateway // by ipv6, cached once looked up without error
	system    []netip.Addr            // the system DNS servers last read without error
	primary   string                  // the primary service last read without error
	rules     []router.RuleState
	env       router.Env
	table     router.Table // the last synced table
	skips     []router.Skip
	syncErr   error
	synced    bool // Sync has run: there may be routes of ours to remove
	healthOff bool // the last health tick found no network (offline)
}

// runTunnel is an enabled tunnel.
type runTunnel struct {
	name      string
	tun       *tunnel.Tunnel   // nil: not running
	starting  bool             // tun nil: being brought up
	err       string           // tun nil, not starting: why it failed to start
	endpoints []netip.AddrPort // resolved, index = peer index
	addrs     []netip.Addr     // valid endpoint addresses, each with a host route in hosts
	index     int              // utun interface index; 0: unknown
	health    health.Health    // tun set: the verdict (design 9)
	check     string           // tun set: the check made (activeCheck), address or URL; "": none
	checker   health.Checker   // of check; nil: none or failed to open
	// resolvedAt: tun set, the endpoints were last resolved (design 6: a
	// dead tunnel resolves its host names again reresolveEvery after it).
	resolvedAt time.Time
	failedAt   time.Time // err set: when it failed (retryEvery)
}

// hostRoute is the host route of an endpoint: the tunnel that put it in
// place (for logs), whether AddHost added it (false: on-link, nothing
// added), the gateway it was added with, whether moving it to a new gateway
// failed (rehost tries again) and the number of running tunnels using it.
type hostRoute struct {
	tunnel string
	set    bool
	gw     router.Gateway
	failed bool
	refs   int
}

var _ rpc.Daemon = (*daemon)(nil)

// newDaemon returns a daemon with no config; srv is the resolver, its Sync
// is set here. dir is the config directory, statePath the state.json the
// toggles were loaded from, logFile the log (nil: none).
func newDaemon(ctx context.Context, srv *dns.Server, log *slog.Logger, dir, statePath string, toggles state.State, logFile *rotatingFile) *daemon {
	d := &daemon{
		ctx:       ctx,
		srv:       srv,
		log:       log,
		dir:       dir,
		statePath: statePath,
		toggles:   toggles,
		logFile:   logFile,
		tunnels:   map[string]*runTunnel{},
		hosts:     map[netip.Addr]*hostRoute{},
		gws:       map[bool]router.Gateway{},
	}
	// Sync before a DNS answer with new addresses, from the resolver's
	// goroutines (not under the resolver's lock: syncNow calls Dynamic).
	srv.Sync = func() error {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.syncNow()
	}
	return d
}

// setSystem reads the system DNS servers and passes them to the resolver;
// on an error the old ones stay. It also records the primary service for
// networkChanged. Returns whether there are servers now.
func (d *daemon) setSystem() bool {
	s, err := dns.SystemServers()
	primary, perr := dns.PrimaryService()
	d.mu.Lock()
	defer d.mu.Unlock()
	if perr != nil {
		d.log.Warn("primary network service", "err", perr)
	} else {
		d.primary = primary
	}
	if err != nil {
		d.log.Warn("system DNS servers: keeping the old ones", "err", err, "old", d.system)
	} else {
		d.log.Info("system DNS servers", "servers", s)
		d.system = s
		d.srv.SetSystem(s)
	}
	return len(d.system) > 0
}

// locked runs f under mu; mu is released even if f panics.
func (d *daemon) locked(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f()
}

// Reload is config.reload: the config directory is read and applied again
// (design 10.2).
func (d *daemon) Reload() (rpc.ApplyResult, error) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return rpc.ApplyResult{}, errStopping
	}
	return d.apply()
}

// startup applies the config at start, before the RPC (design 4.1, 10.2).
// With an invalid config the daemon runs without tunnels: the table is synced
// empty, so the routes of the previous run go away, and the DNS capture key
// of the previous run is released. Nothing is removed beforehand: a valid
// config replaces the leftovers by its own sync.
func (d *daemon) startup() {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if _, err := d.apply(); err == nil {
		return
	}
	d.locked(d.sync)
	if err := releaseDNS(d.log); err != nil {
		// As if captured: the next apply without domains retries.
		d.addWarning("DNS release failed: " + err.Error())
		d.captured = true
	} else {
		d.captured = false
	}
}

// apply reads the config directory (config.LoadDir) and applies it. An
// invalid config is the CodeConfigInvalid error: the previous config keeps
// running, its errors go to status.get. opMu is held.
func (d *daemon) apply() (rpc.ApplyResult, error) {
	next, warnings, err := config.LoadDir(d.dir)
	if warnings == nil {
		warnings = []string{}
	}
	if err != nil {
		errs := errorList(err)
		d.locked(func() { d.cfgErrs = errs })
		for _, e := range errs {
			d.log.Error("config apply", "err", e)
		}
		for _, w := range warnings {
			d.log.Warn("config", "warning", w)
		}
		return rpc.ApplyResult{}, jrpc.NewError(rpc.CodeConfigInvalid, "config is invalid",
			rpc.ConfigErrorData{Errors: errs, Warnings: warnings})
	}
	warnings = append(warnings, blockedDNSWarnings(next)...)
	warnings = append(warnings, checkWarnings(next)...)
	for _, w := range warnings {
		d.log.Warn("config", "warning", w)
	}
	d.log.Info("config apply", "tunnels", len(next.Tunnels), "rules", len(next.Rules))

	// The network may have changed since the last apply.
	// Reading the new values would hide the change from the Network event
	// to come, so a changed network gets the reaction of
	// onNetwork here: renetwork, which also reads them; the failed tunnels
	// are brought up and the rules selected by the apply itself. The first
	// apply has nothing running to react with.
	var configured bool
	d.locked(func() { configured = d.cfg != nil })
	if configured && d.networkChanged() {
		d.renetwork(false)
	} else {
		d.setSystem()
	}
	var hasSystem bool
	d.locked(func() { hasSystem = len(d.system) > 0 })

	// The endpoints are resolved before replan: a tunnel to be restarted
	// keeps running meanwhile instead of standing in starting.
	planned := d.toStart(next)
	endpoints, errs := d.resolve(planned)
	// The config is applied (nothing below fails): the toggles of tunnels
	// gone from it are dropped (design 11). Before replan: they do not
	// change its plan, and a toggle write still failing keeps its warning in
	// the new warnings.
	if d.toggles.Prune(tunnelNames(next)) || d.stateDirty {
		d.saveToggles()
	}
	warnings = d.withStateWarning(warnings)
	start := d.replan(next, warnings)
	if !sameTunnels(planned, start) { // cannot happen: opMu is held
		endpoints, errs = d.resolve(start)
	}
	res := rpc.ApplyResult{Warnings: slices.Clone(warnings)} // d.warnings is shared with State
	d.setLogGroup(next.ControlGroup)
	started := map[string]bool{}
	for i, t := range start {
		started[t.Name] = true
		// Each tunnel gets its Ifaces and rules as soon as it is up.
		if err := d.up(t, endpoints[i], errs[i], false); err != nil {
			res.Tunnels = append(res.Tunnels, rpc.TunnelError{Name: t.Name, Error: err.Error()})
		}
	}
	d.locked(func() {
		for _, t := range next.Tunnels {
			if rt := d.tunnels[t.Name]; rt != nil && rt.tun != nil && !started[t.Name] {
				addScoped(d.log, &t, rt.index) // the routes may be gone with a network change
				if activeCheck(&t) != rt.check {
					// The check changed without a restart: its verdict
					// starts over. The scoped route to the old check stays
					// until the tunnel stops:
					// the utun is ours, the route harms nothing.
					rt.health = health.New(time.Now())
					d.setChecker(&t, rt)
				}
			}
		}
		d.reselect(nil)
		d.logOverlaps()
	})

	// The system DNS is captured only when the config has domains. Without
	// them the key is released when captured or present in the system: a key
	// left by a previous config or a previous run goes too (design 4.1). An
	// absent key is left alone: Release would flush the mDNSResponder cache
	// on every reload.
	switch {
	case !next.NeedsDNS():
		if !d.captured {
			present, err := dns.Captured()
			if err == nil && !present {
				d.log.Debug("dns release: no domains in config, no key")
				break
			}
			if err != nil {
				d.log.Warn("dns capture key", "err", err) // released to be sure
			}
		}
		d.log.Debug("dns release: no domains in config")
		if err := releaseDNS(d.log); err != nil {
			// captured stays: the next apply without domains retries.
			w := "DNS release failed: " + err.Error()
			res.Warnings = append(res.Warnings, w)
			d.addWarning(w)
		} else {
			d.captured = false
		}
	case !hasSystem:
		d.log.Warn("no system DNS servers: DNS not captured")
	default:
		// Also puts the key back if configd lost it (the 30 s key check watches for that, design 8).
		if err := captureDNS(d.log); err != nil {
			d.log.Error("dns capture", "err", err)
			w := "DNS capture failed: " + err.Error()
			res.Warnings = append(res.Warnings, w)
			d.addWarning(w) // shown by status.get too
		} else {
			d.captured = true
		}
	}
	return res, nil
}

// addWarning adds w to the warnings of the applied config shown by
// status.get, unless they already have it. Replaced, not appended to in
// place: a State snapshot may hold the old slice.
func (d *daemon) addWarning(w string) {
	d.locked(func() {
		if !slices.Contains(d.warnings, w) {
			d.warnings = append(slices.Clone(d.warnings), w)
		}
	})
}

// removeWarning drops w from the warnings shown by status.get.
func (d *daemon) removeWarning(w string) {
	d.locked(func() {
		if slices.Contains(d.warnings, w) {
			d.warnings = slices.DeleteFunc(slices.Clone(d.warnings), func(x string) bool { return x == w })
		}
	})
}

// withStateWarning returns warnings with the warning of the failed write of
// state.json while it is unsaved (stateDirty): the warnings of a new config
// keep it. opMu is held.
func (d *daemon) withStateWarning(warnings []string) []string {
	if !d.stateDirty || slices.Contains(warnings, d.stateWarning) {
		return warnings
	}
	return append(warnings, d.stateWarning)
}

// setToggle records the explicit toggle of name and writes state.json when
// it changed or the last write failed (design 11). Returns the warning of a
// failed write ("": none). opMu is held.
func (d *daemon) setToggle(name string, on bool) string {
	if v, ok := d.toggles.Tunnels[name]; ok && v == on && !d.stateDirty {
		return ""
	}
	if d.toggles.Tunnels == nil {
		d.toggles.Tunnels = map[string]bool{}
	}
	d.toggles.Tunnels[name] = on
	return d.saveToggles()
}

// saveToggles writes state.json. A failure does not undo the action: it is a
// warning in the log and in status.get, returned ("": saved), and sets
// stateDirty; a successful write clears it and its warning. opMu is held.
func (d *daemon) saveToggles() string {
	err := d.toggles.Save(d.statePath, -1)
	if err == nil {
		if d.stateDirty {
			d.removeWarning(d.stateWarning)
			d.stateDirty, d.stateWarning = false, ""
		}
		return ""
	}
	d.log.Warn("state not saved", "err", err)
	w := "state not saved: " + err.Error()
	if d.stateDirty && w != d.stateWarning {
		d.removeWarning(d.stateWarning)
	}
	d.stateDirty, d.stateWarning = true, w
	d.addWarning(w)
	return w
}

// setLogGroup gives the log file the group control_group of the applied
// config (design 15); a failure is a warning in the log. opMu is held.
func (d *daemon) setLogGroup(group string) {
	if d.logFile == nil {
		return
	}
	gid, err := groupID(group)
	if err == nil {
		err = d.logFile.SetGroup(gid)
	}
	if err != nil {
		d.log.Warn("log group", "group", group, "err", err)
	}
}

// tunnelNames returns the names of the tunnels of cfg.
func tunnelNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		names = append(names, t.Name)
	}
	return names
}

// toStart returns the tunnels replan would start for next now (planApply
// under mu), in next's order. opMu is held.
func (d *daemon) toStart(next *config.Config) []*config.Tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _, start := planApply(d.cfg, next, d.toggles.Tunnels, d.running())
	var ts []*config.Tunnel
	for _, name := range start {
		ts = append(ts, findTunnel(next, name))
	}
	return ts
}

// running returns the enabled tunnels with whether each is running, for
// planApply. mu is held.
func (d *daemon) running() map[string]bool {
	running := map[string]bool{}
	for name, rt := range d.tunnels {
		running[name] = rt.tun != nil
	}
	return running
}

// sameTunnels reports whether a and b name the same tunnels in the same order.
func sameTunnels(a, b []*config.Tunnel) bool {
	return slices.EqualFunc(a, b, func(x, y *config.Tunnel) bool { return x.Name == y.Name })
}

// replan switches the state to next (planApply): stops the tunnels it
// stops, drops the failed ones it disables, marks the ones it starts as
// starting, selects the rules from scratch and syncs. Returns the tunnels
// to start, in next's order. opMu is held.
func (d *daemon) replan(next *config.Config, warnings []string) []*config.Tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.gws)
	d.rehost()
	nextEnabled, stop, start := planApply(d.cfg, next, d.toggles.Tunnels, d.running())
	var stopped []*runTunnel
	for _, name := range stop {
		stopped = append(stopped, d.tunnels[name])
		delete(d.tunnels, name)
	}
	for name := range d.tunnels {
		if !nextEnabled[name] {
			delete(d.tunnels, name) // failed, not running: nothing to stop
		}
	}
	var ts []*config.Tunnel
	for _, name := range start {
		d.tunnels[name] = &runTunnel{name: name, starting: true}
		ts = append(ts, findTunnel(next, name))
	}
	d.cfg, d.warnings, d.cfgErrs = next, warnings, nil
	d.reselect(nil)
	d.closeTunnels(stopped)
	return ts
}

// SetEnabled is tunnel.setEnabled.
func (d *daemon) SetEnabled(name string, enabled bool) error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return errStopping
	}
	t, err := d.toggle(name, enabled)
	if err != nil {
		return err
	}
	// Remembered across restarts even if t fails to come up (design 11).
	d.setToggle(name, enabled)
	// t stays enabled even when it fails to come up (design 10.2).
	if t == nil {
		return nil
	}
	endpoints, errs := d.resolve([]*config.Tunnel{t})
	if err := d.up(t, endpoints[0], errs[0], true); err != nil {
		return jrpc.NewError(rpc.CodeTunnelStart, fmt.Sprintf("tunnel %s: %v", name, err), nil)
	}
	return nil
}

// Enable is tunnel.enable (design 12, 14): the toggle on in state.json, the
// tunnel brought up unless paused. A tunnel in "error" is brought up again.
// Paused: nothing is brought up, StartsOnResume true. Without a config:
// CodeNoConfig; unknown name: CodeUnknownTunnel; failed to start:
// CodeTunnelStart.
func (d *daemon) Enable(name string) (rpc.EnableResult, error) {
	panic("not implemented")
}

// Disable is tunnel.disable: the toggle off in state.json, the tunnel
// stopped. Without a config: CodeNoConfig; unknown name: CodeUnknownTunnel.
func (d *daemon) Disable(name string) error {
	panic("not implemented")
}

// Pause is daemon.pause (design 12), idempotent, also without a config:
// paused in state.json, every tunnel of the config stopped with the toggles
// kept, the rules reselected (into fallback), one Sync. The DNS capture stays.
func (d *daemon) Pause() error {
	panic("not implemented")
}

// Resume is daemon.resume (design 12), idempotent, also without a config:
// paused cleared in state.json, the tunnels brought up by the toggles and
// autostart, as planApply does.
func (d *daemon) Resume() error {
	panic("not implemented")
}

// effectiveCfg returns the config the table, the rules and the DNS capture
// work from (mu held): d.cfg or, while it is nil, the synthetic config of
// the block snapshot (blockConfig); nil: neither. Readers that must see
// "no config applied" (toggle, DisableAll, snapshot, planApply, health)
// keep d.cfg (plan M3, spike facts).
func (d *daemon) effectiveCfg() *config.Config {
	panic("not implemented")
}

// blockConfig builds from the block snapshot b (design 9.1) a synthetic
// config without tunnels: one service with the CIDRs and the domains of b,
// one rule with fallback: block whose via is a tunnel that does not exist, and
// its RuleState{Fallback: true}. The table then gets reject routes on the
// CIDRs and the resolver answers NODATA for the domains. b nil or empty: nil, nil.
func blockConfig(b *state.Block) (*config.Config, []router.RuleState) {
	panic("not implemented")
}

// toggle is the part of SetEnabled under mu: it checks the config and the
// name, then disables the tunnel, or marks it as starting and returns it to
// be brought up (nil: nothing more to do).
func (d *daemon) toggle(name string, enabled bool) (*config.Tunnel, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return nil, jrpc.NewError(rpc.CodeNoConfig, "no config applied", nil)
	}
	t := findTunnel(d.cfg, name)
	if t == nil {
		return nil, jrpc.NewError(rpc.CodeUnknownTunnel, fmt.Sprintf("unknown tunnel %q", name), nil)
	}
	rt := d.tunnels[name]
	if !enabled {
		if rt != nil {
			delete(d.tunnels, name)
			d.log.Info("tunnel disabled", "tunnel", name)
			d.reselect(d.rules)
			d.closeTunnels([]*runTunnel{rt})
			d.sync() // the table without its endpoint routes; no ops
		}
		return nil, nil
	}
	if rt != nil && rt.tun != nil {
		return nil, nil // running
	}
	d.log.Info("tunnel enabled", "tunnel", name)
	d.tunnels[name] = &runTunnel{name: name, starting: true}
	d.reselect(d.rules)
	return t, nil
}

// DisableAll is tunnel.disableAll: SetEnabled false for every tunnel of the
// config with one Sync and one write of state.json (design 11, 12); the DNS
// capture stays. Without a config: CodeNoConfig.
func (d *daemon) DisableAll() error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return errStopping
	}
	var names []string
	d.locked(func() {
		if d.cfg == nil {
			return
		}
		names = tunnelNames(d.cfg)
		if len(d.tunnels) == 0 {
			return
		}
		var stopped []*runTunnel
		for _, t := range d.cfg.Tunnels {
			if rt := d.tunnels[t.Name]; rt != nil {
				stopped = append(stopped, rt)
			}
		}
		clear(d.tunnels)
		d.log.Info("all tunnels disabled")
		d.reselect(d.rules)
		d.closeTunnels(stopped)
		d.sync() // the table without their endpoint routes; no ops
	})
	if names == nil {
		return jrpc.NewError(rpc.CodeNoConfig, "no config applied", nil)
	}
	changed := false
	for _, name := range names {
		if v, ok := d.toggles.Tunnels[name]; !ok || v {
			changed = true
		}
		if d.toggles.Tunnels == nil {
			d.toggles.Tunnels = map[string]bool{}
		}
		d.toggles.Tunnels[name] = false
	}
	if changed || d.stateDirty {
		d.saveToggles()
	}
	return nil
}

// State returns a snapshot for status.get and diag.*, peer stats included.
func (d *daemon) State() *rpc.State {
	s := d.snapshot()
	s.Pairs = d.srv.Pairs()
	return s
}

// snapshot is State without the dynamic pairs, taken under mu.
func (d *daemon) snapshot() *rpc.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := &rpc.State{
		Cfg:          d.cfg,
		Warnings:     d.warnings,
		ConfigErrors: d.cfgErrs,
		Tunnels:      make(map[string]rpc.TunnelRuntime, len(d.tunnels)),
		Rules:        slices.Clone(d.rules),
		Table:        d.table, // replaced, never modified in place
		Skips:        d.skips,
		SyncErr:      d.syncErr,
		Ifaces:       maps.Clone(d.env.Ifaces),
	}
	for name, rt := range d.tunnels {
		tr := rpc.TunnelRuntime{Err: rt.err, Starting: rt.starting, Endpoints: rt.endpoints}
		if rt.tun != nil {
			tr.Interface = rt.tun.Interface()
			tr.Dead, tr.Reason = rt.health.State == health.Dead, rt.health.Reason
			if rt.check != "" {
				tr.Check = &rpc.CheckStatus{
					Addr:   rt.check,
					LastOK: rt.health.LastOK,
					RTTMs:  float64(rt.health.RTT) / float64(time.Millisecond),
					Fails:  rt.health.Fails,
				}
			}
			if t := findTunnel(d.cfg, name); t != nil {
				peers, err := rt.tun.Stats(t.WG.Peers)
				if err != nil {
					d.log.Warn("tunnel stats", "tunnel", name, "err", err)
				}
				tr.Peers = peers
			}
		}
		s.Tunnels[name] = tr
	}
	return s
}

// expire drops expired dynamic addresses and syncs when some were dropped.
func (d *daemon) expire(now time.Time) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed || !d.srv.Expire(now) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sync()
}

// shutdown releases DNS, shuts the resolver down, removes routes, closes
// tunnels and removes endpoint host routes. It waits for a mutating call in
// progress; mutating calls after it fail with errStopping.
func (d *daemon) shutdown() {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return
	}
	d.closed = true

	// The capture goes first: the system DNS must not point at a resolver
	// that is gone. Released even if never captured (a crash leftover); a
	// failure is logged, nothing more can be done.
	_ = releaseDNS(d.log)
	if err := d.srv.Shutdown(); err != nil {
		d.log.Warn("dns server shutdown", "err", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// All our routes but the endpoint ones: those go with DeleteHost.
	// Before the first Sync there are none.
	if d.synced {
		d.syncTable(endpointRoutes(d.table), router.Env{})
	}
	var all []*runTunnel
	if d.cfg != nil {
		for _, t := range d.cfg.Tunnels {
			if rt := d.tunnels[t.Name]; rt != nil {
				all = append(all, rt)
			}
		}
	}
	clear(d.tunnels)
	d.closeTunnels(all)
}

// resolve resolves the endpoints of ts (index = index in ts) in parallel,
// all within one resolveTimeout, without mu: DNS answers do not wait for it.
// Resolving gives up when the daemon stops.
func (d *daemon) resolve(ts []*config.Tunnel) ([][]netip.AddrPort, []error) {
	var resolver tunnel.Resolver = net.DefaultResolver // not captured without system servers
	var servers []netip.Addr                           // the servers of resolver; nil for net.DefaultResolver
	d.locked(func() {
		if len(d.system) > 0 {
			servers = d.system
			resolver = dns.SystemResolver(servers) // past our own resolver (design 6)
		}
	})
	ctx, cancel := context.WithTimeout(d.ctx, resolveTimeout)
	defer cancel()
	endpoints := make([][]netip.AddrPort, len(ts))
	errs := make([]error, len(ts))
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Go(func() {
			endpoints[i], errs[i] = tunnel.ResolveEndpoints(ctx, resolver, t.WG.Peers)
			if errs[i] != nil {
				// The servers asked, not the resolv.conf one Go names.
				errs[i] = fmt.Errorf("resolve endpoints: %w", dns.SystemError(errs[i], servers))
			}
		})
	}
	wg.Wait()
	return endpoints, errs
}

// up brings t up with its resolved endpoints (rerr: resolving failed): adds
// the host routes, starts t and adds the scoped routes to its DNS servers.
// The starting entry of t in tunnels becomes the running tunnel or gets the
// error; t stays enabled either way. Then the rules are
// selected again (keepRules: from the current ones, else from scratch) and
// the table is synced, so t gets its Ifaces and rules at once. Takes mu.
func (d *daemon) up(t *config.Tunnel, endpoints []netip.AddrPort, rerr error, keepRules bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rt := d.tunnels[t.Name]
	if rt == nil { // cannot happen: opMu is held since the entry was added
		rt = &runTunnel{}
		d.tunnels[t.Name] = rt
	}
	err := rerr
	if err == nil {
		err = d.start(t, endpoints, rt)
	}
	if err != nil {
		*rt = runTunnel{name: t.Name, err: err.Error(), failedAt: time.Now()}
		d.log.Error("tunnel", "tunnel", t.Name, "err", err)
	}
	var prev []router.RuleState
	if keepRules {
		prev = d.rules
	}
	d.reselect(prev)
	return err
}

// start adds the host routes to endpoints, starts t and fills rt; on failure
// it removes the host routes it added. mu is held.
func (d *daemon) start(t *config.Tunnel, endpoints []netip.AddrPort, rt *runTunnel) error {
	var addrs []netip.Addr
	for _, ep := range endpoints {
		if a := ep.Addr(); a.IsValid() && !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	var mine []netip.Addr
	for _, a := range addrs {
		if err := d.addHost(t.Name, a); err != nil {
			d.releaseHosts(mine)
			return fmt.Errorf("host route: %w", err)
		}
		mine = append(mine, a)
	}
	tun, err := tunnel.Start(t.Name, &t.WG, endpoints, d.log)
	if err != nil {
		d.releaseHosts(mine)
		return err // "utunN: ...": the caller adds the tunnel name
	}
	now := time.Now()
	*rt = runTunnel{name: t.Name, tun: tun, endpoints: endpoints, addrs: addrs, health: health.New(now), resolvedAt: now}
	if ifi, err := net.InterfaceByName(tun.Interface()); err != nil {
		d.log.Warn("tunnel interface", "tunnel", t.Name, "err", err)
	} else {
		rt.index = ifi.Index
	}
	d.log.Info("tunnel up", "tunnel", t.Name, "utun", tun.Interface())
	addScoped(d.log, t, rt.index)
	d.setChecker(t, rt)
	return nil
}

// closeTunnels closes the running tunnels of ts and releases their host
// routes; their routes must already be gone from the table (reselect).
// mu is held.
func (d *daemon) closeTunnels(ts []*runTunnel) {
	for _, rt := range ts {
		if rt.checker != nil {
			rt.checker.Close()
			rt.checker = nil
		}
		if rt.tun == nil {
			continue
		}
		rt.tun.Close()
		d.log.Info("tunnel down", "tunnel", rt.name, "utun", rt.tun.Interface())
		d.releaseHosts(rt.addrs)
	}
}

// addHost adds a reference to the host route to a, adding the route for the
// first one. mu is held.
func (d *daemon) addHost(name string, a netip.Addr) error {
	if h := d.hosts[a]; h != nil {
		h.refs++
		return nil
	}
	gw, err := d.gateway(a.Is6())
	var set bool
	if err == nil {
		set, err = router.AddHost(a, gw)
	}
	if err != nil {
		return err
	}
	d.hosts[a] = &hostRoute{tunnel: name, set: set, gw: gw, refs: 1}
	logHostRoute(d.log, name, a, gw, set)
	return nil
}

// releaseHosts drops a reference to the host routes to addrs, removing a
// route when no running tunnel uses it. mu is held.
func (d *daemon) releaseHosts(addrs []netip.Addr) {
	for _, a := range addrs {
		h := d.hosts[a]
		if h == nil {
			continue
		}
		if h.refs--; h.refs > 0 {
			continue
		}
		delete(d.hosts, a)
		// DeleteHost removes only our route: nothing for an on-link endpoint.
		if err := router.DeleteHost(a); err != nil {
			d.log.Warn("delete host route", "tunnel", h.tunnel, "dst", a, "err", err)
		} else if h.set {
			d.log.Info("host route deleted", "tunnel", h.tunnel, "dst", a)
		}
	}
}

// reendpoint switches the running rt to the endpoints resolved again for
// its tunnel t (design 6, DDNS): for every peer whose endpoint differs, a
// host route to the new address (addHost), the endpoint of the device
// (SetEndpoint), the host route to the old address released when no other
// peer of rt uses it; rt.endpoints and rt.addrs follow. A failure of addHost
// or SetEndpoint is logged and the peer keeps its old endpoint. Returns
// whether some endpoint changed: the caller starts a handshake and syncs.
// mu is held.
func (d *daemon) reendpoint(t *config.Tunnel, rt *runTunnel, endpoints []netip.AddrPort) bool {
	changed := false
	for i, ep := range endpoints {
		if i >= len(rt.endpoints) || i >= len(t.WG.Peers) || !ep.IsValid() || ep == rt.endpoints[i] {
			continue
		}
		old, a := rt.endpoints[i], ep.Addr()
		added := false
		if !slices.Contains(rt.addrs, a) {
			if err := d.addHost(t.Name, a); err != nil {
				d.log.Warn("endpoint changed: host route failed, keeping the old address", "tunnel", t.Name, "peer", i+1, "was", old, "now", ep, "err", err)
				continue
			}
			added = true
		}
		if err := rt.tun.SetEndpoint(t.WG.Peers[i].PublicKey, ep); err != nil {
			if added {
				d.releaseHosts([]netip.Addr{a})
			}
			d.log.Warn("endpoint changed: keeping the old address", "tunnel", t.Name, "peer", i+1, "was", old, "now", ep, "err", err)
			continue
		}
		// Replaced, not modified in place: a State snapshot may hold them.
		rt.endpoints = slices.Clone(rt.endpoints)
		rt.endpoints[i] = ep
		if added {
			rt.addrs = append(slices.Clone(rt.addrs), a)
		}
		if oa := old.Addr(); oa.IsValid() && oa != a && !slices.ContainsFunc(rt.endpoints, func(e netip.AddrPort) bool { return e.Addr() == oa }) {
			d.releaseHosts([]netip.Addr{oa})
			rt.addrs = slices.DeleteFunc(slices.Clone(rt.addrs), func(x netip.Addr) bool { return x == oa })
		}
		d.log.Info("endpoint changed", "tunnel", t.Name, "peer", i+1, "was", old, "now", ep)
		changed = true
	}
	return changed
}

// rehost moves the endpoint host routes whose gateway has changed and tries
// again the ones that failed before. mu is held.
func (d *daemon) rehost() {
	for a, h := range d.hosts {
		gw, err := d.gateway(a.Is6())
		if err != nil {
			d.log.Warn("default gateway", "dst", a, "err", err)
			continue
		}
		if gw == h.gw && !h.failed {
			continue
		}
		set, err := router.AddHost(a, gw) // replaces our old route
		if err != nil {
			d.log.Error("host route", "tunnel", h.tunnel, "dst", a, "err", err)
			h.failed = true
			continue
		}
		h.set, h.gw, h.failed = set, gw, false
		logHostRoute(d.log, h.tunnel, a, gw, set)
	}
}

// gateway returns the physical gateway; a lookup error is returned, while
// "no gateway" (zero Gateway) means a blackhole route. mu is held.
func (d *daemon) gateway(ipv6 bool) (router.Gateway, error) {
	if gw, ok := d.gws[ipv6]; ok {
		return gw, nil
	}
	gw, err := router.DefaultGateway(ipv6)
	if err != nil {
		return router.Gateway{}, err
	}
	d.gws[ipv6] = gw
	return gw, nil
}

// states returns the router states of the enabled tunnels. mu is held.
func (d *daemon) states() map[string]router.TunnelState {
	st := make(map[string]router.TunnelState, len(d.tunnels))
	for name, rt := range d.tunnels {
		st[name] = router.TunnelState{Up: true, Alive: rt.tun != nil && rt.health.Alive(), Endpoints: rt.addrs}
	}
	return st
}

// reselect selects the rules again (prev nil: from scratch, design 7.3),
// passes the state to the resolver and syncs the table. mu is held, cfg set.
func (d *daemon) reselect(prev []router.RuleState) {
	d.rules = router.SelectRules(d.cfg, d.states(), prev)
	env := router.Env{Ifaces: map[string]int{}}
	for name, rt := range d.tunnels {
		if rt.tun != nil && rt.index > 0 {
			env.Ifaces[name] = rt.index
		}
	}
	for _, ipv6 := range []bool{false, true} {
		gw, err := d.gateway(ipv6)
		if err != nil {
			// The previous gateway stays: a zero one would make Sync
			// remove the direct routes.
			d.log.Warn("default gateway: keeping the previous one", "ipv6", ipv6, "err", err)
			gw = d.env.GW4
			if ipv6 {
				gw = d.env.GW6
			}
		}
		if ipv6 {
			env.GW6 = gw
		} else {
			env.GW4 = gw
		}
	}
	d.env = env
	d.srv.SetState(d.cfg, d.rules, env.Ifaces)
	d.sync()
}

// sync is syncNow for every caller but the resolver: a failed Sync makes the
// resolver sync again before its next answer with rule addresses. mu is held.
func (d *daemon) sync() {
	if err := d.syncNow(); err != nil {
		d.srv.Invalidate()
	}
}

// syncNow builds the table with the current dynamic addresses and every
// endpoint host route of ours (tableFor), and syncs it. mu is held.
func (d *daemon) syncNow() error {
	t := tableFor(d.cfg, d.states(), d.rules, d.srv.Dynamic(), d.hosts)
	err := d.syncTable(t, d.env)
	d.table, d.syncErr, d.synced = t, err, true
	return err
}

// syncTable applies t, logs every op and skipped route and records the
// skipped routes. mu is held.
func (d *daemon) syncTable(t router.Table, env router.Env) error {
	ops, skips, err := router.Sync(t, env)
	for _, op := range ops {
		d.log.Info("route "+string(op.Type), "route", op.Route.String())
	}
	for _, s := range skips {
		d.log.Warn("route skipped", "prefix", s.Route.Prefix, "target", s.Route.Target, "tunnel", s.Route.Tunnel, "reason", s.Reason)
	}
	if err != nil {
		d.log.Error("route sync", "err", err)
	}
	d.log.Info("routes synced", "ops", len(ops), "skipped", len(skips), "routes", len(t))
	d.skips = skips
	return err
}

// logOverlaps warns about routes of the table overlapping local networks
// (design 18). mu is held.
func (d *daemon) logOverlaps() {
	local, err := router.LocalNets()
	if err != nil {
		d.log.Warn("local networks", "err", err)
	}
	for _, r := range router.Overlaps(d.table, local) {
		d.log.Warn("overlaps local network", "prefix", r.Prefix, "target", r.Target, "tunnel", r.Tunnel)
	}
}

// tableFor is the table to sync: router.Build of cfg with an endpoint route
// to every address of hosts (withEndpoints). cfg nil (no config applied, a
// start with an invalid one): the endpoint routes alone — empty right after
// start, so Sync removes every route of ours left by the previous run
// (design 4.1).
func tableFor(cfg *config.Config, tunnels map[string]router.TunnelState, rules []router.RuleState, dynamic []router.Dynamic, hosts map[netip.Addr]*hostRoute) router.Table {
	var t router.Table
	if cfg != nil {
		t = router.Build(cfg, tunnels, rules, dynamic)
	}
	return withEndpoints(t, hosts)
}

// withEndpoints returns t with an endpoint route (direct) to every address
// of hosts that t does not already have as one, replacing a route of t on
// the same prefix as Build does (endpoint wins, design 7.2).
func withEndpoints(t router.Table, hosts map[netip.Addr]*hostRoute) router.Table {
	have := map[netip.Prefix]int{}
	for i, r := range t {
		have[r.Prefix] = i
	}
	added := false
	for a := range hosts {
		p := netip.PrefixFrom(a, a.BitLen())
		r := router.Route{Prefix: p, Target: router.TargetDirect, Source: router.SourceEndpoint, Rule: -1}
		i, ok := have[p]
		switch {
		case !ok:
			t = append(t, r)
			have[p] = len(t) - 1
			added = true
		case t[i].Source != router.SourceEndpoint:
			t[i] = r
		}
	}
	if added {
		slices.SortFunc(t, func(a, b router.Route) int {
			if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
				return c
			}
			return a.Prefix.Bits() - b.Prefix.Bits()
		})
	}
	return t
}

// endpointRoutes returns the endpoint routes of t: synced alone, they make
// Sync remove every other route of ours.
func endpointRoutes(t router.Table) router.Table {
	var res router.Table
	for _, r := range t {
		if r.Source == router.SourceEndpoint {
			res = append(res, r)
		}
	}
	return res
}

// errorList returns the messages of a config.Load error, one per problem.
func errorList(err error) []string {
	var errs config.Errors
	if !errors.As(err, &errs) {
		return []string{err.Error()}
	}
	res := make([]string, 0, len(errs))
	for _, e := range errs {
		res = append(res, e.Error())
	}
	return res
}

// addScoped adds scoped host routes via the utun index to the DNS servers of
// t (dns.Servers) and to its check address, of the families t has in
// Address: a socket bound to the utun reaches them only so (design 8, 9).
// A check address that is also a DNS server gets one route. A check URL gets
// none here: HTTPChecker adds the route to its address before each request.
// Errors are logged: queries through t then get SERVFAIL, pings fail. Index
// 0 (unknown): nothing is added.
func addScoped(log *slog.Logger, t *config.Tunnel, index int) {
	if index <= 0 {
		return
	}
	var dsts []netip.Addr
	for _, s := range dns.Servers(t) {
		dsts = append(dsts, s.Unmap())
	}
	if c := t.Check.Unmap(); c.IsValid() && !slices.Contains(dsts, c) {
		dsts = append(dsts, c)
	}
	for _, s := range dsts {
		if !hasFamily(t.WG.Addresses, s.Is6()) {
			continue
		}
		if err := router.AddScoped(s, index); err != nil {
			log.Warn("scoped route", "tunnel", t.Name, "dst", s, "err", err)
			continue
		}
		log.Info("scoped route", "tunnel", t.Name, "dst", s, "ifindex", index)
	}
}

// hasFamily reports whether addrs has an IPv6 (ipv6) or an IPv4 prefix.
func hasFamily(addrs []netip.Prefix, ipv6 bool) bool {
	for _, p := range addrs {
		if p.Addr().Unmap().Is6() == ipv6 {
			return true
		}
	}
	return false
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

// captureDNS makes the resolver the system DNS (dns.Capture) and logs it; a
// failed cache flush is only logged.
func captureDNS(log *slog.Logger) error {
	err := dns.Capture()
	if err != nil && !errors.Is(err, dns.ErrFlush) {
		return err
	}
	if err != nil {
		log.Warn("dns cache", "err", err)
	}
	log.Info("dns captured", "addr", dnsAddr)
	return nil
}

// releaseDNS releases the system DNS (dns.Release) and logs the outcome. It
// returns the error of the release; a failed cache flush is only logged and
// counts as a release.
func releaseDNS(log *slog.Logger) error {
	err := dns.Release()
	switch {
	case err == nil:
		log.Info("dns released")
	case errors.Is(err, dns.ErrFlush):
		log.Warn("dns cache", "err", err)
		log.Info("dns released")
	default:
		log.Error("dns release", "err", err)
		return err
	}
	return nil
}

// logHostRoute logs the outcome of AddHost for dst.
func logHostRoute(log *slog.Logger, tunnel string, dst netip.Addr, gw router.Gateway, set bool) {
	switch {
	case !set:
		log.Info("host route skipped: endpoint is on-link", "tunnel", tunnel, "dst", dst)
	case gw.Addr.IsValid():
		log.Info("host route via gateway", "tunnel", tunnel, "dst", dst, "gateway", gw.Addr, "ifindex", gw.Index)
	default:
		log.Warn("host route: no physical gateway, blackhole", "tunnel", tunnel, "dst", dst)
	}
}
