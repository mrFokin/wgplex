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
	// of the CLI (Wirefork M6 review note 6).
	resolveTimeout = 10 * time.Second
	expireEvery    = time.Minute    // how often expired dynamic addresses are dropped
	dnsAddr        = "127.0.0.1:53" // the resolver of the daemon (design 8)
)

// errStopping is the error of a mutating call after shutdown has begun; the
// client gets it as Internal error.
var errStopping = errors.New("wgplex daemon is stopping")

// daemon is the state of the wgplex daemon and the system calls on it (manual check
// only). opMu orders the mutating calls (Reload, SetEnabled, DisableAll,
// expire, the health tick, netwatch events, shutdown); mu guards the state
// and Sync, which the resolver calls too (Server.Sync). Lock order: opMu → mu → Server.mu. Endpoints are
// resolved under opMu without mu, so DNS answers do not wait for them. mu is
// always released by defer, so a panic under it does not hang the daemon.
//
// A tunnel is enabled when it is in tunnels: running (tun set), being
// brought up (starting) or failed (err set). A tunnel that is not running is
// Up but not Alive for the router: its AllowedIPs become reject and rules
// pass it over (decisions 6, 14).
//
// Every endpoint host route of ours is in hosts until DeleteHost; syncNow
// puts all of them into the table as endpoint routes, so Sync never removes
// one of a tunnel being brought up or stopped (M4 Sync doc on keep).
type daemon struct {
	opMu     sync.Mutex
	closed   bool // under opMu: shutdown has begun, mutating calls fail
	captured bool // under opMu: the DNS capture succeeded and is not released
	mu       sync.Mutex

	ctx       context.Context // done at stop: endpoint resolving gives up
	srv       *dns.Server
	log       *slog.Logger
	configDir string // the config directory read by applyConfig (design 10.2)
	statePath string // state.json, written by saveState (design 11)

	// release removes the DNS capture key (releaseDNS): a field so that the
	// empty-state sync of a test does not touch the system DNS.
	release func(*slog.Logger) error

	// Under mu.
	cfg       *config.Config  // nil: no config applied yet
	warnings  []string        // of cfg
	cfgErrs   []string        // of the last failed Apply; nil after a successful one
	toggles   map[string]bool // explicitly toggled tunnels (state.json, design 11)
	tunnels   map[string]*runTunnel
	hosts     map[netip.Addr]*hostRoute
	gws       map[bool]router.Gateway // by ipv6, cached once looked up without error
	system    []netip.Addr            // the system DNS servers last read without error
	primary   string                  // the primary service last read without error (decision 12)
	rules     []router.RuleState
	env       router.Env
	table     router.Table // the last synced table
	skips     []router.Skip
	syncErr   error
	healthOff bool // the last health tick found no network (offline)
}

// runTunnel is an enabled tunnel.
type runTunnel struct {
	name      string
	tun       *tunnel.Tunnel   // nil: not running
	starting  bool             // tun nil: being brought up (decision 14)
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
// is set here. configDir is the config directory (design 10.2), read at
// startup and by config.reload. statePath is state.json (design 11),
// applied at startup and rewritten after every successful apply; toggles
// is what Load of it gave (nil or empty: tunnels by autostart), SetEnabled
// and DisableAll add records.
func newDaemon(ctx context.Context, srv *dns.Server, log *slog.Logger, configDir, statePath string, toggles map[string]bool) *daemon {
	// A missing state.json gives nil toggles: SetEnabled and DisableAll
	// record into the map, so it is never nil here.
	toggles = maps.Clone(toggles)
	if toggles == nil {
		toggles = map[string]bool{}
	}
	d := &daemon{
		ctx:       ctx,
		srv:       srv,
		log:       log,
		configDir: configDir,
		statePath: statePath,
		release:   releaseDNS,
		toggles:   toggles,
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

// Reload is config.reload (design 14, 10.2): the daemon re-reads its config
// directory and applies the result. Tunnels keep their toggles, a new one
// follows autostart (planApply with the current config as cur). A config
// that failed to load is not applied: the previous one keeps working and
// the client gets the CodeConfigInvalid error with the problems in data.
func (d *daemon) Reload() (rpc.ReloadResult, error) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return rpc.ReloadResult{}, errStopping
	}
	return d.applyConfig()
}

// applyConfig loads the config directory (config.LoadDir, design 10.2) and
// applies the result. It is the startup path too (runDaemon): its error
// travels to that caller to log once; every problem is already logged here.
// opMu is held.
func (d *daemon) applyConfig() (rpc.ReloadResult, error) {
	next, warnings, err := config.LoadDir(d.configDir)
	if warnings == nil {
		warnings = []string{}
	}
	if err != nil {
		errs := errorList(err)
		// Without a config applied yet there is no state of ours to keep:
		// the routes and the DNS key of a previous run are synced with the
		// empty state right away, not left until shutdown (design 4.1). A
		// failed reload keeps the previous config and changes nothing (10.2).
		var unconfigured bool
		d.locked(func() {
			d.cfgErrs = errs
			unconfigured = d.cfg == nil
		})
		for _, e := range errs {
			d.log.Error("config load", "dir", d.configDir, "err", e)
		}
		if unconfigured {
			d.syncEmpty()
		}
		return rpc.ReloadResult{}, jrpc.NewError(rpc.CodeConfigInvalid, "config is invalid",
			rpc.ConfigErrorData{Errors: errs, Warnings: warnings})
	}
	warnings = append(warnings, blockedDNSWarnings(next)...)
	warnings = append(warnings, checkWarnings(next)...)
	for _, w := range warnings {
		d.log.Warn("config", "warning", w)
	}
	d.log.Info("config applied", "tunnels", len(next.Tunnels), "rules", len(next.Rules))

	// The network may have changed since the last apply (decision 11).
	// Reading the new values would hide the change from the Network event
	// to come (re-review note 1), so a changed network gets the reaction of
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
	// keeps running meanwhile instead of standing in starting (M7
	// accumulated task 6).
	planned := d.toStart(next)
	endpoints, errs := d.resolve(planned)
	start := d.replan(next, warnings)
	if !sameTunnels(planned, start) { // cannot happen: opMu is held
		endpoints, errs = d.resolve(start)
	}
	res := rpc.ReloadResult{Warnings: slices.Clone(warnings)} // d.warnings is shared with State
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
					// until the tunnel stops (review note 5, accepted):
					// the utun is ours, the route harms nothing.
					rt.health = health.New(time.Now())
					d.setChecker(&t, rt)
				}
			}
		}
		d.reselect(nil)
		d.logOverlaps()
	})

	// The system DNS is captured only when the config has domains (M10
	// decision 11). The key is synced with the config, not only with what
	// this daemon captured: a key left by a previous run must go too
	// (design 4.1, no cleanup at startup), so Release runs here even with
	// captured false. Without the key it changes nothing; after a failed
	// release the next apply runs it again.
	switch {
	case !next.NeedsDNS():
		if err := releaseDNS(d.log); err != nil {
			w := "DNS release failed: " + err.Error()
			res.Warnings = append(res.Warnings, w)
			d.locked(func() { d.warnings = append(slices.Clone(d.warnings), w) })
		} else {
			d.captured = false
			d.log.Debug("dns released: no domains in config")
		}
	case !hasSystem:
		d.log.Warn("no system DNS servers: DNS not captured")
	default:
		// Also puts the key back if configd lost it (M7 watches for that).
		if err := captureDNS(d.log); err != nil {
			d.log.Error("dns capture", "err", err)
			w := "DNS capture failed: " + err.Error()
			res.Warnings = append(res.Warnings, w)
			// Shown by status.get too. Replaced, not appended to in place: a
			// State snapshot may hold the old slice.
			d.locked(func() { d.warnings = append(slices.Clone(d.warnings), w) })
		} else {
			d.captured = true
		}
	}
	// The apply succeeded: the toggles (pruned by replan, design 11) go to
	// state.json so that a restart brings up the same tunnels.
	d.saveState()
	return res, nil
}

// syncEmpty syncs the routing table and the DNS capture key with the empty
// state: no config has ever been applied (a broken config at startup), so the
// routes and the key left by a previous run go at once instead of living
// until shutdown (design 4.1, 9.1). The key is released even if this daemon
// never captured it — a leftover of a crash. A failed release is a warning of
// status.get and is retried by the next apply. opMu is held.
func (d *daemon) syncEmpty() {
	d.mu.Lock()
	// The table of no config: Sync removes every route of ours from the
	// kernel dump, the endpoint routes included (no tunnel is running).
	d.table = nil
	d.syncErr = d.syncTable(router.Table{}, router.Env{})
	d.mu.Unlock()
	if err := d.release(d.log); err != nil {
		w := "DNS release failed: " + err.Error()
		d.locked(func() { d.warnings = append(slices.Clone(d.warnings), w) })
		return
	}
	d.captured = false
}

// saveState writes the toggles to state.json (design 11); an error is only
// logged: the daemon keeps working without the file (tunnels then follow
// autostart at startup). opMu is held — saveState runs from the mutating
// calls it serializes — while the write happens without mu, cloning the
// toggles under it.
func (d *daemon) saveState() {
	if d.statePath == "" {
		return
	}
	d.mu.Lock()
	toggles := maps.Clone(d.toggles)
	d.mu.Unlock()
	if err := state.Save(d.statePath, state.State{Tunnels: toggles}); err != nil {
		d.log.Error("state save", "path", d.statePath, "err", err)
	}
}

// toStart returns the tunnels replan would start for next now (planApply
// under mu), in next's order. opMu is held.
func (d *daemon) toStart(next *config.Config) []*config.Tunnel {
	d.mu.Lock()
	defer d.mu.Unlock()
	enabled, running := d.enabledRunning()
	_, _, start := planApply(d.cfg, next, d.toggles, enabled, running)
	var ts []*config.Tunnel
	for _, name := range start {
		ts = append(ts, findTunnel(next, name))
	}
	return ts
}

// enabledRunning returns the enabled tunnels and those running, for
// planApply. mu is held.
func (d *daemon) enabledRunning() (enabled, running map[string]bool) {
	enabled, running = map[string]bool{}, map[string]bool{}
	for name, rt := range d.tunnels {
		enabled[name] = true
		running[name] = rt.tun != nil
	}
	return enabled, running
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
	enabled, running := d.enabledRunning()
	nextEnabled, stop, start := planApply(d.cfg, next, d.toggles, enabled, running)
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
	// Every successful apply prunes the toggles of the tunnels gone from
	// the config (design 11); saveState persists them after the apply.
	d.toggles = pruneToggles(d.toggles, next)
	d.reselect(nil)
	d.closeTunnels(stopped)
	return ts
}

// pruneToggles keeps only the records of cfg's tunnels (design 11: a
// successful apply removes the toggles of the tunnels no longer in the
// config), in a fresh map with the records in cfg's tunnel order.
func pruneToggles(toggles map[string]bool, cfg *config.Config) map[string]bool {
	out := make(map[string]bool, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		if v, ok := toggles[t.Name]; ok {
			out[t.Name] = v
		}
	}
	return out
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
	// The explicit toggle is recorded (design 11) even when coming up
	// fails: the tunnel stays enabled, so does the record.
	d.saveState()
	// t stays enabled even when it fails to come up (design 11).
	if t == nil {
		return nil
	}
	endpoints, errs := d.resolve([]*config.Tunnel{t})
	if err := d.up(t, endpoints[0], errs[0], true); err != nil {
		return jrpc.NewError(rpc.CodeTunnelStart, fmt.Sprintf("tunnel %s: %v", name, err), nil)
	}
	return nil
}

// toggle is the part of SetEnabled under mu: it checks the config and the
// name, records the toggle (design 11) and disables the tunnel, or marks it
// as starting and returns it to be brought up (nil: nothing more to do).
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
	d.toggles[name] = enabled
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

// DisableAll is tunnel.disableAll: SetEnabled false for every enabled tunnel
// with one Sync; the DNS capture stays (decision 2). Without an applied
// config it is error 2, as tunnel.setEnabled (design 14).
func (d *daemon) DisableAll() error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return errStopping
	}
	var noConfig error
	d.locked(func() {
		if d.cfg == nil {
			noConfig = jrpc.NewError(rpc.CodeNoConfig, "no config applied", nil)
			return
		}
		var stopped []*runTunnel
		for _, t := range d.cfg.Tunnels {
			if rt := d.tunnels[t.Name]; rt != nil {
				stopped = append(stopped, rt)
			}
			// design 12: every tunnel of the config becomes off; a later
			// reload does not bring them back, a new one follows autostart.
			d.toggles[t.Name] = false
		}
		clear(d.tunnels)
		d.log.Info("all tunnels disabled")
		d.reselect(d.rules)
		d.closeTunnels(stopped)
		d.sync() // the table without their endpoint routes; no ops
	})
	if noConfig != nil {
		return noConfig
	}
	d.saveState()
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
	// All our routes but the endpoint ones: those go with DeleteHost. Sync
	// reads the kernel dump, so this removes the routes of a previous run
	// too, even when this daemon never synced (a broken config at startup):
	// the startup cleanup is gone (design 4.1), stop still removes them (9.1).
	d.syncTable(endpointRoutes(d.table), router.Env{})
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
// error; t stays enabled either way (decision 6). Then the rules are
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
// again the ones that failed before (Wirefork M7 accumulated task 2). mu is held.
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
			// remove the direct routes (Wirefork M7 accumulated task 1).
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
// resolver sync again before its next answer with rule addresses (M7
// accumulated task 5). mu is held.
func (d *daemon) sync() {
	if err := d.syncNow(); err != nil {
		d.srv.Invalidate()
	}
}

// syncNow builds the table with the current dynamic addresses and every
// endpoint host route of ours, and syncs it. mu is held.
func (d *daemon) syncNow() error {
	if d.cfg == nil {
		return nil
	}
	t := withEndpoints(router.Build(d.cfg, d.states(), d.rules, d.srv.Dynamic()), d.hosts)
	err := d.syncTable(t, d.env)
	d.table, d.syncErr = t, err
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
