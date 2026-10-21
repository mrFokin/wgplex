package main

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/health"
	"github.com/mrFokin/wgplex/internal/tunnel"
)

const (
	// reresolveEvery: a dead tunnel resolves its endpoint host names again
	// at most this often, counted from the last resolving (design 6).
	reresolveEvery = 60 * time.Second
	// retryEvery: a failed tunnel is brought up again at most this often,
	// counted from the last failure (design 6).
	retryEvery = 60 * time.Second
)

// probe is one running tunnel in a health tick: what the snapshot took
// under mu and the check and the resolving made without locks.
type probe struct {
	rt      *runTunnel
	t       *config.Tunnel // of d.cfg at the snapshot
	tun     *tunnel.Tunnel // rt.tun at the snapshot
	checker health.Checker // rt.checker at the snapshot; nil: no check
	check   string         // rt.check at the snapshot
	at      time.Time
	peers   []tunnel.PeerStats
	ping    health.PingResult

	reresolve  bool             // dead, with host names, due resolving again
	resolvedAt time.Time        // reresolve: rt.resolvedAt at the snapshot
	endpoints  []netip.AddrPort // reresolve: the result
	rerr       error            // reresolve: resolving failed
}

// healthTick polls every running tunnel (Health model of the Wirefork M7 plan):
// a snapshot under mu, the checks of all tunnels in parallel without locks
// (and the endpoints of the dead tunnels due it resolved again, design 6),
// then under opMu → mu the verdicts of the tunnels that are still the same
// (not restarted or stopped meanwhile). A change of Alive selects the rules
// again without going back to a preferred tunnel (design 7.3); a dead tunnel
// gets a handshake attempt every health.PokeEvery, a new endpoint address
// (reendpoint). Last, the failed tunnels due it are brought up again
// (retryEvery).
//
// Without a network (no physical gateway, Wirefork M7 decision 13, design 9) nothing
// is polled, poked, resolved or retried and the verdicts stay; the network
// coming back resets the health window (onNetwork).
func (d *daemon) healthTick(ctx context.Context, now time.Time) {
	probes, offline := d.probes(now)
	if offline {
		return
	}
	var wg sync.WaitGroup
	var dead []*probe
	for _, p := range probes {
		if p.reresolve {
			dead = append(dead, p)
		}
		if p.checker == nil {
			continue
		}
		wg.Go(func() {
			// Each checker bounds itself: PingTimeout, HTTPTimeout.
			p.ping = p.checker.Check(ctx)
		})
	}
	if len(dead) > 0 {
		wg.Go(func() {
			ts := make([]*config.Tunnel, len(dead))
			for i, p := range dead {
				ts[i] = p.t
			}
			endpoints, errs := d.resolve(ts)
			for i, p := range dead {
				p.endpoints, p.rerr = endpoints[i], errs[i]
			}
		})
	}
	wg.Wait()

	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed || ctx.Err() != nil {
		return
	}
	d.locked(func() { offline = d.observe(probes, now) })
	if offline {
		return
	}
	d.retryFailed(func(rt *runTunnel) bool { return now.Sub(rt.failedAt) >= retryEvery })
}

// observe is the part of healthTick under opMu → mu: the verdicts, the
// handshake attempts and the new endpoints. Returns whether the network went
// away meanwhile (nothing is done then). mu is held.
func (d *daemon) observe(probes []*probe, now time.Time) (offline bool) {
	if d.offline() {
		return true // the network went away during the checks
	}
	changed, moved := false, false
	for _, p := range probes {
		rt := d.tunnels[p.rt.name]
		if rt != p.rt || rt.tun != p.tun {
			continue // restarted or stopped during the check
		}
		t := findTunnel(d.cfg, rt.name)
		if t == nil {
			continue
		}
		if rt.checker != p.checker {
			p.ping = health.PingResult{} // the check changed during the check
		}
		s := health.SampleOf(p.at, p.peers, p.ping)
		if a, err := netip.ParseAddr(p.check); err == nil {
			s.Check = a
		} else {
			s.URL = p.check
		}
		was := rt.health
		rt.health = rt.health.Observe(s)
		if rt.health.State != was.State {
			d.log.Info("tunnel health", "tunnel", rt.name, "state", stateName(rt.health.State), "was", stateName(was.State), "reason", rt.health.Reason)
		}
		if rt.health.Alive() != was.Alive() {
			changed = true
		}
		// A newer resolving (renetwork during the checks) wins over this one.
		if p.reresolve && !rt.resolvedAt.After(p.resolvedAt) {
			rt.resolvedAt = now
			if p.rerr != nil {
				d.log.Warn("endpoint resolve: keeping the old address", "tunnel", rt.name, "err", p.rerr)
			} else if d.reendpoint(t, rt, p.endpoints) {
				moved = true
				rt.tun.Rehandshake(t.WG.Peers, false)
			}
		}
		var poke bool
		if rt.health, poke = rt.health.Poke(now); poke {
			d.log.Info("tunnel dead: handshake attempt", "tunnel", rt.name)
			rt.tun.Rehandshake(t.WG.Peers, false)
		}
	}
	switch {
	case changed:
		d.reselect(d.rules)
	case moved:
		d.sync() // the endpoint routes of the new addresses
	}
	return false
}

// offline reports whether there is no physical gateway, neither IPv4 nor
// IPv6 (Wirefork M7 decision 13); the first tick without one is logged. mu is held.
func (d *daemon) offline() bool {
	off := !d.env.GW4.Addr.IsValid() && !d.env.GW6.Addr.IsValid()
	if off && !d.healthOff {
		d.log.Debug("no physical gateway: health checks paused")
	}
	d.healthOff = off
	return off
}

// probes returns the running tunnels with their peer stats, under mu, the
// dead ones with endpoint host names last resolved reresolveEvery ago or
// earlier marked reresolve; none and offline without a network.
func (d *daemon) probes(now time.Time) (res []*probe, offline bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.offline() {
		return nil, true
	}
	for _, rt := range d.tunnels {
		if rt.tun == nil {
			continue
		}
		t := findTunnel(d.cfg, rt.name)
		if t == nil {
			continue
		}
		peers, err := rt.tun.Stats(t.WG.Peers)
		if err != nil {
			d.log.Warn("tunnel stats", "tunnel", rt.name, "err", err)
			continue
		}
		res = append(res, &probe{
			rt: rt, t: t, tun: rt.tun, checker: rt.checker, check: rt.check,
			at: time.Now().Round(0), peers: peers, resolvedAt: rt.resolvedAt,
			reresolve: rt.health.State == health.Dead && tunnel.HasHostnames(t.WG.Peers) &&
				now.Sub(rt.resolvedAt) >= reresolveEvery,
		})
	}
	return res, false
}

// activeCheck returns the check of t that is made, as CheckStatus.Addr shows
// it: the check address, or the check URL; "" without a check, when its
// address (an IP literal host of the URL) is of a family t has no Address of
// (decision 7, checkWarnings) or when the URL host is a name and t has no
// DNS server reachable through it (checkServers, Wirefork M11 decision 6).
func activeCheck(t *config.Tunnel) string {
	c := t.Check.Unmap()
	if t.CheckURL != "" {
		a := urlAddr(t.CheckURL)
		if a.IsValid() && !hasFamily(t.WG.Addresses, a.Is6()) {
			return ""
		}
		if !a.IsValid() && len(checkServers(t)) == 0 {
			return ""
		}
		return t.CheckURL
	}
	if !c.IsValid() || !hasFamily(t.WG.Addresses, c.Is6()) {
		return ""
	}
	return c.String()
}

// checkIPv6 reports whether the HTTP check of t resolves its host name in
// IPv6: t has no IPv4 Address (design 9).
func checkIPv6(t *config.Tunnel) bool {
	return !hasFamily(t.WG.Addresses, false)
}

// checkServers returns the DNS servers of t (dns.Servers) reachable through
// it, unmapped: those of a family t has an Address of, which it has scoped
// routes to (addScoped, design 9). The family of the query is checkIPv6,
// independent of the server family.
func checkServers(t *config.Tunnel) []netip.Addr {
	var res []netip.Addr
	for _, s := range dns.Servers(t) {
		if s = s.Unmap(); hasFamily(t.WG.Addresses, s.Is6()) {
			res = append(res, s)
		}
	}
	return res
}

// setChecker replaces the checker of rt with one of activeCheck(t) through
// its utun: a Pinger of the check address or an HTTPChecker of the check
// URL; none without such a check or a utun index. A checker that fails to
// open is logged: the tunnel is then checked only passively. mu is held.
func (d *daemon) setChecker(t *config.Tunnel, rt *runTunnel) {
	if rt.checker != nil {
		rt.checker.Close()
		rt.checker = nil
	}
	rt.check = activeCheck(t)
	if rt.check == "" || rt.index <= 0 {
		return
	}
	var c health.Checker
	var err error
	if t.CheckURL != "" {
		c, err = health.NewHTTPChecker(rt.index, t.CheckURL, checkServers(t), checkIPv6(t))
	} else {
		c, err = health.NewPinger(rt.index, netip.MustParseAddr(rt.check))
	}
	if err != nil {
		d.log.Warn("health check", "tunnel", t.Name, "err", err)
		return
	}
	rt.checker = c
}

// stateName names s for logs.
func stateName(s health.State) string {
	switch s {
	case health.Alive:
		return "alive"
	case health.Dead:
		return "dead"
	}
	return "unknown"
}
