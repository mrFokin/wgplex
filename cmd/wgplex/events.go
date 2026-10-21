package main

import (
	"net/netip"
	"slices"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/netwatch"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/tunnel"
)

// handle reacts to netwatch events ("Реакция демона" of the Wirefork M7 plan), under
// opMu:
//   - Wake always, Network and Resync when the system DNS servers, the
//     gateways or the primary service have changed (decision 12): onNetwork;
//     a Network event with none of them changed (another VPN, IPv6
//     addresses) gives no reaction;
//   - Network, Wake, Capture and Resync: checkCapture.
func (d *daemon) handle(e netwatch.Event) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.closed {
		return
	}
	d.log.Debug("netwatch", "events", e)
	wake := e&netwatch.Wake != 0
	network := wake
	if !wake && e&(netwatch.Network|netwatch.Resync) != 0 {
		if d.networkChanged() {
			d.log.Info("network changed", "events", e)
			network = true
		} else if e&netwatch.Network != 0 {
			d.log.Debug("network event: no change")
		}
	}
	if network {
		d.onNetwork(wake)
	}
	if e&(netwatch.Network|netwatch.Wake|netwatch.Capture|netwatch.Resync) != 0 {
		d.checkCapture()
	}
}

// networkChanged reports whether the system DNS servers, the physical
// gateways or the primary service (decision 12) differ from the ones in
// use; a lookup error is no change (a lost network has no primary service
// and a zero gateway: both are changes). opMu is held.
func (d *daemon) networkChanged() bool {
	primary, perr := dns.PrimaryService()
	servers, serr := dns.SystemServers()
	var gws [2]router.Gateway
	var gerr error
	for i, ipv6 := range []bool{false, true} {
		gw, err := router.DefaultGateway(ipv6)
		if err != nil {
			gerr = err
		}
		gws[i] = gw
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if perr == nil && primary != d.primary {
		return true
	}
	if serr == nil && !slices.Equal(servers, d.system) {
		return true
	}
	return gerr == nil && d.cfg != nil && (gws[0] != d.env.GW4 || gws[1] != d.env.GW6)
}

// onNetwork reacts to a network change or a wake (design 6): the system DNS
// servers, the gateways and the endpoint host routes, rebind and a new
// handshake of every running tunnel (wake: with its keypairs expired), its
// scoped routes to DNS servers and check put again (Wirefork M6 decision 11), the
// health window reset, the rules selected again without going back to a
// preferred tunnel and the failed tunnels brought up again, unless there is
// no network (Wirefork M11 decision 7: the selection reads the new gateways for it
// first). opMu is held.
func (d *daemon) onNetwork(wake bool) {
	d.renetwork(wake)
	offline := true
	d.locked(func() {
		if d.cfg != nil {
			d.reselect(d.rules)
			offline = d.offline()
		}
	})
	if !offline {
		d.retryFailed(func(*runTunnel) bool { return true })
	}
}

// retryFailed brings up again the failed tunnels (err set) that due reports
// true for, in config order, as SetEnabled does them (design 6: on a network
// change and retryEvery after a failure). Each one gets its rules as soon as
// it is up; one that fails again gets a new failedAt. opMu is held.
func (d *daemon) retryFailed(due func(*runTunnel) bool) {
	var retry []*config.Tunnel
	d.locked(func() {
		if d.cfg == nil {
			return
		}
		for _, t := range d.cfg.Tunnels {
			if rt := d.tunnels[t.Name]; rt != nil && rt.err != "" && due(rt) {
				d.log.Info("tunnel retry", "tunnel", t.Name)
				d.tunnels[t.Name] = &runTunnel{name: t.Name, starting: true}
				retry = append(retry, findTunnel(d.cfg, t.Name))
			}
		}
		if len(retry) > 0 {
			d.reselect(d.rules)
		}
	})
	if len(retry) == 0 {
		return
	}
	endpoints, errs := d.resolve(retry) // without mu
	for i, t := range retry {
		d.up(t, endpoints[i], errs[i], true) // logs its error
	}
}

// renetwork is the part of onNetwork that does not sync: the system DNS
// servers (setSystem), the endpoint host names of the running tunnels
// resolved again (design 6, DDNS; without mu), the gateways and the endpoint
// host routes, the new endpoint addresses (reendpoint), rebind, a new
// handshake, the scoped routes and the health reset of every running
// tunnel. Apply calls it alone: it brings up the failed tunnels and selects
// the rules itself. opMu is held.
func (d *daemon) renetwork(wake bool) {
	d.log.Info("network change", "wake", wake)
	d.setSystem()

	var rts []*runTunnel
	var ts []*config.Tunnel
	d.locked(func() {
		for _, rt := range d.tunnels {
			if t := findTunnel(d.cfg, rt.name); rt.tun != nil && t != nil && tunnel.HasHostnames(t.WG.Peers) {
				rts, ts = append(rts, rt), append(ts, t)
			}
		}
	})
	var endpoints [][]netip.AddrPort
	var errs []error
	if len(ts) > 0 {
		endpoints, errs = d.resolve(ts)
	}

	d.locked(func() {
		clear(d.gws)
		d.rehost()
		now := time.Now()
		// opMu is held since the snapshot: rts are still running. The
		// handshake below goes to the new addresses.
		for i, rt := range rts {
			rt.resolvedAt = now
			if errs[i] != nil {
				d.log.Warn("endpoint resolve: keeping the old address", "tunnel", rt.name, "err", errs[i])
				continue
			}
			d.reendpoint(ts[i], rt, endpoints[i])
		}
		for _, rt := range d.tunnels {
			if rt.tun == nil {
				continue
			}
			t := findTunnel(d.cfg, rt.name)
			if t == nil {
				continue
			}
			if err := rt.tun.Rebind(); err != nil {
				d.log.Warn("rebind", "tunnel", rt.name, "err", err)
			} else {
				d.log.Info("rebind", "tunnel", rt.name)
			}
			rt.tun.Rehandshake(t.WG.Peers, wake)
			addScoped(d.log, t, rt.index) // idempotent; may be gone with the network change
			rt.health = rt.health.Reset(now)
		}
	})
}

// checkCapture puts the DNS capture back when it was made and its key is
// gone (a configd restart, design 8). Our own write of the key also gives a
// Capture event: the key is there then, nothing is done. Without system DNS
// servers the capture is not put back, as in Apply: the resolver would have
// no upstream. Nor is it put back when the config has no domains: captured
// is then left by a failed release (decision 11), and the lost key completes
// that release. opMu is held.
func (d *daemon) checkCapture() {
	if !d.captured {
		return
	}
	var hasSystem, needsDNS bool
	d.locked(func() {
		hasSystem = len(d.system) > 0
		needsDNS = d.cfg != nil && d.cfg.NeedsDNS()
	})
	ok, err := dns.Captured()
	if err != nil {
		d.log.Warn("dns capture check", "err", err)
		return
	}
	if ok {
		return
	}
	if !needsDNS {
		d.log.Info("dns capture lost; no domains in config: released")
		d.captured = false
		return
	}
	if !hasSystem {
		d.log.Warn("dns capture lost; no system DNS servers: not restored")
		return
	}
	if err := captureDNS(d.log); err != nil {
		d.log.Error("dns capture", "err", err)
		return
	}
	d.log.Info("dns capture restored")
}
