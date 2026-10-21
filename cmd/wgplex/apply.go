package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"reflect"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
)

// planApply decides the tunnels after applying next over cur (decision 1).
// toggles maps the explicitly toggled tunnels (state.json, design 11) to
// their state: a record wins over cur and autostart, a tunnel without one
// follows enabled when cur kept it (a repeated apply) and otherwise —
// first apply — its autostart. enabled: tunnels enabled now; running:
// those with a utun. restart: kept, running, enabled and its WGConfig
// changed (reflect.DeepEqual). stop: running and (not enabled in next or
// restart); start: enabled in next and (not running or restart). Both in
// next's (stop: cur's) tunnel order.
//
// nextEnabled holds only enabled tunnels (all values true).
func planApply(cur, next *config.Config, toggles, enabled, running map[string]bool) (nextEnabled map[string]bool, stop, start []string) {
	nextEnabled = map[string]bool{}
	for _, t := range next.Tunnels {
		on := t.Autostart
		if v, ok := toggles[t.Name]; ok {
			on = v
		} else if cur != nil && findTunnel(cur, t.Name) != nil {
			on = enabled[t.Name]
		}
		if on {
			nextEnabled[t.Name] = true
		}
	}
	restart := map[string]bool{}
	if cur != nil {
		for _, t := range next.Tunnels {
			ct := findTunnel(cur, t.Name)
			if ct != nil && running[t.Name] && nextEnabled[t.Name] && !reflect.DeepEqual(ct.WG, t.WG) {
				restart[t.Name] = true
			}
		}
		for _, t := range cur.Tunnels {
			if running[t.Name] && (!nextEnabled[t.Name] || restart[t.Name]) {
				stop = append(stop, t.Name)
			}
		}
	}
	for _, t := range next.Tunnels {
		if nextEnabled[t.Name] && (!running[t.Name] || restart[t.Name]) {
			start = append(start, t.Name)
		}
	}
	return nextEnabled, stop, start
}

// blockedDNSWarnings warns about DNS servers of tunnels (dns.Servers) inside
// a CIDR of a service of a rule with fallback: block: in fallback the reject
// route cuts DNS through that tunnel too (Wirefork M5 fact 3).
//
// One warning per (rule, tunnel, server), with the first such CIDR; rules
// in config order, then tunnels in config order.
func blockedDNSWarnings(cfg *config.Config) []string {
	var res []string
	for i, r := range cfg.Rules {
		if r.Fallback != config.FallbackBlock {
			continue
		}
		for ti := range cfg.Tunnels {
			t := &cfg.Tunnels[ti]
			for _, s := range dns.Servers(t) {
				svc, p, ok := blockingCIDR(cfg, r, s.Unmap())
				if !ok {
					continue
				}
				res = append(res, fmt.Sprintf(
					"tunnel %q: DNS server %s is in %s of service %q of rule #%d with fallback: block; in fallback DNS through the tunnel is cut too",
					t.Name, s.Unmap(), p, svc, i+1))
			}
		}
	}
	return res
}

// blockingCIDR returns the first CIDR of a service of r (in r.Services
// order) that contains a.
func blockingCIDR(cfg *config.Config, r config.Rule, a netip.Addr) (svc string, p netip.Prefix, ok bool) {
	for _, name := range r.Services {
		for _, p := range cfg.Services[name].CIDRs {
			if p.Contains(a) {
				return name, p, true
			}
		}
	}
	return "", netip.Prefix{}, false
}

// checkWarnings warns about a check address, or an IP literal host of a
// check URL, of a family the tunnel has no Address of, and about a check URL
// with a host name when the tunnel has no DNS server reachable through it
// (checkServers): such a check is not made (decision 7, Wirefork M11 decision 6,
// design 9). One warning per such tunnel, in config order.
func checkWarnings(cfg *config.Config) []string {
	var res []string
	for _, t := range cfg.Tunnels {
		c, what := t.Check.Unmap(), "pinged"
		if t.CheckURL != "" {
			c, what = urlAddr(t.CheckURL), "checked"
			if !c.IsValid() {
				if len(checkServers(&t)) == 0 {
					res = append(res, fmt.Sprintf(
						"tunnel %q: check %s is not checked: the tunnel has no DNS server reachable through it; only the passive check works",
						t.Name, t.CheckURL))
				}
				continue
			}
		}
		if !c.IsValid() || hasFamily(t.WG.Addresses, c.Is6()) {
			continue
		}
		check := c.String()
		if t.CheckURL != "" {
			check = t.CheckURL
		}
		res = append(res, fmt.Sprintf(
			"tunnel %q: check %s is not %s: the tunnel has no %s address; only the passive check works",
			t.Name, check, what, familyName(c.Is6())))
	}
	return res
}

// familyName names the address family for warnings.
func familyName(ipv6 bool) string {
	if ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

// urlAddr returns the host of the check URL u when it is an IP literal
// (unmapped); zero for a host name.
func urlAddr(u string) netip.Addr {
	p, err := url.Parse(u)
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(p.Hostname())
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
