package rpc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests follow design 5 (Visibility) and plan M3 decision 4: for a caller
// that cannot control the endpoints and resolved addresses of peers, the
// check address, the texts of config errors and warnings, the names of routes
// and the servers of explain are dropped; counts, names, states, via, the
// serving tunnel, reasons, addresses, handshakes and traffic stay.

var redactT0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func fullStatus() Status {
	return Status{
		APIVersion:       1,
		Version:          "0.3.0",
		CanControl:       false,
		ControlGroup:     "wgpctl",
		Configured:       true,
		Paused:           false,
		ConfigDir:        "/etc/wgplex",
		LogPath:          "/var/log/wgplex/wgplex.log",
		Icon:             "warn",
		ConfigErrors:     []string{"wgplex.yaml: secret-host.example is bad", "de.conf: x"},
		ConfigErrorCount: 2,
		Warnings:         []string{"check http://10.9.8.7/health is slow"},
		WarningCount:     1,
		Tunnels: []TunnelStatus{
			{
				Name: "de", Enabled: true, State: "up", Interface: "utun6",
				Addresses: []string{"10.1.0.2/32"}, Routes: "rules", RouteCount: 3,
				Peers: []PeerStatus{{
					Endpoint: "vpn-secret.example.net:51820", Resolved: "203.0.113.5:51820",
					LastHandshake: redactT0, RxBytes: 100, TxBytes: 200,
				}},
				Check: &CheckStatus{Addr: "http://10.9.8.7/health", LastOK: redactT0, RTTMs: 12.5, Fails: 0},
			},
			{
				Name: "fi", Enabled: true, State: "dead", Reason: "http https://x.example/?token=SECRETTOK: 3 failures", Routes: "rules",
				Peers: []PeerStatus{{Endpoint: "203.0.113.7:51820", Resolved: "203.0.113.7:51820"}},
				Check: &CheckStatus{Addr: "198.51.100.9", Fails: 4},
			},
			{Name: "home", Enabled: false, State: "off", Routes: "config"},
			{Name: "bad", Enabled: true, State: "error", Error: "resolve endpoints: lookup secret-dns.example via 192.0.2.53", Routes: "config"},
		},
		Rules: []RuleStatus{
			{Index: 0, Services: []string{"tun"}, Via: []string{"de", "fi"}, Fallback: "default", Tunnel: "de"},
			{Index: 1, Services: []string{"ai"}, Via: []string{"home"}, Fallback: "block", InFallback: true, Degraded: true, Reason: "disabled"},
		},
	}
}

var secretStrings = []string{"vpn-secret.example.net", "203.0.113.5", "203.0.113.7", "10.9.8.7", "198.51.100.9", "secret-host.example", "SECRETTOK", "secret-dns.example", "192.0.2.53"}

// design 5: the redacted status has no endpoint, resolved, check address, texts.
func TestRedactStatusDropsSecrets(t *testing.T) {
	got := RedactStatus(fullStatus())
	js, _ := json.Marshal(got)
	for _, s := range secretStrings {
		if strings.Contains(string(js), s) {
			t.Errorf("redacted status still has %q: %s", s, js)
		}
	}
	for _, ts := range got.Tunnels {
		for _, p := range ts.Peers {
			if p.Endpoint != "" || p.Resolved != "" {
				t.Errorf("tunnel %s: peer %+v keeps an address", ts.Name, p)
			}
		}
		if ts.Check != nil && ts.Check.Addr != "" {
			t.Errorf("tunnel %s: Check.Addr = %q", ts.Name, ts.Check.Addr)
		}
	}
	if len(got.ConfigErrors) != 0 || len(got.Warnings) != 0 {
		t.Errorf("texts kept: errors %q warnings %q", got.ConfigErrors, got.Warnings)
	}
}

// design 5: counts, names, states, via, rule reasons, traffic stay; the
// tunnel reason and error texts go (they name the check URL, DNS servers).
func TestRedactStatusKeeps(t *testing.T) {
	in := fullStatus()
	got := RedactStatus(in)
	if got.ConfigErrorCount != 2 || got.WarningCount != 1 {
		t.Errorf("counts = %d, %d; want 2, 1", got.ConfigErrorCount, got.WarningCount)
	}
	if got.APIVersion != in.APIVersion || got.Version != in.Version || got.ControlGroup != in.ControlGroup ||
		got.Configured != in.Configured || got.Paused != in.Paused || got.ConfigDir != in.ConfigDir ||
		got.LogPath != in.LogPath || got.Icon != in.Icon || got.CanControl != in.CanControl {
		t.Errorf("scalar fields changed:\n got %+v\nwant %+v", got, in)
	}
	if !reflect.DeepEqual(got.Rules, in.Rules) {
		t.Errorf("rules changed:\n got %+v\nwant %+v", got.Rules, in.Rules)
	}
	if len(got.Tunnels) != len(in.Tunnels) {
		t.Fatalf("%d tunnels, want %d", len(got.Tunnels), len(in.Tunnels))
	}
	for i, want := range in.Tunnels {
		g := got.Tunnels[i]
		if g.Name != want.Name || g.Enabled != want.Enabled || g.State != want.State || g.Interface != want.Interface ||
			!reflect.DeepEqual(g.Addresses, want.Addresses) || g.Routes != want.Routes || g.RouteCount != want.RouteCount ||
			g.Reason != "" || g.Error != "" {
			t.Errorf("tunnel %s changed:\n got %+v\nwant %+v", want.Name, g, want)
		}
		if len(g.Peers) != len(want.Peers) {
			t.Errorf("tunnel %s: %d peers, want %d", want.Name, len(g.Peers), len(want.Peers))
			continue
		}
		for j, wp := range want.Peers {
			gp := g.Peers[j]
			if !gp.LastHandshake.Equal(wp.LastHandshake) || gp.RxBytes != wp.RxBytes || gp.TxBytes != wp.TxBytes {
				t.Errorf("tunnel %s peer %d: handshake or traffic changed: %+v", want.Name, j, gp)
			}
		}
		if (g.Check == nil) != (want.Check == nil) {
			t.Errorf("tunnel %s: Check presence changed", want.Name)
		} else if want.Check != nil &&
			(g.Check.Fails != want.Check.Fails || g.Check.RTTMs != want.Check.RTTMs || !g.Check.LastOK.Equal(want.Check.LastOK)) {
			t.Errorf("tunnel %s: check result changed: %+v", want.Name, g.Check)
		}
	}
}

// The Redact functions return a copy: the argument (and its slices) stays as it was.
func TestRedactStatusDoesNotMutate(t *testing.T) {
	in := fullStatus()
	RedactStatus(in)
	if !reflect.DeepEqual(in, fullStatus()) {
		t.Errorf("RedactStatus changed its argument:\n%+v", in)
	}
}

func TestRedactStatusEmpty(t *testing.T) {
	got := RedactStatus(Status{})
	if got.Configured || len(got.Tunnels) != 0 {
		t.Errorf("empty status changed: %+v", got)
	}
}

func fullExplanation() Explanation {
	return Explanation{
		Query: "openai.com", Kind: "domain",
		Rule:     &RuleStatus{Index: 1, Services: []string{"ai"}, Via: []string{"de"}, Fallback: "block"},
		Skipped:  &RuleStatus{Index: 0, Services: []string{"x"}},
		Upstream: "de", Zone: "corp.example",
		Servers:  []string{"10.0.0.53", "1.0.0.1"},
		DropAAAA: true,
		Addrs:    []string{"104.18.32.7"},
		Route: &RouteInfo{
			Prefix: "104.18.32.7/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: 1,
			Names: []string{"openai.com", "www.openai.com"},
		},
	}
}

// design 5: no servers of explain, no names of its route.
func TestRedactExplanation(t *testing.T) {
	in := fullExplanation()
	got := RedactExplanation(in)
	if len(got.Servers) != 0 {
		t.Errorf("Servers = %q, want none", got.Servers)
	}
	if got.Route == nil || len(got.Route.Names) != 0 {
		t.Errorf("Route = %+v, want it without Names", got.Route)
	}
	want := fullExplanation()
	want.Servers = nil
	want.Route.Names = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("redacted explanation:\n got %+v\nwant %+v", got, want)
	}
	if !reflect.DeepEqual(in, fullExplanation()) {
		t.Error("RedactExplanation changed its argument")
	}
}

func TestRedactExplanationNoRoute(t *testing.T) {
	in := fullExplanation()
	in.Route = nil
	got := RedactExplanation(in)
	if got.Route != nil || len(got.Servers) != 0 || got.Upstream != "de" {
		t.Errorf("got %+v", got)
	}
}

func TestRedactRoutes(t *testing.T) {
	in := Routes{
		Routes: []RouteInfo{
			{Prefix: "104.18.32.7/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: 1, Names: []string{"openai.com"}},
			{Prefix: "10.0.0.0/8", Target: "tunnel", Tunnel: "work", Source: "allowed_ips", Rule: -1},
			{Prefix: "198.51.100.0/24", Target: "reject", Source: "rule_cidr", Rule: 1, Skipped: "exists"},
		},
		SyncError: "sync failed",
	}
	orig := Routes{Routes: append([]RouteInfo(nil), in.Routes...), SyncError: in.SyncError}
	got := RedactRoutes(in)
	if len(got.Routes) != 3 || got.SyncError != "sync failed" {
		t.Fatalf("got %+v", got)
	}
	for i, r := range got.Routes {
		if len(r.Names) != 0 {
			t.Errorf("route %d keeps Names %q", i, r.Names)
		}
		want := orig.Routes[i]
		want.Names = nil
		if !reflect.DeepEqual(r, want) {
			t.Errorf("route %d:\n got %+v\nwant %+v", i, r, want)
		}
	}
	if len(in.Routes[0].Names) != 1 {
		t.Error("RedactRoutes changed its argument")
	}
}
