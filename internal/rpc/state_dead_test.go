package rpc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Tests follow design 9 (a dead tunnel keeps its utun and its routes), 14
// (state "dead", the icon, the ping result; TunnelStatus.Reason, Check,
// CheckStatus), not the
// implementation. The fixture is newState of state_test.go: work, de, fi up,
// bad failed, home off.

const deadReason = "ping 1.1.1.1: 3 failures"

// deadState is newState with de dead (ping) and fi alive with a check;
// bad is turned off so that only health decides the icon.
func deadState(f *fixture) *State {
	s := newState(f)
	de := s.Tunnels["de"]
	de.Dead = true
	de.Reason = deadReason
	de.Check = &CheckStatus{Addr: "1.1.1.1", LastOK: t0.Add(-time.Minute), RTTMs: 12.5, Fails: 3}
	s.Tunnels["de"] = de
	fi := s.Tunnels["fi"]
	fi.Check = &CheckStatus{Addr: "1.1.1.1", LastOK: t0.Add(-5 * time.Second), RTTMs: 34, Fails: 0}
	s.Tunnels["fi"] = fi
	delete(s.Tunnels, "bad")
	return s
}

// design 14: a running tunnel that health calls dead is
// "dead" with its reason; it keeps its interface, peers and route count; the
// check result is passed on for "up" and "dead".
func TestStatusDead(t *testing.T) {
	f := newFixture(t)
	got := statusOf(t, deadState(f))

	de, ok := tunnelByName(got, "de")
	if !ok {
		t.Fatal("tunnel de missing")
	}
	if !de.Enabled || de.State != "dead" || de.Reason != deadReason || de.Error != "" {
		t.Errorf("de: enabled %v state %q reason %q error %q; want true dead %q no error",
			de.Enabled, de.State, de.Reason, de.Error, deadReason)
	}
	if de.Interface != "utun6" || de.RouteCount != 3 || len(de.Peers) != 2 {
		t.Errorf("de: iface %q routes %d peers %d; want utun6 3 2 (a dead tunnel keeps its utun, design 9)",
			de.Interface, de.RouteCount, len(de.Peers))
	}
	if de.Check == nil {
		t.Error("de: Check nil, want the ping result")
	} else if c := *de.Check; c.Addr != "1.1.1.1" || c.Fails != 3 || c.RTTMs != 12.5 || !c.LastOK.Equal(t0.Add(-time.Minute)) {
		t.Errorf("de: Check %+v, want 1.1.1.1, 3 fails, 12.5 ms, last OK a minute ago", c)
	}

	fi, _ := tunnelByName(got, "fi")
	if fi.State != "up" || fi.Reason != "" {
		t.Errorf("fi: state %q reason %q, want up, no reason", fi.State, fi.Reason)
	}
	if fi.Check == nil {
		t.Error("fi: Check nil, want the ping result")
	} else if c := *fi.Check; c.Addr != "1.1.1.1" || c.Fails != 0 || c.RTTMs != 34 || !c.LastOK.Equal(t0.Add(-5*time.Second)) {
		t.Errorf("fi: Check %+v, want 1.1.1.1, 0 fails, 34 ms", c)
	}

	work, _ := tunnelByName(got, "work")
	if work.State != "up" || work.Reason != "" || work.Check != nil {
		t.Errorf("work (no check): state %q reason %q check %+v; want up, none, nil", work.State, work.Reason, work.Check)
	}
	home, _ := tunnelByName(got, "home")
	if home.State != "off" || home.Reason != "" || home.Check != nil {
		t.Errorf("home (off): state %q reason %q check %+v; want off, none, nil", home.State, home.Reason, home.Check)
	}
}

// design 14: warn also for an enabled dead tunnel;
// Unknown and Alive are "up"; "starting" still never gives warn.
func TestStatusIconDead(t *testing.T) {
	f := newFixture(t)
	dead := func(rt TunnelRuntime) TunnelRuntime { rt.Dead, rt.Reason = true, deadReason; return rt }
	cases := []struct {
		name string
		edit func(s *State)
		want string
	}{
		{"de dead, others up", func(s *State) {}, "warn"},
		{"only de, dead", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{"de": s.Tunnels["de"]}
		}, "warn"},
		{"all up, de with 2 ping failures (not dead)", func(s *State) {
			de := s.Tunnels["de"]
			de.Dead, de.Reason = false, ""
			de.Check = &CheckStatus{Addr: "1.1.1.1", Fails: 2}
			s.Tunnels["de"] = de
		}, "on"},
		{"de dead, bad starting", func(s *State) {
			s.Tunnels["bad"] = TunnelRuntime{Starting: true}
		}, "warn"},
		{"all dead", func(s *State) {
			for n, rt := range s.Tunnels {
				s.Tunnels[n] = dead(rt)
			}
		}, "warn"},
		{"only starting", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{"bad": {Starting: true}}
		}, "off"},
		{"starting and up", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{"bad": {Starting: true}, "work": s.Tunnels["work"]}
		}, "on"},
	}
	for _, c := range cases {
		s := deadState(f)
		c.edit(s)
		if got := statusOf(t, s); got.Icon != c.want {
			t.Errorf("%s: icon %q, want %q", c.name, got.Icon, c.want)
		}
	}
}

// tunnelsJSON returns the tunnels of the status.get reply as JSON objects
// by name.
func tunnelsJSON(t *testing.T, st Status) map[string]map[string]any {
	t.Helper()
	var reply struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal([]byte(jsonOf(t, st)), &reply); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, tn := range reply.Tunnels {
		name, _ := tn["name"].(string)
		out[name] = tn
	}
	return out
}

// Reason and check are on the wire only when set;
// check has addr and fails always, last_ok and rtt_ms only when known.
func TestStatusJSON(t *testing.T) {
	f := newFixture(t)
	s := deadState(f)
	fi := s.Tunnels["fi"]
	fi.Check = &CheckStatus{Addr: "1.1.1.1"} // no ping yet
	s.Tunnels["fi"] = fi
	tns := tunnelsJSON(t, statusOf(t, s))

	for _, name := range []string{"work", "home"} {
		for _, key := range []string{"reason", "check"} {
			if _, ok := tns[name][key]; ok {
				t.Errorf("%s: key %q in JSON, want it omitted: %v", name, key, tns[name])
			}
		}
	}

	de := tns["de"]
	if de["state"] != "dead" || de["reason"] != deadReason {
		t.Errorf("de: state %v reason %v, want dead %q", de["state"], de["reason"], deadReason)
	}
	check, ok := de["check"].(map[string]any)
	if !ok {
		t.Fatalf("de: check %v, want an object", de["check"])
	}
	if check["addr"] != "1.1.1.1" || check["fails"] != float64(3) || check["rtt_ms"] != 12.5 {
		t.Errorf("de: check %v, want addr 1.1.1.1, fails 3, rtt_ms 12.5", check)
	}
	if lo, _ := check["last_ok"].(string); lo == "" {
		t.Errorf("de: check.last_ok %v, want a time", check["last_ok"])
	} else if tm, err := time.Parse(time.RFC3339Nano, lo); err != nil || !tm.Equal(t0.Add(-time.Minute)) {
		t.Errorf("de: check.last_ok %q, want %v", lo, t0.Add(-time.Minute))
	}

	fc, ok := tns["fi"]["check"].(map[string]any)
	if !ok {
		t.Fatalf("fi: check %v, want an object", tns["fi"]["check"])
	}
	if fc["addr"] != "1.1.1.1" || fc["fails"] != float64(0) {
		t.Errorf("fi: check %v, want addr 1.1.1.1, fails 0", fc)
	}
	for _, key := range []string{"last_ok", "rtt_ms"} {
		if _, ok := fc[key]; ok {
			t.Errorf("fi: check.%s present before the first successful ping: %v", key, fc)
		}
	}
	if _, ok := tns["fi"]["reason"]; ok {
		t.Errorf("fi (up): reason in JSON: %v", tns["fi"])
	}
}

// design 10.1 Keys, 14: no key of the fixture in the replies with a dead tunnel.
func TestNoKeysDead(t *testing.T) {
	f := newFixture(t)
	s := deadState(f)
	outs := []string{jsonOf(t, statusOf(t, s)), jsonOf(t, routesOf(t, s))}
	for _, out := range outs {
		for _, k := range f.keys {
			if strings.Contains(out, k) {
				t.Error("a reply contains a key")
			}
		}
	}
}

// Explain and RoutesOf do not change for a dead
// tunnel: its utun is there, its routes are its own (design 9: AllowedIPs
// stay on it; rules skip it by their RuleState).
func TestRoutesDead(t *testing.T) {
	f := newFixture(t)
	s := deadState(f)
	r := routesOf(t, s)
	n := 0
	for _, ri := range r.Routes {
		if ri.Tunnel == "de" {
			n++
			if ri.Target != "tunnel" {
				t.Errorf("route %s of dead de: target %q, want tunnel", ri.Prefix, ri.Target)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d routes of de, want 3", n)
	}
	e, err := explainOf(t, s, "91.108.4.1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Route == nil || e.Route.Target != "tunnel" || e.Route.Tunnel != "de" {
		t.Errorf("Explain 91.108.4.1 with de dead: route %+v, want tunnel de", e.Route)
	}
}
