package rpc

import (
	"fmt"
	"testing"

	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow design 14 (status.get: enabled is the toggle, reason of a
// rule, priority of icon) and design 12 (pause), plan M3 decisions 5, 6, 8,
// not the implementation. They build on the fixture of state_test.go:
// tunnels work, home, de, fi, bad; rules rTun .. rTg.

// switches returns the toggles of all tunnels of the fixture: on are enabled.
func switches(on ...string) map[string]bool {
	m := map[string]bool{"work": false, "home": false, "de": false, "fi": false, "bad": false}
	for _, n := range on {
		m[n] = true
	}
	return m
}

func runtimeUp(names ...string) map[string]TunnelRuntime {
	m := map[string]TunnelRuntime{}
	for i, n := range names {
		m[n] = TunnelRuntime{Interface: fmt.Sprintf("utun%d", 10+i)}
	}
	return m
}

// configured state, work, de, fi up and enabled, home and bad off.
func upState(f *fixture) *State {
	s := newState(f)
	s.Tunnels = runtimeUp("work", "de", "fi")
	s.Switches = switches("work", "de", "fi")
	return s
}

func allFallback() []router.RuleState {
	return []router.RuleState{{Fallback: true}, {Fallback: true}, {}, {Fallback: true}, {Fallback: true}, {Fallback: true}}
}

// design 14: priority of icon.
func TestIconPriority(t *testing.T) {
	f := newFixture(t)
	dead := TunnelRuntime{Interface: "utun9", Dead: true, Reason: "no handshake"}
	cases := []struct {
		name string
		edit func(s *State)
		want string
	}{
		{"up", func(s *State) {}, "on"},
		{"configured false", func(s *State) { s.Cfg = nil; s.Tunnels = nil; s.Rules = nil; s.Table = nil; s.Switches = nil }, "warn"},
		{"configured false with errors", func(s *State) {
			s.Cfg = nil
			s.Tunnels = nil
			s.Rules = nil
			s.Table = nil
			s.Switches = nil
			s.ConfigErrors = []string{"bad yaml"}
		}, "warn"},
		{"DNS capture error", func(s *State) { s.DNSError = "port 53 is busy" }, "warn"},
		// design 14: configured false and DNS error beat pause
		{"DNS capture error beats pause", func(s *State) {
			s.DNSError = "port 53 is busy"
			s.Paused = true
			s.Tunnels = nil
			s.Rules = allFallback()
		}, "warn"},
		{"paused", func(s *State) { s.Paused = true; s.Tunnels = nil; s.Rules = allFallback() }, "paused"},
		{"paused beats config error", func(s *State) {
			s.Paused = true
			s.Tunnels = nil
			s.Rules = allFallback()
			s.ConfigErrors = []string{"x"}
		}, "paused"},
		{"paused beats dead tunnel", func(s *State) {
			s.Paused = true
			s.Tunnels = map[string]TunnelRuntime{"de": dead}
		}, "paused"},
		{"config error", func(s *State) { s.ConfigErrors = []string{"x"} }, "warn"},
		{"enabled tunnel dead", func(s *State) { s.Tunnels["de"] = dead }, "warn"},
		{"enabled tunnel in error", func(s *State) { s.Tunnels["bad"] = TunnelRuntime{Err: badErr}; s.Switches["bad"] = true }, "warn"},
		{"starting does not change on", func(s *State) { s.Tunnels["bad"] = TunnelRuntime{Starting: true}; s.Switches["bad"] = true }, "on"},
		{"only starting: off", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{"de": {Starting: true}}
			s.Switches = switches("de")
		}, "off"},
		{"fallback after a toggle does not change on", func(s *State) {
			s.Tunnels = runtimeUp("work")
			s.Switches = switches("work")
			s.Rules = allFallback()
		}, "on"},
		{"all toggled off, rules in fallback", func(s *State) {
			s.Tunnels = nil
			s.Switches = switches()
			s.Rules = allFallback()
		}, "off"},
	}
	for _, c := range cases {
		s := upState(f)
		c.edit(s)
		if got := statusOf(t, s).Icon; got != c.want {
			t.Errorf("%s: icon %q, want %q", c.name, got, c.want)
		}
	}
}

// design 12: on pause the toggle stays, the state is off; Paused is reported.
func TestEnabledOnPause(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	s.Paused = true
	s.Tunnels = nil
	s.Switches = switches("work", "de", "fi")
	s.Rules = allFallback()
	got := statusOf(t, s)
	if !got.Paused {
		t.Error("Paused = false on pause")
	}
	want := map[string]bool{"work": true, "home": false, "de": true, "fi": true, "bad": false}
	for name, en := range want {
		ts, ok := tunnelByName(got, name)
		if !ok {
			t.Errorf("tunnel %s missing", name)
			continue
		}
		if ts.Enabled != en {
			t.Errorf("tunnel %s: Enabled = %v on pause, want %v (the toggle)", name, ts.Enabled, en)
		}
		if ts.State != "off" {
			t.Errorf("tunnel %s: State = %q on pause, want off", name, ts.State)
		}
		if ts.Interface != "" || ts.Error != "" {
			t.Errorf("tunnel %s: interface %q / error %q on pause", name, ts.Interface, ts.Error)
		}
	}
	if got.Icon != "paused" {
		t.Errorf("icon %q, want paused", got.Icon)
	}
}

// Enabled is the toggle, not "is running": an enabled tunnel that is not
// running is Enabled with state off; a not paused daemon reports Paused false.
func TestEnabledIsToggle(t *testing.T) {
	f := newFixture(t)
	s := upState(f)
	s.Switches["home"] = true // enabled, but not running
	got := statusOf(t, s)
	if got.Paused {
		t.Error("Paused = true without pause")
	}
	home, _ := tunnelByName(got, "home")
	if !home.Enabled || home.State != "off" {
		t.Errorf("home: Enabled %v State %q, want true and off", home.Enabled, home.State)
	}
	s.Switches["work"] = false
	delete(s.Tunnels, "work")
	work, _ := tunnelByName(statusOf(t, s), "work")
	if work.Enabled {
		t.Error("work: Enabled with the toggle off")
	}
}

func ruleReasons(t *testing.T, s *State) []string {
	t.Helper()
	got := statusOf(t, s)
	out := make([]string, len(got.Rules))
	for i, r := range got.Rules {
		out[i] = r.Reason
	}
	return out
}

func wantReasons(t *testing.T, name string, got []string, want map[int]string) {
	t.Helper()
	for i, r := range got {
		if r != want[i] {
			t.Errorf("%s: rule %d reason %q, want %q", name, i, r, want[i])
		}
	}
}

// design 14: reason of a rule on a backup or in fallback.
func TestRuleReason(t *testing.T) {
	f := newFixture(t)

	// paused: every rule with a via is in fallback with "paused"; a direct rule has none
	s := newState(f)
	s.Paused = true
	s.Tunnels = nil
	s.Switches = switches("work", "de", "fi")
	s.Rules = allFallback()
	wantReasons(t, "paused", ruleReasons(t, s),
		map[int]string{rTun: "paused", rAI: "paused", rDefFall: "paused", rOrg: "paused", rTg: "paused"})

	// the rules not degraded have no reason
	s = upState(f)
	wantReasons(t, "healthy", ruleReasons(t, s), map[int]string{rAI: "disabled", rDefFall: "disabled", rTg: "disabled"})

	// home is off by the toggle: rAI, rDefFall in fallback and rTg on the backup
	// are there because of "disabled"
	// design 14: dead — enabled by the toggle but dead
	s = upState(f)
	s.Switches["home"] = true
	s.Tunnels["home"] = TunnelRuntime{Interface: "utun9", Dead: true, Reason: "no handshake"}
	wantReasons(t, "home dead", ruleReasons(t, s), map[int]string{rAI: "dead", rDefFall: "dead", rTg: "dead"})

	// ... or failed to start
	s = upState(f)
	s.Switches["home"] = true
	s.Tunnels["home"] = TunnelRuntime{Err: badErr}
	wantReasons(t, "home error", ruleReasons(t, s), map[int]string{rAI: "dead", rDefFall: "dead", rTg: "dead"})

	// the backup serves because the first via is dead
	s = upState(f)
	s.Switches["home"] = true
	s.Tunnels["home"] = TunnelRuntime{Interface: "utun9", Dead: true}
	got := statusOf(t, s).Rules[rTg]
	if got.Tunnel != "de" || !got.Degraded || got.Reason != "dead" {
		t.Errorf("backup rule: %+v, want tunnel de, degraded, reason dead", got)
	}

	// mixed: de is toggled off, fi is dead: fallback, "dead" (one enabled tunnel failed)
	s = upState(f)
	s.Rules = allFallback()
	s.Switches["de"] = false
	delete(s.Tunnels, "de")
	s.Tunnels["fi"] = TunnelRuntime{Interface: "utun8", Dead: true}
	if r := ruleReasons(t, s)[rTun]; r != "dead" {
		t.Errorf("de off, fi dead: reason %q, want dead", r)
	}
	// mixed the other way round
	s = upState(f)
	s.Rules = allFallback()
	s.Switches["fi"] = false
	delete(s.Tunnels, "fi")
	s.Tunnels["de"] = TunnelRuntime{Interface: "utun8", Dead: true}
	if r := ruleReasons(t, s)[rTun]; r != "dead" {
		t.Errorf("de dead, fi off: reason %q, want dead", r)
	}
	// both off by the toggle
	s = upState(f)
	s.Rules = allFallback()
	s.Switches["de"], s.Switches["fi"] = false, false
	delete(s.Tunnels, "de")
	delete(s.Tunnels, "fi")
	if r := ruleReasons(t, s)[rTun]; r != "disabled" {
		t.Errorf("de and fi off: reason %q, want disabled", r)
	}
	// both dead
	s = upState(f)
	s.Rules = allFallback()
	s.Tunnels["de"] = TunnelRuntime{Interface: "utun8", Dead: true}
	s.Tunnels["fi"] = TunnelRuntime{Err: badErr}
	if r := ruleReasons(t, s)[rTun]; r != "dead" {
		t.Errorf("de and fi dead: reason %q, want dead", r)
	}
}

// A rule on its first via, or direct, has no reason.
func TestRuleReasonNone(t *testing.T) {
	f := newFixture(t)
	s := upState(f)
	got := ruleReasons(t, s)
	for _, i := range []int{rTun, rCorp, rOrg} {
		if got[i] != "" {
			t.Errorf("rule %d on its via[0] or direct: reason %q, want none", i, got[i])
		}
	}
}
