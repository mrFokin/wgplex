package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/rpc"
	"github.com/mrFokin/wgplex/internal/state"
)

// Tests of design 12 (pause) on the daemon paths that make no system calls:
// pause keeps the toggles, tunnel.enable/disable on pause change the toggle
// and bring nothing up, pause and resume are idempotent and work without a
// config, a paused daemon starts nothing. Resume with tunnels to bring up
// needs the system (host routes, utun), so it is tried only with every
// toggle off.

// pausedDaemon is a testDaemon with the base config applied and its
// state.json path.
func pausedDaemon(t *testing.T, toggles state.State) (*daemon, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	d := testDaemon(t, path, toggles)
	d.cfg = loadConfig(t, baseYAML(baseTunnels()...), newConfFiles(t).texts(nil))
	return d, path
}

func loadState(t *testing.T, path string) state.State {
	t.Helper()
	s, err := state.Load(path)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return s
}

// design 12: pause writes paused to state.json; the toggles of the tunnels
// are not changed, neither in memory nor on disk, nor in status.get (Switches).
func TestDaemonPauseKeepsToggles(t *testing.T) {
	toggles := map[string]bool{"home": true, "de": false}
	d, path := pausedDaemon(t, state.State{Tunnels: maps.Clone(toggles)})
	if err := d.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if !d.toggles.Paused || !maps.Equal(d.toggles.Tunnels, toggles) {
		t.Errorf("toggles = %+v, want paused with %v", d.toggles, toggles)
	}
	s := loadState(t, path)
	if !s.Paused || !maps.Equal(s.Tunnels, toggles) {
		t.Errorf("state.json = %+v, want paused with %v", s, toggles)
	}
	st := d.State()
	if !st.Paused {
		t.Error("State().Paused = false")
	}
	if len(st.Tunnels) != 0 {
		t.Errorf("State().Tunnels = %v, want no running tunnel", st.Tunnels)
	}
	// Effective toggles: explicit ones, the rest by autostart (work, fi on).
	want := map[string]bool{"work": true, "home": true, "de": false, "fi": true}
	if !maps.Equal(st.Switches, want) {
		t.Errorf("State().Switches = %v, want %v", st.Switches, want)
	}
}

// design 12: pause without a toggle for a tunnel does not write one either.
func TestDaemonPauseWritesNoToggles(t *testing.T) {
	d, path := pausedDaemon(t, state.State{})
	if err := d.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if s := loadState(t, path); !s.Paused || len(s.Tunnels) != 0 {
		t.Errorf("state.json = %+v, want paused only", s)
	}
}

// design 12, 14: pause and resume are idempotent.
func TestDaemonPauseResumeIdempotent(t *testing.T) {
	d, path := pausedDaemon(t, state.State{Tunnels: map[string]bool{"work": false, "home": false, "de": false, "fi": false}})
	for i := range 2 {
		if err := d.Pause(); err != nil {
			t.Fatalf("Pause #%d: %v", i+1, err)
		}
		if s := loadState(t, path); !s.Paused {
			t.Errorf("Pause #%d: state.json = %+v, want paused", i+1, s)
		}
	}
	// Every toggle is off: resume brings nothing up, so no system call.
	for i := range 2 {
		if err := d.Resume(); err != nil {
			t.Fatalf("Resume #%d: %v", i+1, err)
		}
		if s := loadState(t, path); s.Paused {
			t.Errorf("Resume #%d: state.json = %+v, want not paused", i+1, s)
		}
		if d.toggles.Paused || d.State().Paused {
			t.Errorf("Resume #%d: still paused in memory", i+1)
		}
	}
	// Resume does not change the toggles.
	if s := loadState(t, path); len(s.Tunnels) != 4 || s.Tunnels["work"] {
		t.Errorf("state.json tunnels = %v, want the four false toggles", s.Tunnels)
	}
}

// design 12, 14 (plan M3, decision 7): daemon.pause and daemon.resume work
// without a config.
func TestDaemonPauseResumeNoConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	d := testDaemon(t, path, state.State{})
	if err := d.Pause(); err != nil {
		t.Fatalf("Pause without a config: %v", err)
	}
	if !d.State().Paused {
		t.Error("State().Paused = false after Pause")
	}
	if s := loadState(t, path); !s.Paused {
		t.Errorf("state.json = %+v, want paused (the pause survives a restart)", s)
	}
	if err := d.Resume(); err != nil {
		t.Fatalf("Resume without a config: %v", err)
	}
	if d.State().Paused {
		t.Error("State().Paused = true after Resume")
	}
	if s := loadState(t, path); s.Paused {
		t.Errorf("state.json = %+v, want not paused", s)
	}
	// Resume when not paused is a success too.
	if err := d.Resume(); err != nil {
		t.Errorf("Resume when not paused: %v", err)
	}
}

// design 12: tunnel.enable on pause turns the toggle on and brings nothing
// up: starts_on_resume. The toggle is in state.json, the pause stays.
func TestDaemonEnableOnPause(t *testing.T) {
	d, path := pausedDaemon(t, state.State{})
	if err := d.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	res, err := d.Enable("home")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !res.StartsOnResume {
		t.Errorf("Enable on pause = %+v, want StartsOnResume", res)
	}
	st := d.State()
	if len(st.Tunnels) != 0 {
		t.Errorf("State().Tunnels = %v, want nothing brought up on pause", st.Tunnels)
	}
	if !st.Switches["home"] {
		t.Errorf("State().Switches = %v, want home on", st.Switches)
	}
	s := loadState(t, path)
	if v, ok := s.Tunnels["home"]; !ok || !v || !s.Paused {
		t.Errorf("state.json = %+v, want home true and paused", s)
	}

	// A tunnel that is on already (autostart) gets the same answer.
	res, err = d.Enable("work")
	if err != nil || !res.StartsOnResume {
		t.Errorf("Enable(work) on pause = %+v, %v; want StartsOnResume", res, err)
	}
}

// design 12, 14: errors of tunnel.enable are the same on pause: unknown
// tunnel is code 3, no config is code 2.
func TestDaemonEnableOnPauseErrors(t *testing.T) {
	d, _ := pausedDaemon(t, state.State{})
	if err := d.Pause(); err != nil {
		t.Fatal(err)
	}
	_, err := d.Enable("nosuch")
	wantCode(t, "Enable(nosuch)", err, rpc.CodeUnknownTunnel)
	wantCode(t, "Disable(nosuch)", d.Disable("nosuch"), rpc.CodeUnknownTunnel)

	nocfg := testDaemon(t, filepath.Join(t.TempDir(), "state.json"), state.State{})
	if err := nocfg.Pause(); err != nil {
		t.Fatal(err)
	}
	_, err = nocfg.Enable("home")
	wantCode(t, "Enable without a config", err, rpc.CodeNoConfig)
	wantCode(t, "Disable without a config", nocfg.Disable("home"), rpc.CodeNoConfig)
}

// design 12: tunnel.disable on pause turns the toggle off in state.json;
// the pause stays.
func TestDaemonDisableOnPause(t *testing.T) {
	d, path := pausedDaemon(t, state.State{})
	if err := d.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := d.Disable("work"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	s := loadState(t, path)
	if v, ok := s.Tunnels["work"]; !ok || v || !s.Paused {
		t.Errorf("state.json = %+v, want work false and paused", s)
	}
	st := d.State()
	if st.Switches["work"] {
		t.Errorf("State().Switches = %v, want work off", st.Switches)
	}
	if !st.Paused || len(st.Tunnels) != 0 {
		t.Errorf("State() = paused %v, tunnels %v; want paused, nothing up", st.Paused, st.Tunnels)
	}
}

// design 12: the pause of state.json survives a restart: a daemon built on
// the loaded state is paused, and the switches are kept.
func TestDaemonPauseSurvivesRestart(t *testing.T) {
	d, path := pausedDaemon(t, state.State{Tunnels: map[string]bool{"home": true}})
	if err := d.Pause(); err != nil {
		t.Fatal(err)
	}
	loaded := loadState(t, path)
	d2 := testDaemon(t, path, loaded)
	if !d2.State().Paused {
		t.Error("a daemon started on a paused state.json is not paused")
	}
	if !d2.toggles.Paused || !d2.toggles.Tunnels["home"] {
		t.Errorf("toggles = %+v, want paused with home on", d2.toggles)
	}
}

// design 12: "Pause: tunnels are down, nothing is brought up": toStart is
// empty on pause and the autostart/toggle set otherwise (design 10.2).
func TestDaemonToStartOnPause(t *testing.T) {
	next := loadConfig(t, baseYAML(baseTunnels()...), newConfFiles(t).texts(nil))
	names := func(ts []*config.Tunnel) []string {
		var out []string
		for _, t := range ts {
			out = append(out, t.Name)
		}
		return out
	}

	d := testDaemon(t, filepath.Join(t.TempDir(), "state.json"), state.State{Tunnels: map[string]bool{"home": true, "fi": false}})
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if got, want := names(d.toStart(next)), []string{"work", "home", "de"}; !slices.Equal(got, want) {
		t.Errorf("toStart not paused = %v, want %v (toggles, then autostart, config order)", got, want)
	}
	d.toggles.Paused = true
	if got := d.toStart(next); len(got) != 0 {
		t.Errorf("toStart paused = %v, want none", names(got))
	}
	d.toggles.Paused = false
	if got := d.toStart(next); len(got) != 3 {
		t.Errorf("toStart after the pause = %v, want 3 again", names(got))
	}
}

// design 12, 10.2: reload on pause (replan) starts nothing and keeps the
// toggles; without the pause it hands out the tunnels to start.
func TestDaemonReplanOnPause(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("replan syncs the routing table: not as root")
	}
	next := loadConfig(t, baseYAML(baseTunnels()...), newConfFiles(t).texts(nil))
	toggles := map[string]bool{"home": true}

	d := testDaemon(t, filepath.Join(t.TempDir(), "state.json"), state.State{Tunnels: maps.Clone(toggles), Paused: true})
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if got := d.replan(next, nil); len(got) != 0 {
		t.Errorf("replan paused = %d tunnels to start, want none", len(got))
	}
	if len(d.tunnels) != 0 {
		t.Errorf("tunnels after replan on pause = %v, want none", d.tunnels)
	}
	if !maps.Equal(d.toggles.Tunnels, toggles) {
		t.Errorf("toggles = %v, want %v kept", d.toggles.Tunnels, toggles)
	}

	d2 := testDaemon(t, filepath.Join(t.TempDir(), "state.json"), state.State{Tunnels: maps.Clone(toggles)})
	d2.opMu.Lock()
	defer d2.opMu.Unlock()
	if got := d2.replan(next, nil); len(got) != 4 {
		t.Errorf("replan not paused = %d tunnels to start, want 4 (work, home, de, fi)", len(got))
	}
}

// design 9.1, 12: fallback: block holds on pause: the tunnels are stopped,
// the rule goes to fallback and the table keeps its reject routes.
func TestDaemonPauseBlockHolds(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Pause syncs the routing table: not as root")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	d := testDaemon(t, path, state.State{})
	d.cfg = loadConfig(t, "tunnels:\n"+tunnelYAML("de", "rules", true)+`services:
  tg:
    cidrs: [198.51.100.0/24]
rules:
  - services: [tg]
    via: [de]
    fallback: block
`, newConfFiles(t).texts(nil))
	// Before the pause: de serves the rule and a route goes to it.
	d.mu.Lock()
	d.tunnels["de"] = &runTunnel{name: "de", index: 7}
	d.rules = []router.RuleState{{Tunnel: "de"}}
	d.env = router.Env{Ifaces: map[string]int{"de": 7}}
	d.mu.Unlock()

	if err := d.Pause(); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	st := d.State()
	if len(st.Tunnels) != 0 {
		t.Errorf("tunnels on pause = %v, want none", st.Tunnels)
	}
	if len(st.Rules) != 1 || !st.Rules[0].Fallback {
		t.Errorf("rules on pause = %+v, want the rule in fallback", st.Rules)
	}
	found := false
	for _, r := range st.Table {
		if r.Prefix.String() == "198.51.100.0/24" && r.Target == router.TargetReject {
			found = true
		}
	}
	if !found {
		t.Errorf("table on pause = %v, want a reject route on 198.51.100.0/24", st.Table)
	}
	// The DNS capture and the zones are a function of the config: untouched.
	if s := loadState(t, path); !s.Paused || len(s.Tunnels) != 0 {
		t.Errorf("state.json = %+v, want paused, no toggles written", s)
	}
}
