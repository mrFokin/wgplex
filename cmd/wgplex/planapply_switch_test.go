package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 10.2 and 11: switches (state.json toggles) decide a
// tunnel; a tunnel without an entry follows its autostart on EVERY successful
// apply, the first one and a repeated one alike; a removed tunnel is stopped;
// a running, enabled tunnel with a changed .conf restarts. Names carry the
// Switch prefix so as not to clash with apply_test.go.

// switchTunnel describes one tunnel of a fixture config.
type switchTunnel struct {
	name      string
	autostart bool
	mtu       int // part of the .conf; a changed value is a changed .conf
}

func switchKey(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// switchKeys keeps generated keys per tunnel name, so that the same tunnel
// in cur and next has the same keys and differs only by what a test changes.
type switchKeys map[string][2]string

func (ks switchKeys) of(t *testing.T, name string) [2]string {
	if k, ok := ks[name]; ok {
		return k
	}
	k := [2]string{switchKey(t), switchKey(t)}
	ks[name] = k
	return k
}

// switchConfig builds a config from tunnels in the given order.
func switchConfig(t *testing.T, ks switchKeys, tunnels ...switchTunnel) *config.Config {
	t.Helper()
	var y strings.Builder
	y.WriteString("tunnels:\n")
	files := map[string][]byte{}
	for i, tn := range tunnels {
		fmt.Fprintf(&y, "  - name: %s\n    conf: %s.conf\n    routes: rules\n    autostart: %v\n", tn.name, tn.name, tn.autostart)
		k := ks.of(t, tn.name)
		mtu := ""
		if tn.mtu != 0 {
			mtu = fmt.Sprintf("MTU = %d\n", tn.mtu)
		}
		files[tn.name+".conf"] = []byte(fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nAddress = 10.50.%d.2/32\n%s\n[Peer]\nPublicKey = %s\nEndpoint = 203.0.113.%d:51820\nAllowedIPs = 10.50.%d.0/24\n",
			k[0], i, mtu, k[1], i+1, i))
	}
	files["wgplex.yaml"] = []byte(y.String())
	cfg, _, err := config.Load(files)
	if err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	return cfg
}

func switchSet(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func switchTrue(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func switchPlan(t *testing.T, cur, next *config.Config, switches, running map[string]bool) (enabled map[string]bool, stop, start []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("planApply panicked: %v", r)
		}
	}()
	return planApply(cur, next, switches, running)
}

func switchSame(a, b []string) bool { return len(a) == 0 && len(b) == 0 || slices.Equal(a, b) }

type switchWant struct {
	enabled []string // sorted names of enabled tunnels
	stop    []string
	start   []string
}

func switchCheck(t *testing.T, cur, next *config.Config, switches, running map[string]bool, want switchWant) {
	t.Helper()
	enabled, stop, start := switchPlan(t, cur, next, switches, running)
	if got := switchTrue(enabled); !switchSame(got, want.enabled) {
		t.Errorf("enabled = %v, want %v", got, want.enabled)
	}
	if !switchSame(stop, want.stop) {
		t.Errorf("stop = %v, want %v", stop, want.stop)
	}
	if !switchSame(start, want.start) {
		t.Errorf("start = %v, want %v", start, want.start)
	}
}

func TestSwitchFirstApplyOnOverridesAutostart(t *testing.T) {
	// design 11: t1:true with autostart: false is enabled
	next := switchConfig(t, switchKeys{}, switchTunnel{name: "t1"})
	switchCheck(t, nil, next, switchSet("t1"), nil,
		switchWant{enabled: []string{"t1"}, start: []string{"t1"}})
}

func TestSwitchFirstApplyOffOverridesAutostart(t *testing.T) {
	// design 11: t1:false with autostart: true is disabled
	next := switchConfig(t, switchKeys{}, switchTunnel{name: "t1", autostart: true})
	switchCheck(t, nil, next, map[string]bool{"t1": false}, nil, switchWant{})
}

func TestSwitchFirstApplyNoEntryFollowsAutostart(t *testing.T) {
	// design 10.2: without an entry the tunnel follows autostart
	next := switchConfig(t, switchKeys{},
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "b"})
	switchCheck(t, nil, next, nil, nil,
		switchWant{enabled: []string{"a"}, start: []string{"a"}})
}

func TestSwitchRepeatedApplyNoEntryFollowsAutostart(t *testing.T) {
	// design 10.2: with cur != nil a tunnel without an entry also follows
	// autostart: an autostart edit takes effect with the next reload
	ks := switchKeys{}
	cur := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: false},
		switchTunnel{name: "b", autostart: true})
	next := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "b", autostart: false})
	// b is running (it was enabled by autostart), a is not
	switchCheck(t, cur, next, nil, switchSet("b"),
		switchWant{enabled: []string{"a"}, stop: []string{"b"}, start: []string{"a"}})
}

func TestSwitchRepeatedApplyEntryWins(t *testing.T) {
	// design 11: an explicit toggle wins over autostart on a repeated apply
	ks := switchKeys{}
	cur := switchConfig(t, ks,
		switchTunnel{name: "on", autostart: false},
		switchTunnel{name: "off", autostart: true})
	next := switchConfig(t, ks,
		switchTunnel{name: "on", autostart: false},
		switchTunnel{name: "off", autostart: true})
	switches := map[string]bool{"on": true, "off": false}
	// "off" is running until the apply stops it; "on" is not running yet
	switchCheck(t, cur, next, switches, switchSet("off"),
		switchWant{enabled: []string{"on"}, stop: []string{"off"}, start: []string{"on"}})
}

func TestSwitchRepeatedApplyKeepsRunning(t *testing.T) {
	// design 10.2: an unchanged running tunnel is neither stopped nor started
	ks := switchKeys{}
	cfg := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	next := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	switchCheck(t, cfg, next, switchSet("a"), switchSet("a"),
		switchWant{enabled: []string{"a"}})
}

func TestSwitchNewTunnelByAutostart(t *testing.T) {
	// design 10.2: a new tunnel is enabled by autostart (and by its switch)
	ks := switchKeys{}
	cur := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	next := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "auto", autostart: true},
		switchTunnel{name: "manual"})
	switchCheck(t, cur, next, nil, switchSet("a"),
		switchWant{enabled: []string{"a", "auto"}, start: []string{"auto"}})
}

func TestSwitchRemovedTunnelStopped(t *testing.T) {
	// design 10.2: a removed tunnel is stopped; it is not in enabled even
	// when state.json still has an entry for it
	ks := switchKeys{}
	cur := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "gone", autostart: true})
	next := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	switchCheck(t, cur, next, map[string]bool{"gone": true}, switchSet("a", "gone"),
		switchWant{enabled: []string{"a"}, stop: []string{"gone"}})
}

func TestSwitchRemovedNotRunningNotStopped(t *testing.T) {
	// design 10.2: stop lists only running tunnels
	ks := switchKeys{}
	cur := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "idle"})
	next := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	switchCheck(t, cur, next, nil, switchSet("a"),
		switchWant{enabled: []string{"a"}})
}

func TestSwitchConfChangedRestarts(t *testing.T) {
	// design 10.2: a running, enabled tunnel with a changed .conf restarts
	// (stop and start); a YAML-only change does not
	ks := switchKeys{}
	cur := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true},
		switchTunnel{name: "b", autostart: true})
	next := switchConfig(t, ks,
		switchTunnel{name: "a", autostart: true, mtu: 1380},
		switchTunnel{name: "b", autostart: true})
	switchCheck(t, cur, next, nil, switchSet("a", "b"),
		switchWant{enabled: []string{"a", "b"}, stop: []string{"a"}, start: []string{"a"}})
}

func TestSwitchConfChangedDisabledNotRestarted(t *testing.T) {
	// design 10.2: a switched-off tunnel is not restarted for a changed
	// .conf, and an explicit off stops it when it runs
	ks := switchKeys{}
	cur := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	next := switchConfig(t, ks, switchTunnel{name: "a", autostart: true, mtu: 1380})
	off := map[string]bool{"a": false}
	switchCheck(t, cur, next, off, nil, switchWant{})
	switchCheck(t, cur, next, off, switchSet("a"), switchWant{stop: []string{"a"}})
}

func TestSwitchConfChangedNotRunningJustStarts(t *testing.T) {
	// design 10.2: an enabled tunnel that is not running is started once,
	// not stopped first
	ks := switchKeys{}
	cur := switchConfig(t, ks, switchTunnel{name: "a", autostart: true})
	next := switchConfig(t, ks, switchTunnel{name: "a", autostart: true, mtu: 1380})
	switchCheck(t, cur, next, nil, nil,
		switchWant{enabled: []string{"a"}, start: []string{"a"}})
}
