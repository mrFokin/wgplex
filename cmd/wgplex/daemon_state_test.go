package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/rpc"
	"github.com/mrFokin/wgplex/internal/state"
)

// Tests of the daemon paths that make no system calls: without a config, and
// tunnel.disableAll with no tunnel running.

func testDaemon(t *testing.T, statePath string, toggles state.State) *daemon {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newDaemon(context.Background(), &dns.Server{Log: log}, log, t.TempDir(), statePath, toggles, nil)
}

func wantCode(t *testing.T, what string, err error, code int) {
	t.Helper()
	var je *jrpc.JRPCError
	if !errors.As(err, &je) || je.Code != code {
		t.Errorf("%s: err = %v, want JSON-RPC code %d", what, err, code)
	}
}

// design 14: tunnel.* without an applied config is code 2, disableAll too.
func TestDaemonNoConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	d := testDaemon(t, path, state.State{})
	wantCode(t, "DisableAll", d.DisableAll(), rpc.CodeNoConfig)
	wantCode(t, "SetEnabled", d.SetEnabled("x", true), rpc.CodeNoConfig)
	if s, err := state.Load(path); err != nil || len(s.Tunnels) != 0 {
		t.Errorf("state.json = %+v, %v; want nothing written", s, err)
	}
}

// design 11, 12: disableAll writes false for every tunnel of the config; a
// toggle of a tunnel gone from it is left to Prune.
func TestDaemonDisableAllWritesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	d := testDaemon(t, path, state.State{Tunnels: map[string]bool{"home": true, "gone": true}})
	d.cfg = loadConfig(t, baseYAML(baseTunnels()...), newConfFiles(t).texts(nil))
	if err := d.DisableAll(); err != nil {
		t.Fatalf("DisableAll: %v", err)
	}
	s, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"work": false, "home": false, "de": false, "fi": false, "gone": true}
	if !maps.Equal(s.Tunnels, want) {
		t.Errorf("state.json tunnels = %v, want %v", s.Tunnels, want)
	}
}

// design 11: a failed write of state.json does not fail the action: a
// warning in status.get.
func TestDaemonDisableAllSaveFails(t *testing.T) {
	d := testDaemon(t, filepath.Join(t.TempDir(), "nodir", "state.json"), state.State{})
	d.cfg = loadConfig(t, baseYAML(baseTunnels()...), newConfFiles(t).texts(nil))
	if err := d.DisableAll(); err != nil {
		t.Fatalf("DisableAll: %v", err)
	}
	if len(d.warnings) != 1 || !strings.HasPrefix(d.warnings[0], "state not saved: ") {
		t.Errorf("warnings = %q, want one about state.json", d.warnings)
	}
	if v, ok := d.toggles.Tunnels["work"]; !ok || v {
		t.Errorf("toggles = %v, want work false in memory", d.toggles.Tunnels)
	}
}

// design 4.1: without a config the table to sync holds only the endpoint
// routes of ours; right after start there are none, so the first sync
// removes the routes of the previous run.
func TestTableForNoConfig(t *testing.T) {
	if got := tableFor(nil, nil, nil, nil, nil); len(got) != 0 {
		t.Errorf("tableFor(nil) = %v, want empty", got)
	}
	a := netip.MustParseAddr("203.0.113.7")
	got := tableFor(nil, nil, nil, nil, map[netip.Addr]*hostRoute{a: {refs: 1}})
	if len(got) != 1 || got[0].Prefix != netip.PrefixFrom(a, 32) || got[0].Source != router.SourceEndpoint {
		t.Errorf("tableFor(nil, hosts) = %v, want the endpoint route to %s", got, a)
	}
}

func TestGroupID(t *testing.T) {
	if gid, err := groupID("4242"); err != nil || gid != 4242 {
		t.Errorf("groupID(4242) = %d, %v", gid, err)
	}
	if gid, err := groupID("wgplex-no-such-group"); err == nil {
		t.Errorf("groupID(unknown) = %d, want an error", gid)
	}
}
