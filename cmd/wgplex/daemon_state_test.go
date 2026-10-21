package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/rpc"
)

// Tests of the daemon state over state.json (design 11) and of the replies of
// the mutating methods without an applied config (design 14), not the
// implementation. No root: the cases here never touch a tunnel or the system
// DNS.

// newTestDaemon returns a daemon with a discarded log and no tunnels; srv is
// only the resolver the daemon hooks Sync into.
func newTestDaemon(t *testing.T, configDir, statePath string, toggles map[string]bool) *daemon {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newDaemon(context.Background(), &dns.Server{}, log, configDir, statePath, toggles)
}

// design 11: the toggles map is usable from the start — SetEnabled and
// DisableAll record into it even when state.json had no records (nil).
func TestNewDaemonNilToggles(t *testing.T) {
	d := newTestDaemon(t, "", "", nil)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.toggles == nil {
		t.Fatal("toggles is nil, want an empty map")
	}
	d.toggles["work"] = true // must not panic
}

// design 14: tunnel.disableAll without an applied config is error 2, as
// tunnel.setEnabled is (data: none).
func TestDisableAllNoConfig(t *testing.T) {
	d := newTestDaemon(t, "", "", nil)
	err := d.DisableAll()
	var jerr *jrpc.JRPCError
	if !errors.As(err, &jerr) || jerr.Code != rpc.CodeNoConfig {
		t.Fatalf("DisableAll without a config = %v, want error %d", err, rpc.CodeNoConfig)
	}
}

// brokenConfigDir returns a config directory with an unparsable wgplex.yaml.
func brokenConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte("tunnels: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// design 4.1: a broken config at startup leaves no state of ours — the
// routes and the DNS key of a previous run are synced with the empty state
// now, not left until shutdown. As root the empty sync would change the
// routing table of the host, so the test runs as a user only.
func TestApplyConfigBrokenSyncsEmptyState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the empty sync would change the routing table")
	}
	var released int
	d := newTestDaemon(t, brokenConfigDir(t), "", nil)
	d.release = func(*slog.Logger) error {
		released++
		return nil
	}
	_, err := d.Reload()
	var jerr *jrpc.JRPCError
	if !errors.As(err, &jerr) || jerr.Code != rpc.CodeConfigInvalid {
		t.Fatalf("Reload with a broken config = %v, want error %d", err, rpc.CodeConfigInvalid)
	}
	if released != 1 {
		t.Errorf("DNS released %d times, want once", released)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg != nil {
		t.Error("cfg is set after a broken config")
	}
	if len(d.cfgErrs) == 0 {
		t.Error("config errors are not recorded")
	}
	if d.table != nil {
		t.Errorf("table = %v, want empty", d.table)
	}
}

// design 10.2: a failed reload keeps the applied config working and removes
// nothing; the empty-state sync is for the start without a config only.
func TestApplyConfigBrokenKeepsPrevious(t *testing.T) {
	var released int
	d := newTestDaemon(t, brokenConfigDir(t), "", nil)
	prev := &config.Config{}
	d.cfg = prev
	d.release = func(*slog.Logger) error {
		released++
		return nil
	}
	_, err := d.Reload()
	var jerr *jrpc.JRPCError
	if !errors.As(err, &jerr) || jerr.Code != rpc.CodeConfigInvalid {
		t.Fatalf("Reload with a broken config = %v, want error %d", err, rpc.CodeConfigInvalid)
	}
	if released != 0 {
		t.Errorf("DNS released %d times, want none", released)
	}
	if d.cfg != prev {
		t.Error("the applied config was replaced by a failed reload")
	}
	if len(d.cfgErrs) == 0 {
		t.Error("config errors are not recorded")
	}
}
