package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/state"
)

// design 9.1: the resolver stopping after it listened does not stop the
// daemon nor release the key; listening is tried again at once and, with
// the port busy, by retryListen later, as for a busy port at start.
func TestDaemonLostRetries(t *testing.T) {
	busy := errors.New("address already in use")
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	if !d.retryListen() {
		t.Fatal("not listening")
	}
	d.testCapture([]string{"example.com"})

	f.listenErrs = []error{busy}
	if d.lost(errors.New("dns udp: read: closed")) {
		t.Fatal("lost: listening again on a busy port")
	}
	if f.listens != 2 {
		t.Errorf("listens after lost = %d, want 2 (tried at once)", f.listens)
	}
	if e := dnsError(d); !strings.Contains(e, "already in use") {
		t.Errorf("DNSError = %q, want the busy port", e)
	}
	if f.releases != 0 || !f.present || !slices.Equal(f.key, []string{"example.com"}) {
		t.Errorf("key after lost: releases %d, present %v, zones %v; want kept", f.releases, f.present, f.key)
	}
	if !d.retryListen() {
		t.Fatal("not listening once the port is free")
	}
	if e := dnsError(d); e != "" {
		t.Errorf("DNSError = %q after listening again", e)
	}

	// The port free at once: listening again right away.
	if !d.lost(errors.New("dns tcp: accept: closed")) {
		t.Error("lost: not listening again on a free port")
	}
	if e := dnsError(d); e != "" {
		t.Errorf("DNSError = %q after listening again", e)
	}
}

// plan m4 decision 9, design 9.1: a start with an invalid config, a block
// snapshot with domains and the port busy writes the zones of the snapshot
// to the key and keeps running; the busy port is in status.
func TestDaemonStartupBlockBusyPort(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("startup syncs the routing table: not as root")
	}
	busy := errors.New("address already in use")
	f := &fakeDNS{listenErrs: []error{busy}}
	d := dnsDaemon(t, f)
	d.toggles.Block = &state.Block{CIDRs: []string{"198.51.100.0/24"}, Domains: []string{"tg.example", "=api.example"}}
	if err := os.WriteFile(filepath.Join(d.dir, "wgplex.yaml"), []byte("bogus_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if d.retryListen() {
		t.Fatal("listening on a busy port")
	}
	d.startup()

	if d.blockCfg == nil || d.cfg != nil {
		t.Fatalf("blockCfg %v, cfg %v; want the snapshot in force, no config", d.blockCfg, d.cfg)
	}
	want := d.blockCfg.Zones()
	if len(want) != 2 {
		t.Fatalf("zones of the snapshot = %v, want two", want)
	}
	if !f.present || !slices.Equal(f.key, want) || f.releases != 0 {
		t.Errorf("key: present %v, zones %v, releases %d; want %v written", f.present, f.key, f.releases, want)
	}
	if e := dnsError(d); !strings.Contains(e, "already in use") {
		t.Errorf("DNSError = %q, want the busy port", e)
	}
	if d.listening {
		t.Error("listening after a busy port")
	}
}

// warnings of status.get hold the busy resolver port and the failed check of
// the capture while they last, next to the warnings of the config (which an
// apply replaces), and lose them once fixed; the icon stays warn meanwhile.
func TestStatusWarningsDNS(t *testing.T) {
	has := func(ws []string, sub string) bool {
		return slices.ContainsFunc(ws, func(w string) bool { return strings.Contains(w, sub) })
	}
	busy := errors.New("address already in use")
	f := &fakeDNS{listenErrs: []error{busy}, verifyErr: errors.New("zones missing: example.com")}
	d := dnsDaemon(t, f)
	d.retryListen()
	d.testCapture([]string{"example.com"})
	d.locked(func() { d.warnings = []string{"config warning"} }) // as an apply leaves them

	ws := d.snapshot().Warnings
	if !has(ws, "config warning") || !has(ws, "already in use") || !has(ws, "zones missing") || len(ws) != 3 {
		t.Errorf("warnings = %q, want the config one, the busy port and the check", ws)
	}
	if d.snapshot().DNSError == "" {
		t.Error("DNSError empty: icon not warn")
	}
	if got := d.warnings; len(got) != 1 {
		t.Errorf("d.warnings = %q: the DNS warnings must not be stored in it", got)
	}

	d.retryListen()
	ws = d.snapshot().Warnings
	if has(ws, "already in use") || !has(ws, "zones missing") {
		t.Errorf("warnings after listening = %q, want only the check left", ws)
	}
	f.verifyErr = nil
	d.testCapture([]string{"example.com"})
	if ws = d.snapshot().Warnings; len(ws) != 1 || ws[0] != "config warning" {
		t.Errorf("warnings after the check passed = %q, want the config one", ws)
	}
}

// A failed write of the key is one warning, not repeated by statusWarnings.
func TestStatusWarningsCaptureOnce(t *testing.T) {
	f := &fakeDNS{captureErr: errors.New("no root")}
	d := dnsDaemon(t, f)
	d.testCapture([]string{"example.com"})
	n := 0
	for _, w := range d.snapshot().Warnings {
		if strings.Contains(w, "no root") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("warnings = %q, want the failed write once", d.snapshot().Warnings)
	}
}
