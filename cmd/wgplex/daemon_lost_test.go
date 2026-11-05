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
