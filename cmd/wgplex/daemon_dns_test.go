package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/state"
)

// fakeDNS is the system DNS layer of a test daemon: the capture key in
// memory and the calls counted.
type fakeDNS struct {
	key      []string // SupplementalMatchDomains of the key
	present  bool     // the key is set
	writes   int
	releases int
	verifies int

	captureErr error
	releaseErr error
	verifyErr  error
	listenErrs []error // returned by successive listen calls; then nil
	listens    int
}

// dnsDaemon is testDaemon with f as its DNS layer.
func dnsDaemon(t *testing.T, f *fakeDNS) *daemon {
	t.Helper()
	d := testDaemon(t, filepath.Join(t.TempDir(), "state.json"), state.State{})
	d.dnsCapture = func(zones []string) error {
		if f.captureErr != nil {
			return f.captureErr
		}
		f.writes++
		f.key, f.present = slices.Clone(zones), true
		return nil
	}
	d.dnsRelease = func() error {
		if f.releaseErr != nil {
			return f.releaseErr
		}
		f.releases++
		f.key, f.present = nil, false
		return nil
	}
	d.dnsCaptured = func() ([]string, bool, error) { return slices.Clone(f.key), f.present, nil }
	d.dnsVerify = func([]string) error { f.verifies++; return f.verifyErr }
	d.dnsListen = func() error {
		f.listens++
		if len(f.listenErrs) > 0 {
			err := f.listenErrs[0]
			f.listenErrs = f.listenErrs[1:]
			return err
		}
		return nil
	}
	return d
}

// Tests do not wait between checks, and a daemon of another test whose
// Reload starts the real resolver binds a free port, not dns.Port.
func init() {
	verifyGap = 0
	dnsAddr = "127.0.0.1:0"
}

// domainsCfg is a config whose one rule names a service with domains.
func domainsCfg(domains ...string) *config.Config {
	var svc config.Service
	for _, n := range domains {
		svc.Domains = append(svc.Domains, config.Domain{Name: n})
	}
	return &config.Config{
		Services: map[string]config.Service{"s": svc},
		Rules:    []config.Rule{{Services: []string{"s"}}},
	}
}

// capture is setCapture under opMu.
func (d *daemon) testCapture(zones []string) string {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.setCapture(zones)
}

func dnsError(d *daemon) string { return d.snapshot().DNSError }

// design 8, plan m4 decision 5: the key is written only when the zones
// change or the key lost them; the same zones write nothing.
func TestSetCaptureWritesOnChange(t *testing.T) {
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	a := []string{"example.com"}
	b := []string{"example.com", "example.org"}

	steps := []struct {
		what   string
		before func()
		zones  []string
		writes int
	}{
		{"first", nil, a, 1},
		{"same zones", nil, a, 1},
		{"same again", nil, a, 1},
		{"new zones", nil, b, 2},
		{"key lost (configd restart)", func() { f.key, f.present = nil, false }, b, 3},
		{"key with other zones", func() { f.key = []string{"other.com"} }, b, 4},
		{"back in line", nil, b, 4},
	}
	for _, s := range steps {
		if s.before != nil {
			s.before()
		}
		if w := d.testCapture(s.zones); w != "" {
			t.Fatalf("%s: warning %q", s.what, w)
		}
		if f.writes != s.writes {
			t.Errorf("%s: writes = %d, want %d", s.what, f.writes, s.writes)
		}
		if !slices.Equal(f.key, s.zones) {
			t.Errorf("%s: key = %v, want %v", s.what, f.key, s.zones)
		}
	}
	if f.releases != 0 {
		t.Errorf("releases = %d, want 0", f.releases)
	}
}

// A key left by the previous run with the same zones is still written
// once: the daemon has not written it itself (the cache is flushed).
func TestSetCaptureLeftoverKey(t *testing.T) {
	f := &fakeDNS{key: []string{"example.com"}, present: true}
	d := dnsDaemon(t, f)
	d.testCapture([]string{"example.com"})
	d.testCapture([]string{"example.com"})
	if f.writes != 1 {
		t.Errorf("writes = %d, want 1", f.writes)
	}
}

// No zones: the key is released when it may be ours or is present, and an
// absent key is left alone (no flush).
func TestSetCaptureNoZones(t *testing.T) {
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	d.testCapture(nil)
	if f.releases != 0 {
		t.Fatalf("no key: releases = %d, want 0", f.releases)
	}
	d.testCapture([]string{"example.com"})
	d.testCapture(nil)
	if f.releases != 1 || f.present {
		t.Fatalf("captured: releases = %d, present %v; want released once", f.releases, f.present)
	}
	d.testCapture(nil)
	if f.releases != 1 {
		t.Errorf("released again: releases = %d", f.releases)
	}
	// A key of a previous run.
	f.key, f.present = []string{"x.com"}, true
	d.testCapture(nil)
	if f.releases != 2 || f.present {
		t.Errorf("leftover key: releases = %d, present %v; want it released", f.releases, f.present)
	}
}

// A failed release keeps captured: the next call retries.
func TestSetCaptureReleaseFails(t *testing.T) {
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	d.testCapture([]string{"example.com"})
	f.releaseErr = errors.New("boom")
	if w := d.testCapture(nil); !strings.Contains(w, "boom") {
		t.Errorf("warning = %q, want the release error", w)
	}
	f.releaseErr = nil
	d.testCapture(nil)
	if f.releases != 1 || f.present {
		t.Errorf("retry: releases = %d, present %v", f.releases, f.present)
	}
}

// A failed write sets dnsErr and a warning; the next call writes again and
// clears it.
func TestSetCaptureWriteFails(t *testing.T) {
	f := &fakeDNS{captureErr: errors.New("no root")}
	d := dnsDaemon(t, f)
	zones := []string{"example.com"}
	if w := d.testCapture(zones); !strings.Contains(w, "no root") {
		t.Errorf("warning = %q, want the capture error", w)
	}
	if e := dnsError(d); !strings.Contains(e, "no root") {
		t.Errorf("DNSError = %q, want the capture error", e)
	}
	f.captureErr = nil
	d.testCapture(zones)
	if f.writes != 1 {
		t.Errorf("writes = %d, want the retry", f.writes)
	}
	if e := dnsError(d); e != "" {
		t.Errorf("DNSError = %q after a write, want none", e)
	}
}

// design 8: after a write scutil --dns is checked; a failure goes to dnsErr
// (icon warn), is tried verifyTries times, and is checked again without a
// write while the zones stay.
func TestSetCaptureVerify(t *testing.T) {
	f := &fakeDNS{verifyErr: errors.New("zones missing: example.com")}
	d := dnsDaemon(t, f)
	zones := []string{"example.com"}
	if w := d.testCapture(zones); w != "" {
		t.Errorf("warning = %q; a failed check is no warning", w)
	}
	if f.verifies != verifyTries {
		t.Errorf("verifies = %d, want %d", f.verifies, verifyTries)
	}
	if e := dnsError(d); !strings.Contains(e, "zones missing") {
		t.Errorf("DNSError = %q, want the check error", e)
	}
	f.verifyErr = nil
	d.testCapture(zones)
	if f.writes != 1 {
		t.Errorf("writes = %d, want no rewrite", f.writes)
	}
	if e := dnsError(d); e != "" {
		t.Errorf("DNSError = %q after the check passed", e)
	}
	n := f.verifies
	d.testCapture(zones)
	if f.verifies != n {
		t.Errorf("checked again with no error and no write")
	}
}

// checkCapture works by the zones of the effective config, the block
// snapshot included; nothing ours and no zones: nothing is read or written.
func TestCheckCaptureZones(t *testing.T) {
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	d.dnsCaptured = func() ([]string, bool, error) {
		t.Fatal("key read with no zones and nothing captured")
		return nil, false, nil
	}
	d.checkCapture()
	d = dnsDaemon(t, f)

	d.blockCfg = domainsCfg("Blocked.example.")
	d.checkCapture()
	if want := []string{"blocked.example"}; !slices.Equal(f.key, want) || f.writes != 1 {
		t.Fatalf("block snapshot: key = %v, writes %d; want %v once", f.key, f.writes, want)
	}
	d.checkCapture() // our own write gives a Capture event
	if f.writes != 1 {
		t.Errorf("own write: writes = %d, want 1", f.writes)
	}
	f.key, f.present = nil, false // configd restart
	d.checkCapture()
	if f.writes != 2 || !f.present {
		t.Errorf("key lost: writes = %d, present %v; want restored", f.writes, f.present)
	}
	d.blockCfg = nil
	d.checkCapture()
	if f.present {
		t.Errorf("no zones any more: key still set")
	}
}

// design 8: pause and disableAll do not change the zones: the key is not
// touched.
func TestDisableAllKeepsCapture(t *testing.T) {
	f := &fakeDNS{}
	d := dnsDaemon(t, f)
	d.cfg = domainsCfg("example.com")
	d.testCapture(d.cfg.Zones())
	if err := d.DisableAll(); err != nil {
		t.Fatalf("DisableAll: %v", err)
	}
	if f.writes != 1 || f.releases != 0 || !f.present {
		t.Errorf("after disableAll: writes %d, releases %d, present %v", f.writes, f.releases, f.present)
	}
}

// design 8: a busy port does not stop the daemon; the error is in status
// and cleared by the first successful retry, after which nothing is tried.
func TestListenRetry(t *testing.T) {
	busy := errors.New("address already in use")
	f := &fakeDNS{listenErrs: []error{busy, busy}}
	d := dnsDaemon(t, f)
	if d.retryListen() {
		t.Fatal("listening on a busy port")
	}
	if e := dnsError(d); !strings.Contains(e, "already in use") || !strings.Contains(e, dnsAddr) {
		t.Errorf("DNSError = %q, want the busy port", e)
	}
	// config.reload tries too (the config itself is invalid here).
	d.Reload()
	if f.listens != 2 {
		t.Errorf("listens after reload = %d, want 2", f.listens)
	}
	if !d.retryListen() {
		t.Fatal("not listening once the port is free")
	}
	if e := dnsError(d); e != "" {
		t.Errorf("DNSError = %q after listening", e)
	}
	d.retryListen()
	d.Reload()
	if f.listens != 3 {
		t.Errorf("listens = %d, want none after success", f.listens)
	}
}

// The capture error and the listen error are both shown.
func TestDNSErrorJoined(t *testing.T) {
	f := &fakeDNS{listenErrs: []error{errors.New("busy")}, verifyErr: errors.New("missing")}
	d := dnsDaemon(t, f)
	d.retryListen()
	d.testCapture([]string{"example.com"})
	if e := dnsError(d); !strings.Contains(e, "busy") || !strings.Contains(e, "missing") {
		t.Errorf("DNSError = %q, want both errors", e)
	}
}

// listenEvery retries on every tick of its channel (every dnsRetry in the
// daemon) and stops once listening, or when ctx is done.
func TestListenEvery(t *testing.T) {
	if dnsRetry != time.Minute {
		t.Errorf("dnsRetry = %v, want 60 s (design 8)", dnsRetry)
	}
	busy := errors.New("busy")
	f := &fakeDNS{listenErrs: []error{busy, busy, busy}}
	d := dnsDaemon(t, f)
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		d.listenEvery(context.Background(), tick)
		close(done)
	}()
	for range 3 {
		tick <- time.Time{} // blocks until listenEvery takes it
	}
	select {
	case <-done:
		t.Fatal("stopped while the port is busy")
	default:
	}
	tick <- time.Time{} // the fourth try succeeds
	<-done
	if f.listens != 4 {
		t.Errorf("listens = %d, want 4", f.listens)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.listenEvery(ctx, nil) // returns at once
}
