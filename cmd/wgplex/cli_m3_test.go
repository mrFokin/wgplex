package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/rpc"
)

// Tests of the CLI of plan M3, decision 11 (design 13).

// shortTempDir is a directory for unix sockets: t.TempDir paths may exceed
// the 104-byte limit of sun_path on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// design 13: exit code 3 when the daemon is unavailable — no socket, a
// refused socket, a timeout; 1 for any other error.
func TestExitCode(t *testing.T) {
	dir := shortTempDir(t)
	ctx := context.Background()

	missing := call(ctx, filepath.Join(dir, "none.sock"), "status.get", nil, nil)
	if got := exitCode(missing); got != 3 {
		t.Errorf("no socket: exitCode(%v) = %d, want 3", missing, got)
	}

	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	refused := call(ctx, stale, "status.get", nil, nil)
	if got := exitCode(refused); got != 3 {
		t.Errorf("refused: exitCode(%v) = %d, want 3", refused, got)
	}

	// A daemon that accepts but never answers: the call times out.
	hung := filepath.Join(dir, "hung.sock")
	hl, err := net.Listen("unix", hung)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hl.Close() })
	go func() {
		for {
			c, err := hl.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	timeout := call(tctx, hung, "status.get", nil, nil)
	if got := exitCode(timeout); got != 3 {
		t.Errorf("timeout: exitCode(%v) = %d, want 3", timeout, got)
	}
	out := printed(t, "printError", func(w io.Writer) { printError(w, timeout) })
	if !strings.Contains(out, "not responding") {
		t.Errorf("printError(timeout) = %q, want \"not responding\"", out)
	}

	for _, err := range []error{
		errors.New("something"),
		fmt.Errorf("read config: %w", &fs.PathError{Op: "open", Path: "/nonexistent", Err: fs.ErrNotExist}),
		&httpError{Code: http.StatusRequestEntityTooLarge},
		wireError(t, rpc.CodeUnknownTunnel, "unknown tunnel", nil),
	} {
		if got := exitCode(err); got != 1 {
			t.Errorf("exitCode(%v) = %d, want 1", err, got)
		}
	}
}

// design 13: wgplex version without a daemon prints only the CLI version,
// exit 0, nothing on stderr.
func TestVersionMainNoDaemon(t *testing.T) {
	var out, errb bytes.Buffer
	code := versionMain(command{Name: "version", Socket: filepath.Join(shortTempDir(t), "none.sock")}, &out, &errb)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if out.String() != "wgplex "+version+"\n" {
		t.Errorf("stdout = %q, want only the CLI version", out.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errb.String())
	}
}

// design 13, 14: status shows the pause, configured: false on its own line,
// the reason of a degraded rule and, redacted, only the counts.
func TestPrintStatusM3(t *testing.T) {
	s := rpc.Status{
		Configured: true, Paused: true, Icon: "paused", ControlGroup: "wgpctl",
		ConfigErrorCount: 2, WarningCount: 1,
		Tunnels: []rpc.TunnelStatus{{Name: "nl", Enabled: true, State: "off", Routes: "rules"}},
		Rules: []rpc.RuleStatus{
			{Index: 0, Services: []string{"ai"}, Via: []string{"nl"}, Fallback: "block", InFallback: true, Degraded: true, Reason: "paused"},
			{Index: 1, Services: []string{"yt"}, Via: []string{"nl", "de"}, Fallback: "default", Tunnel: "de", Degraded: true, Reason: "dead"},
		},
	}
	out := printed(t, "printStatus", func(w io.Writer) { printStatus(w, s, fixedNow) })
	wantRow(t, "icon", out, "icon: paused")
	wantRow(t, "paused", out, "paused: true (wgplex resume)")
	wantRow(t, "rule 1", out, "#1 ai nl block (fallback, paused)")
	wantRow(t, "rule 2", out, "#2 yt nl,de de (degraded, dead)")
	if !strings.Contains(out, "config errors: 2") || !strings.Contains(out, "warnings: 1") || !strings.Contains(out, `"wgpctl"`) {
		t.Errorf("redacted counts missing:\n%s", out)
	}
	if strings.Contains(out, "configured: false") {
		t.Errorf("configured: false shown for a configured daemon:\n%s", out)
	}

	out = printed(t, "printStatus", func(w io.Writer) {
		printStatus(w, rpc.Status{Icon: "warn", ConfigErrors: []string{"bad"}, ConfigErrorCount: 1}, fixedNow)
	})
	wantRow(t, "configured", out, "configured: false")
	if strings.Contains(out, "config errors: 1") {
		t.Errorf("count shown with the errors themselves:\n%s", out)
	}
}

// design 13: -json prints the API structure, decodable back.
func TestPrintJSON(t *testing.T) {
	in := rpc.Status{APIVersion: 1, Version: "0.3.0", Configured: true, Icon: "on", Tunnels: []rpc.TunnelStatus{}, Rules: []rpc.RuleStatus{}}
	var b bytes.Buffer
	if err := printJSON(&b, in); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b.String(), "}\n") {
		t.Errorf("no trailing newline: %q", b.String())
	}
	var got rpc.Status
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != in.Version || got.APIVersion != 1 || got.Icon != "on" {
		t.Errorf("round trip: %+v", got)
	}
}

// design 13: check -json is rpc.ConfigErrorData; empty arrays, not null.
func TestCheckJSON(t *testing.T) {
	var d rpc.ConfigErrorData
	if err := json.Unmarshal([]byte(checkJSON(nil, nil)), &d); err != nil {
		t.Fatal(err)
	}
	if d.Errors == nil || d.Warnings == nil || len(d.Errors)+len(d.Warnings) != 0 {
		t.Errorf("OK: %+v, want empty arrays", d)
	}
	if s := checkJSON(nil, nil); strings.Contains(s, "null") {
		t.Errorf("OK: %q has null", s)
	}

	out := checkJSON([]string{"w1"}, config.Errors{errors.New("e1"), errors.New("e2")})
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Errors, "|") != "e1|e2" || strings.Join(d.Warnings, "|") != "w1" {
		t.Errorf("errors: %+v", d)
	}

	// checkMain -json keeps the exit code of the text output.
	var stdout, stderr bytes.Buffer
	code := checkMain(command{Name: "check", ConfigDir: filepath.Join(t.TempDir(), "nodir"), JSON: true}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil || len(d.Errors) == 0 {
		t.Errorf("stdout = %q (%v), want ConfigErrorData with errors", stdout.String(), err)
	}
}
