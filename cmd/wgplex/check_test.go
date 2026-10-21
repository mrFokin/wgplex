package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 13 (wgplex check: a local check of the config without
// the daemon and root, text output, exit codes 0/1), 10.1 (every problem is
// collected, warnings do not make the config invalid) and 10.2 (the same
// logic as the daemon). Fixtures use generated keys (m6NewConf).

// checkWriteDir writes a config directory with wgplex.yaml (yaml, 0600) and
// the .conf files (0600) and returns its path.
func checkWriteDir(t *testing.T, yaml string, confs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, text := range confs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// checkYAML is a valid config of one tunnel with routes: config; its .conf is
// the caller's (work.conf).
func checkYAML() string {
	return `tunnels:
  - name: work
    conf: work.conf
    routes: config
    autostart: true
`
}

func TestCheckMainOK(t *testing.T) {
	dir := checkWriteDir(t, checkYAML(), map[string]string{
		"work.conf": m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8").Text(),
	})
	var out bytes.Buffer
	if code := checkMain(&out, dir); code != 0 {
		t.Fatalf("checkMain = %d, want 0; output:\n%s", code, out.String())
	}
	if got, want := out.String(), "config OK\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// design 10.1: a .conf readable by group is a warning; the config stays valid
// and the check succeeds.
func TestCheckMainWarnings(t *testing.T) {
	dir := checkWriteDir(t, checkYAML(), map[string]string{
		"work.conf": m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8").Text(),
	})
	if err := os.Chmod(filepath.Join(dir, "work.conf"), 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := checkMain(&out, dir); code != 0 {
		t.Fatalf("checkMain = %d, want 0; output:\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "warning: work.conf: readable by group or other") {
		t.Errorf("output %q: want the readable .conf warning", got)
	}
	if !strings.HasSuffix(got, "config OK\n") {
		t.Errorf("output %q: want config OK after the warnings", got)
	}
}

// design 10.2: the check reports the warnings the daemon adds on apply, not
// only those of the loader (here: a check of a family the tunnel has no
// address of, design 9).
func TestCheckMainDaemonWarnings(t *testing.T) {
	yaml := `tunnels:
  - name: work
    conf: work.conf
    routes: config
    check: ::1
`
	dir := checkWriteDir(t, yaml, map[string]string{
		"work.conf": m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8").Text(),
	})
	var out bytes.Buffer
	if code := checkMain(&out, dir); code != 0 {
		t.Fatalf("checkMain = %d, want 0; output:\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, `tunnel "work": check ::1 is not pinged`) {
		t.Errorf("output %q: want the family warning of the apply", got)
	}
	if !strings.HasSuffix(got, "config OK\n") {
		t.Errorf("output %q: want config OK after the warnings", got)
	}
}

// plan m2-system-mode, check scenario 6: two errors — both shown, exit 1.
func TestCheckMainErrors(t *testing.T) {
	yaml := `tunnels:
  - name: work
    conf: work.conf
    routes: config
  - name: work
    conf: missing.conf
    routes: config
`
	dir := checkWriteDir(t, yaml, map[string]string{
		"work.conf": m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8").Text(),
	})
	var out bytes.Buffer
	if code := checkMain(&out, dir); code != 1 {
		t.Fatalf("checkMain = %d, want 1; output:\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "config error:") {
		t.Errorf("output %q: want the config error header", got)
	}
	for _, want := range []string{
		`tunnel "work": duplicate tunnel name`,
		`tunnel "work": conf file "missing.conf" not found`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q: want the error %q", got, want)
		}
	}
	if strings.Contains(got, "config OK") {
		t.Errorf("output %q: no config OK on errors", got)
	}
}

// design 10.2: no directory is a config error of its own; the check exits 1.
func TestCheckMainNoDir(t *testing.T) {
	var out bytes.Buffer
	if code := checkMain(&out, filepath.Join(t.TempDir(), "nosuch")); code != 1 {
		t.Fatalf("checkMain = %d, want 1; output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "does not exist") {
		t.Errorf("output %q: want the no-directory error", out.String())
	}
}

// printCheck: errors first, one per line, then warnings, then "config OK"
// only without errors (design 13, 10.1).
func TestPrintCheck(t *testing.T) {
	var out bytes.Buffer
	printCheck(&out, []string{"w1", "w2"}, config.Errors{errors.New("e1"), errors.New("e2")})
	want := "config error:\n  e1\n  e2\nwarning: w1\nwarning: w2\n"
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}

	out.Reset()
	printCheck(&out, []string{"w1"}, nil)
	if got, want := out.String(), "warning: w1\nconfig OK\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
