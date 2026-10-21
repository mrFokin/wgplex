package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests follow design 15 (a 5 MiB log rotated into .1, the old .1 into .2,
// the old .2 removed, writes continue in the new file, fd 1 and 2 follow it)
// and plan m2-system-mode, scenario 7, not the implementation. They run
// without root; the redirect callback stands in for dup2 (a real dup2 of 1
// and 2 would change the fds of the test process itself).

func TestLogCounterThreshold(t *testing.T) {
	tests := []struct {
		name    string
		written int64
		limit   int64
		want    bool
	}{
		{"empty", 0, 5 << 20, false},
		{"just below", (5 << 20) - 1, 5 << 20, false},
		{"at the limit", 5 << 20, 5 << 20, true},
		{"over the limit", (5 << 20) + 1, 5 << 20, true},
		{"small limit", 10, 10, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := logCounter{limit: tt.limit}
			c.add(tt.written)
			if got := c.reached(); got != tt.want {
				t.Errorf("reached() with %d of %d = %v, want %v", tt.written, tt.limit, got, tt.want)
			}
		})
	}
}

func TestLogCounterSetAndAdd(t *testing.T) {
	c := logCounter{limit: 5}
	c.set(4)
	if c.reached() {
		t.Fatal("reached() after set(4) of 5")
	}
	c.add(1)
	if !c.reached() {
		t.Fatal("reached() after set(4) and add(1) of 5")
	}
	c.set(0)
	if c.reached() {
		t.Fatal("reached() after set(0)")
	}
}

func TestLogArchiveNames(t *testing.T) {
	if got := logArchive("/p/wgplex.log", 1); got != "/p/wgplex.log.1" {
		t.Errorf("logArchive 1 = %q", got)
	}
	if got := logArchive("/p/wgplex.log", 2); got != "/p/wgplex.log.2" {
		t.Errorf("logArchive 2 = %q", got)
	}
}

// design 15: .2 is removed, .1 becomes .2, the log becomes .1.
func TestLogRotationOrder(t *testing.T) {
	remove, renames := logRotation("/p/wgplex.log")
	if remove != "/p/wgplex.log.2" {
		t.Errorf("remove = %q, want %q", remove, "/p/wgplex.log.2")
	}
	want := [][2]string{
		{"/p/wgplex.log.1", "/p/wgplex.log.2"},
		{"/p/wgplex.log", "/p/wgplex.log.1"},
	}
	if len(renames) != len(want) {
		t.Fatalf("renames = %v, want %v", renames, want)
	}
	for i := range want {
		if renames[i] != want[i] {
			t.Errorf("rename %d = %v, want %v", i, renames[i], want[i])
		}
	}
}

// newTestLog opens a log at path with a small limit; the redirect stands in
// for dup2.
func newTestLog(t *testing.T, path string, limit int64, redirect func(*os.File) error) *logFile {
	t.Helper()
	l, err := openLog(path, limit, redirect)
	if err != nil {
		t.Fatalf("openLog(%q): %v", path, err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// plan m2, scenario 7: the threshold is exceeded, the old .1 exists; .1
// becomes .2, the log becomes .1 and writing continues in the new file.
func TestLogFileRotatesAtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wgplex.log")
	if err := os.WriteFile(logArchive(path, 1), []byte("old .1"), 0o640); err != nil {
		t.Fatal(err)
	}
	l := newTestLog(t, path, 10, nil)

	if n, err := l.Write([]byte("0123456789")); n != 10 || err != nil {
		t.Fatalf("Write = %d, %v; want 10, nil", n, err)
	}
	if got := readFile(t, logArchive(path, 1)); got != "0123456789" {
		t.Errorf(".1 = %q, want the rotated file", got)
	}
	if got := readFile(t, logArchive(path, 2)); got != "old .1" {
		t.Errorf(".2 = %q, want the old .1", got)
	}
	if got := readFile(t, path); got != "" {
		t.Errorf("new log = %q, want empty", got)
	}

	// The write after the rotation goes into the new file.
	if _, err := l.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "next" {
		t.Errorf("new log = %q, want %q", got, "next")
	}
	if got := readFile(t, logArchive(path, 1)); got != "0123456789" {
		t.Errorf(".1 = %q after the second write, want the rotated file", got)
	}
}

// The old .2 is removed: only two archives are kept (design 15).
func TestLogFileRotationDropsOldestArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wgplex.log")
	if err := os.WriteFile(path, []byte("now"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logArchive(path, 1), []byte("first"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logArchive(path, 2), []byte("older"), 0o640); err != nil {
		t.Fatal(err)
	}
	l := newTestLog(t, path, 2, nil)
	if _, err := l.Write([]byte("!")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, logArchive(path, 2)); got != "first" {
		t.Errorf(".2 = %q, want the old .1", got)
	}
	if got := readFile(t, logArchive(path, 1)); got != "now!" {
		t.Errorf(".1 = %q, want the rotated log", got)
	}
}

// A file left by a previous run counts from its size: the rotation happens
// at the limit, not at the limit plus the old content.
func TestLogFileCountsExistingSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wgplex.log")
	if err := os.WriteFile(path, []byte("012345678"), 0o640); err != nil {
		t.Fatal(err)
	}
	l := newTestLog(t, path, 10, nil)
	if _, err := l.Write([]byte("9")); err != nil {
		t.Fatal(err)
	}
	if !exists(logArchive(path, 1)) {
		t.Fatal("no .1 after the file reached the limit")
	}
	if got := readFile(t, logArchive(path, 1)); got != "0123456789" {
		t.Errorf(".1 = %q, want the whole file", got)
	}
}

// design 15: after the rotation fd 1 and 2 are pointed at the new file
// again. The redirect callback is called on open and after every rotation;
// without it stdout and stderr would keep writing into the archive.
func TestLogFileRedirectOnOpenAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgplex.log")
	var redirected []string
	redirect := func(f *os.File) error {
		redirected = append(redirected, f.Name())
		return nil
	}
	l := newTestLog(t, path, 5, redirect)
	if len(redirected) != 1 || redirected[0] != path {
		t.Fatalf("redirect on open = %v, want [%q]", redirected, path)
	}
	if _, err := l.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if len(redirected) != 2 || redirected[1] != path {
		t.Fatalf("redirect after rotation = %v, want the log %q again", redirected, path)
	}
}

func TestLogFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgplex.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	l := newTestLog(t, path, 5, nil)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != logMode {
		t.Errorf("mode = %o, want %o", got, logMode)
	}
	if _, err := l.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{logArchive(path, 1), path} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != logMode {
			t.Errorf("%s mode = %o, want %o", p, got, logMode)
		}
	}
}

// design 4.1: the daemon creates no directories; a missing one is an error
// before anything is written to the log.
func TestOpenDaemonLogMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "log", "wgplex")
	_, err := openDaemonLog(filepath.Join(dir, "wgplex.log"))
	if err == nil {
		t.Fatal("openDaemonLog in a missing directory succeeded")
	}
	if !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), dir) {
		t.Errorf("error = %q, want the missing directory", err)
	}
	if exists(dir) {
		t.Errorf("openDaemonLog created %s", dir)
	}
}

func TestOpenDaemonLogNotDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "wgplex.log")
	if err := os.WriteFile(file, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := openDaemonLog(filepath.Join(file, "wgplex.log")); err == nil {
		t.Fatal("openDaemonLog with a file as the directory succeeded")
	}
}

// A missing log file is not an error: the daemon opens (creates) it.
func TestOpenDaemonLogCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgplex.log")
	l, err := openLog(path, logLimit, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != logMode {
		t.Errorf("mode = %o, want %o", got, logMode)
	}
}
