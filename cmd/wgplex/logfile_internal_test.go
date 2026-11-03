package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// internalLogDir returns a temp dir and the log path inside it.
func internalLogDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return dir, filepath.Join(dir, "wgplex.log")
}

func internalReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func internalStat(t *testing.T, name string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("%s: mode %v, want 0640", name, fi.Mode().Perm())
	}
	return fi.Sys().(*syscall.Stat_t)
}

func TestInternalOpenLogAppendsAndCounts(t *testing.T) {
	_, p := internalLogDir(t)
	if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := openLog(p, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer l.f.Close()
	if l.size != 4 {
		t.Fatalf("size = %d, want 4", l.size)
	}
	if _, err := l.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if got := internalReadFile(t, p); got != "old\nnew\n" {
		t.Fatalf("file = %q", got)
	}
	if st := internalStat(t, p); int(st.Gid) != os.Getgid() {
		t.Fatalf("gid = %d, want %d", st.Gid, os.Getgid())
	}
}

// A log removed by hand has nothing to archive at the rotation: the archives
// stay, a new file is opened at path and writing goes there.
func TestInternalRotateFileGone(t *testing.T) {
	_, p := internalLogDir(t)
	os.WriteFile(p+".1", []byte("one"), 0o640)
	l, err := openLog(p, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { l.f.Close() }()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write(bytes.Repeat([]byte("x"), logRotateSize)); err != nil {
		t.Fatalf("rotating Write: %v", err)
	}
	if _, err := l.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if got := internalReadFile(t, p); got != "after" {
		t.Fatalf("new file = %q", got)
	}
	if got := internalReadFile(t, p+".1"); got != "one" {
		t.Fatalf(".1 = %q, want the old .1 untouched", got)
	}
	if _, err := os.Stat(p + ".2"); !os.IsNotExist(err) {
		t.Fatalf(".2 exists: %v", err)
	}
}

// The file moved to .1 but the new one failed to open: writing goes on in the
// old file, the next Write tries to open again (not after another
// logRotateSize), and once it succeeds the writes land in a new file at path,
// the archives shifted once.
func TestInternalRotateOpenFails(t *testing.T) {
	_, p := internalLogDir(t)
	os.WriteFile(p+".1", []byte("one"), 0o640)
	l, err := openLog(p, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { l.f.Close() }()
	fail := true
	logOpenFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if fail {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EMFILE}
		}
		return os.OpenFile(name, flag, perm)
	}
	t.Cleanup(func() { logOpenFile = os.OpenFile })

	if _, err := l.Write(bytes.Repeat([]byte("x"), logRotateSize)); err == nil {
		t.Fatal("rotating Write: no error with the open failing")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s exists after a failed open: %v", p, err)
	}
	if _, err := l.Write([]byte("a")); err == nil {
		t.Fatal("Write: open not tried again")
	}
	fail = false
	if _, err := l.Write([]byte("b")); err != nil {
		t.Fatalf("Write after the open works again: %v", err)
	}
	if _, err := l.Write([]byte("c")); err != nil {
		t.Fatal(err)
	}
	if got := internalReadFile(t, p); got != "c" {
		t.Fatalf("new file = %q, want the writes after the reopen", got)
	}
	if got := internalReadFile(t, p+".1"); len(got) != logRotateSize+2 || !strings.HasSuffix(got, "xab") {
		t.Fatalf(".1: %d bytes, want the rotated file with the writes made meanwhile", len(got))
	}
	if got := internalReadFile(t, p+".2"); got != "one" {
		t.Fatalf(".2 = %q, want the old .1 (shifted once)", got)
	}
	if l.reopen {
		t.Fatal("reopen still set")
	}
}

// TestInternalRotateRedup: after a rotation the attached fds point at the new
// file (temporary fds stand in for 1 and 2).
func TestInternalRotateRedup(t *testing.T) {
	dir, p := internalLogDir(t)
	var fds []int
	for i := 0; i < 2; i++ {
		f, err := os.Create(filepath.Join(dir, "stand-in"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fds = append(fds, int(f.Fd()))
	}
	l, err := openLog(p, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { l.f.Close() }()
	l.std = fds
	if err := l.dup2(); err != nil {
		t.Fatal(err)
	}
	internalSameFile(t, fds, p)

	if _, err := l.Write(bytes.Repeat([]byte("x"), logRotateSize)); err != nil {
		t.Fatal(err)
	}
	internalSameFile(t, fds, p)
	// Writing to the fd lands in the current file, as a panic would.
	if _, err := syscall.Write(fds[1], []byte("panic")); err != nil {
		t.Fatal(err)
	}
	if got := internalReadFile(t, p); got != "panic" {
		t.Fatalf("current file = %q", got)
	}
}

func internalSameFile(t *testing.T, fds []int, path string) {
	t.Helper()
	want := internalStat(t, path)
	for _, fd := range fds {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		if st.Ino != want.Ino || st.Dev != want.Dev {
			t.Fatalf("fd %d is not %s", fd, path)
		}
	}
}

func TestInternalSetGroup(t *testing.T) {
	_, p := internalLogDir(t)
	gid := os.Getgid()
	other := gid
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != gid {
			other = g
			break
		}
	}
	os.WriteFile(p+".1", []byte("one"), 0o640)
	l, err := openLog(p, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { l.f.Close() }()
	if err := l.SetGroup(other); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{p, p + ".1"} {
		if st := internalStat(t, name); int(st.Gid) != other {
			t.Fatalf("%s: gid %d, want %d", name, st.Gid, other)
		}
	}
	if l.gid != other {
		t.Fatalf("gid = %d, want %d", l.gid, other)
	}
	// A file created by rotation gets the remembered group.
	if _, err := l.Write(bytes.Repeat([]byte("x"), logRotateSize)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{p, p + ".1", p + ".2"} {
		if st := internalStat(t, name); int(st.Gid) != other {
			t.Fatalf("%s: gid %d, want %d", name, st.Gid, other)
		}
	}
}
