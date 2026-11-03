package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// implLogDir returns a temp dir and the log path inside it.
func implLogDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return dir, filepath.Join(dir, "wgplex.log")
}

func implReadFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func implStat(t *testing.T, name string) *syscall.Stat_t {
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

func TestImplOpenLogMissingDir(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log", "wgplex.log")
	if _, err := openLog(p, -1); err == nil {
		t.Fatal("openLog in a missing directory: no error")
	}
	if _, err := os.Stat(filepath.Join(dir, "log")); !os.IsNotExist(err) {
		t.Fatalf("directory created: %v", err)
	}
}

func TestImplOpenLogAppendsAndCounts(t *testing.T) {
	_, p := implLogDir(t)
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
	if got := implReadFile(t, p); got != "old\nnew\n" {
		t.Fatalf("file = %q", got)
	}
	if st := implStat(t, p); int(st.Gid) != os.Getgid() {
		t.Fatalf("gid = %d, want %d", st.Gid, os.Getgid())
	}
}

func TestImplRotate(t *testing.T) {
	for _, withArchives := range []bool{true, false} {
		t.Run(map[bool]string{true: "with .1 and .2", false: "no archives"}[withArchives], func(t *testing.T) {
			_, p := implLogDir(t)
			if withArchives {
				os.WriteFile(p+".1", []byte("one"), 0o640)
				os.WriteFile(p+".2", []byte("two"), 0o640)
			}
			// The existing file is one byte short of the limit.
			if err := os.WriteFile(p, bytes.Repeat([]byte("x"), logRotateSize-1), 0o640); err != nil {
				t.Fatal(err)
			}
			l, err := openLog(p, -1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { l.f.Close() }()
			if _, err := l.Write([]byte("y")); err != nil {
				t.Fatalf("rotating Write: %v", err)
			}
			if _, err := l.Write([]byte("after")); err != nil {
				t.Fatal(err)
			}
			if got := implReadFile(t, p); got != "after" {
				t.Fatalf("new file = %q", got)
			}
			if got := implReadFile(t, p+".1"); len(got) != logRotateSize || !strings.HasSuffix(got, "xy") {
				t.Fatalf(".1: %d bytes", len(got))
			}
			implStat(t, p)
			implStat(t, p+".1")
			if withArchives {
				if got := implReadFile(t, p+".2"); got != "one" {
					t.Fatalf(".2 = %q, want the old .1", got)
				}
			} else if _, err := os.Stat(p + ".2"); !os.IsNotExist(err) {
				t.Fatalf(".2 exists: %v", err)
			}
			if l.size != int64(len("after")) {
				t.Fatalf("size = %d", l.size)
			}
		})
	}
}

// TestImplRotateRedup: after a rotation the attached fds point at the new
// file (temporary fds stand in for 1 and 2).
func TestImplRotateRedup(t *testing.T) {
	dir, p := implLogDir(t)
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
	implSameFile(t, fds, p)

	if _, err := l.Write(bytes.Repeat([]byte("x"), logRotateSize)); err != nil {
		t.Fatal(err)
	}
	implSameFile(t, fds, p)
	// Writing to the fd lands in the current file, as a panic would.
	if _, err := syscall.Write(fds[1], []byte("panic")); err != nil {
		t.Fatal(err)
	}
	if got := implReadFile(t, p); got != "panic" {
		t.Fatalf("current file = %q", got)
	}
}

func implSameFile(t *testing.T, fds []int, path string) {
	t.Helper()
	want := implStat(t, path)
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

func TestImplSetGroup(t *testing.T) {
	_, p := implLogDir(t)
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
		if st := implStat(t, name); int(st.Gid) != other {
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
		if st := implStat(t, name); int(st.Gid) != other {
			t.Fatalf("%s: gid %d, want %d", name, st.Gid, other)
		}
	}
}
