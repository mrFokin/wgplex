package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Tests follow design 15: the daemon log rotates at 5 MiB (the file becomes
// .1, an old .1 becomes .2, an old .2 is removed, a missing .2 is not an
// error), a new file is opened and writing goes on; the byte count starts
// from the size of an existing file; the file and archives are 0640.
//
// A rotation points fd 1 and 2 at the new file (Dup2Std), which would eat the
// output of the test binary, so every test saves and restores them.

// logSaveStd saves fd 1 and 2 and restores them when the test ends.
func logSaveStd(t *testing.T) {
	t.Helper()
	out, err := syscall.Dup(1)
	if err != nil {
		t.Fatal(err)
	}
	errFd, err := syscall.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Dup2(out, 1)
		syscall.Dup2(errFd, 2)
		syscall.Close(out)
		syscall.Close(errFd)
	})
}

// logOpen opens the log in a fresh directory.
func logOpen(t *testing.T) (*rotatingFile, string) {
	t.Helper()
	logSaveStd(t)
	path := filepath.Join(t.TempDir(), "wgplex.log")
	l, err := openLog(path, os.Getgid())
	if err != nil {
		t.Fatalf("openLog: %v", err)
	}
	return l, path
}

// logFill writes n bytes of c to l in chunks (never one n-sized slice).
func logFill(t *testing.T, l *rotatingFile, n int, c byte) {
	t.Helper()
	chunk := bytes.Repeat([]byte{c}, 64<<10)
	for n > 0 {
		k := min(n, len(chunk))
		w, err := l.Write(chunk[:k])
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if w != k {
			t.Fatalf("Write returned %d, want %d", w, k)
		}
		n -= k
	}
}

func logSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

func logExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func logMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestLogOpenCreates0640(t *testing.T) {
	// design 15: the file is 0640
	l, path := logOpen(t)
	defer l.f.Close()
	if m := logMode(t, path); m != 0o640 {
		t.Errorf("log mode = %04o, want 0640", m)
	}
}

func TestLogOpenMissingDir(t *testing.T) {
	// design 4.1: the directory is not created, a missing one is an error
	logSaveStd(t)
	path := filepath.Join(t.TempDir(), "nodir", "wgplex.log")
	if _, err := openLog(path, os.Getgid()); err == nil {
		t.Fatal("openLog: expected an error for a missing directory, got nil")
	}
	if logExists(filepath.Dir(path)) {
		t.Error("openLog created the directory")
	}
}

func TestLogWriteBelowThreshold(t *testing.T) {
	// design 15: no rotation below 5 MiB
	l, path := logOpen(t)
	defer l.f.Close()
	if _, err := l.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if got := logSize(t, path); got != 6 {
		t.Errorf("size = %d, want 6", got)
	}
	if logExists(path + ".1") {
		t.Error(".1 exists without a rotation")
	}
}

func TestLogRotateNoArchives(t *testing.T) {
	// design 15: at 5 MiB the file becomes .1 (a missing .2 is not an
	// error), a new file is created and writing goes on
	l, path := logOpen(t)
	defer l.f.Close()

	logFill(t, l, logRotateSize, 'a')
	if !logExists(path + ".1") {
		t.Fatal(".1 not created at the rotation threshold")
	}
	if got := logSize(t, path+".1"); got != logRotateSize {
		t.Errorf(".1 size = %d, want %d", got, logRotateSize)
	}
	if logExists(path + ".2") {
		t.Error(".2 created from nothing")
	}

	if _, err := l.Write([]byte("after\n")); err != nil {
		t.Fatalf("Write after rotation: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("new log file: %v", err)
	}
	if string(data) != "after\n" {
		t.Errorf("new log = %q, want %q", data, "after\n")
	}
}

func TestLogRotateShiftsArchives(t *testing.T) {
	// design 15: .1 becomes .2, an existing .2 is removed
	l, path := logOpen(t)
	defer l.f.Close()
	if err := os.WriteFile(path+".1", []byte("old1"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".2", []byte("old2"), 0o640); err != nil {
		t.Fatal(err)
	}

	logFill(t, l, logRotateSize, 'x')

	if got := logSize(t, path+".1"); got != logRotateSize {
		t.Errorf(".1 size = %d, want the rotated file (%d)", got, logRotateSize)
	}
	data, err := os.ReadFile(path + ".2")
	if err != nil {
		t.Fatalf(".2: %v", err)
	}
	if string(data) != "old1" {
		t.Errorf(".2 = %q, want the former .1 (%q)", data, "old1")
	}
	if _, err := l.Write([]byte("next\n")); err != nil {
		t.Fatalf("Write after rotation: %v", err)
	}
	if got := logSize(t, path); got != 5 {
		t.Errorf("new log size = %d, want 5", got)
	}
}

func TestLogRotateTwice(t *testing.T) {
	// design 15: two rotations keep two archives, the third file is gone
	l, path := logOpen(t)
	defer l.f.Close()

	logFill(t, l, logRotateSize, 'a')
	logFill(t, l, logRotateSize, 'b')
	logFill(t, l, logRotateSize, 'c')

	for _, p := range []string{path + ".1", path + ".2"} {
		if got := logSize(t, p); got != logRotateSize {
			t.Errorf("%s size = %d, want %d", p, got, logRotateSize)
		}
	}
	if logExists(path + ".3") {
		t.Error(".3 must not exist")
	}
	// .1 is the latest rotated file ('c'), .2 the one before ('b')
	for p, c := range map[string]byte{path + ".1": 'c', path + ".2": 'b'} {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1)
		if _, err := f.Read(b); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if b[0] != c {
			t.Errorf("%s starts with %q, want %q", p, b[0], c)
		}
	}
}

func TestLogCountsExistingBytes(t *testing.T) {
	// design 15: the byte count starts from the size of an existing file, so
	// that appending up to the threshold rotates
	logSaveStd(t)
	path := filepath.Join(t.TempDir(), "wgplex.log")
	const initial = 1 << 20
	if err := os.WriteFile(path, bytes.Repeat([]byte("p"), initial), 0o640); err != nil {
		t.Fatal(err)
	}
	l, err := openLog(path, os.Getgid())
	if err != nil {
		t.Fatalf("openLog: %v", err)
	}
	defer l.f.Close()

	logFill(t, l, logRotateSize-initial-1, 'n')
	if logExists(path + ".1") {
		t.Fatal("rotated before the threshold")
	}
	if _, err := l.Write([]byte("zz")); err != nil {
		t.Fatal(err)
	}
	if !logExists(path + ".1") {
		t.Fatal("no rotation after the existing bytes plus new ones reached 5 MiB")
	}
	if got := logSize(t, path+".1"); got < logRotateSize {
		t.Errorf(".1 size = %d, want at least %d (old content kept)", got, logRotateSize)
	}
}

func TestLogModes0640(t *testing.T) {
	// design 15: the file and archives are 0640
	l, path := logOpen(t)
	defer l.f.Close()
	logFill(t, l, logRotateSize, 'a')
	logFill(t, l, logRotateSize, 'b')
	for _, p := range []string{path, path + ".1", path + ".2"} {
		if m := logMode(t, p); m != 0o640 {
			t.Errorf("%s mode = %04o, want 0640", filepath.Base(p), m)
		}
	}
}

func TestLogNoTempFiles(t *testing.T) {
	// design 15: only the log and its archives live in the directory
	l, path := logOpen(t)
	defer l.f.Close()
	logFill(t, l, logRotateSize, 'a')
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "wgplex.log") {
			t.Errorf("unexpected file %s", e.Name())
		}
	}
}
