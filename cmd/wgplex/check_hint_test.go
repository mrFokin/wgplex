package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// A read denied to the user running check (EACCES) gets the hint that the
// daemon reads the file as root; EPERM (TCC) and other errors do not.
func TestUnreadableHint(t *testing.T) {
	eacces := &fs.PathError{Op: "open", Path: "/etc/w/a.conf", Err: syscall.EACCES}
	eperm := &fs.PathError{Op: "open", Path: "/etc/w/b.conf", Err: syscall.EPERM}
	other := errors.New("unknown key")
	got := unreadableHint(config.Errors{eacces, eperm, other}, 501)
	var errs config.Errors
	if !errors.As(got, &errs) || len(errs) != 3 {
		t.Fatalf("got %T %v, want three config.Errors", got, got)
	}
	if want := eacces.Error() + " (cannot read as uid 501; the daemon reads it as root)"; errs[0].Error() != want {
		t.Errorf("EACCES: %q, want %q", errs[0], want)
	}
	if errs[1] != error(eperm) || errs[2] != other {
		t.Errorf("EPERM or other changed: %v", errs[1:])
	}
	if got := unreadableHint(eacces, 7); !strings.HasSuffix(got.Error(), "as uid 7; the daemon reads it as root)") {
		t.Errorf("single error: %q", got)
	}
}

// The hint reaches the text of check, with the same exit code.
func TestCheckMainUnreadableHint(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads 0000 files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte("tunnels: []\n"), 0); err != nil {
		t.Fatal(err)
	}
	out, _, code := checkRun(t, dir)
	if code != 1 || !strings.Contains(out, "the daemon reads it as root") {
		t.Errorf("code %d, stdout %q; want the hint and code 1", code, out)
	}
	if !strings.Contains(out, "permission denied") {
		t.Errorf("stdout = %q, want the original message kept", out)
	}
}
