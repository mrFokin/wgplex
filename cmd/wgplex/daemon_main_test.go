package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/rpc"
)

// Not root, the daemon exits 0 so that launchd does not restart it
// (design 4.1).
func TestDaemonMainNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs the daemon as root")
	}
	if code := daemonMain(command{Name: "daemon", Socket: filepath.Join(t.TempDir(), "s.sock")}); code != 0 {
		t.Fatalf("daemonMain as non-root = %d, want 0", code)
	}
}

// A missing directory of the socket is named in the error: the daemon
// creates no directories (design 4.1).
func TestLogListenErrorMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "run")
	socket := filepath.Join(dir, "wgplex.sock")
	_, err := rpc.Listen(socket)
	if err == nil {
		t.Fatal("Listen in a missing directory succeeded")
	}
	var buf bytes.Buffer
	logListenError(slog.New(slog.NewTextHandler(&buf, nil)), socket, err)
	if out := buf.String(); !strings.Contains(out, "directory "+dir+" does not exist") {
		t.Errorf("log = %q, want the missing directory %s", out, dir)
	}
}

func TestLogListenErrorOther(t *testing.T) {
	var buf bytes.Buffer
	logListenError(slog.New(slog.NewTextHandler(&buf, nil)), filepath.Join(t.TempDir(), "x.sock"), errors.New("boom"))
	if out := buf.String(); !strings.Contains(out, "boom") || strings.Contains(out, "does not exist") {
		t.Errorf("log = %q, want the error itself", out)
	}
}
