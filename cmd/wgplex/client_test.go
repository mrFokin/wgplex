package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Tests follow the Wirefork M6 plan (step 4, remark 7: the CLI rejects a body over 1 MiB
// itself), not the implementation.

const m6MiB = 1 << 20

// m6Params returns params whose JSON is about n bytes.
func m6Params(t *testing.T, n int) map[string]string {
	t.Helper()
	p := map[string]string{"s": strings.Repeat("a", n)}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("params: %d bytes", len(b))
	return p
}

// m6NoSocket returns a socket path in a fresh temp dir that does not exist.
func m6NoSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "wgplex.sock")
}

func m6Call(t *testing.T, socket string, params any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var res any
	return call(ctx, socket, "status.get", params, &res)
}

func m6PrintError(err error) string {
	var b bytes.Buffer
	printError(&b, err)
	return b.String()
}

// m6 remark 7: params over 1 MiB fail with a size error before dialing.
func TestM6CallBodyOverLimit(t *testing.T) {
	err := m6Call(t, m6NoSocket(t), m6Params(t, m6MiB))
	if err == nil {
		t.Fatal("call with params over 1 MiB: no error")
	}
	var op *net.OpError
	if errors.As(err, &op) {
		t.Errorf("call over 1 MiB: dial error %v, want a size error", err)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("call over 1 MiB: socket error %v, want a size error", err)
	}
	var he *httpError
	if errors.As(err, &he) {
		t.Errorf("call over 1 MiB: HTTP error %v, want no contact with the daemon", err)
	}
	out := m6PrintError(err)
	if strings.Contains(out, "not running") {
		t.Errorf("printError(size error) = %q, must not say not running", out)
	}
	if strings.TrimSpace(out) == "" {
		t.Errorf("printError(size error) printed nothing")
	}
}

// m6 remark 7: the size check happens without contacting the socket even
// when a listener is there.
func TestM6CallBodyOverLimitNoConnect(t *testing.T) {
	socket := m6NoSocket(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix listener: %v", err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	if err := m6Call(t, socket, m6Params(t, m6MiB)); err == nil {
		t.Fatal("call with params over 1 MiB: no error")
	}
	ln.Close()
	if n := accepted.Load(); n != 0 {
		t.Errorf("call over 1 MiB connected to the socket %d times, want 0", n)
	}
}

// m6 remark 7, boundary: a body just under 1 MiB is sent, so a missing
// socket gives the dial error and "wgplex daemon is not running".
func TestM6CallBodyUnderLimit(t *testing.T) {
	err := m6Call(t, m6NoSocket(t), m6Params(t, m6MiB-4096))
	if err == nil {
		t.Fatal("call on a missing socket: no error")
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Errorf("call under 1 MiB on a missing socket = %v, want ENOENT of the dial", err)
	}
	if out := m6PrintError(err); !strings.Contains(out, "wgplex daemon is not running") {
		t.Errorf("printError(dial error) = %q, want \"wgplex daemon is not running\"", out)
	}
}
