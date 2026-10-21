package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/rpc"
)

// Tests of the daemon state over state.json (design 11) and of the replies of
// the mutating methods without an applied config (design 14), not the
// implementation. No root: the cases here never touch a tunnel or the system
// DNS.

// newTestDaemon returns a daemon with a discarded log and no tunnels; srv is
// only the resolver the daemon hooks Sync into.
func newTestDaemon(t *testing.T, configDir, statePath string, toggles map[string]bool) *daemon {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newDaemon(context.Background(), &dns.Server{}, log, configDir, statePath, toggles)
}

// design 14: tunnel.disableAll without an applied config is error 2, as
// tunnel.setEnabled is (data: none).
func TestDisableAllNoConfig(t *testing.T) {
	d := newTestDaemon(t, "", "", nil)
	err := d.DisableAll()
	var jerr *jrpc.JRPCError
	if !errors.As(err, &jerr) || jerr.Code != rpc.CodeNoConfig {
		t.Fatalf("DisableAll without a config = %v, want error %d", err, rpc.CodeNoConfig)
	}
}
