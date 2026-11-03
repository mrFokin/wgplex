package rpc

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/mrFokin/jrpc/v2"
)

// Daemon is what the RPC methods call; *daemon in cmd/wgplex implements
// it, tests use a fake. Errors meant for the client are *jrpc.JRPCError with
// the codes above; any other error becomes Internal error.
type Daemon interface {
	Reload() (ApplyResult, error)             // config.reload
	Enable(name string) (EnableResult, error) // tunnel.enable
	Disable(name string) error                // tunnel.disable
	DisableAll() error                        // tunnel.disableAll
	Pause() error                             // daemon.pause; works without a config
	Resume() error                            // daemon.resume; works without a config
	State() *State
}

// Meta are the fields of status.get that do not come from the daemon State.
type Meta struct {
	Version   string // of the engine
	ConfigDir string // the config directory of the daemon
	LogPath   string // the log file of the daemon
}

// peerKey is the context key of the peer of a connection.
type peerKey struct{}

// peer is the uid of the peer of a connection, or the error getting it.
type peer struct {
	uid uint32
	err error
}

// Serve serves the methods of design 14 at Path on ln until ctx is done,
// then shuts down gracefully. Returns nil after ctx is done.
//
// Every connection is accepted: the peer uid (LOCAL_PEERCRED) is taken in
// http.Server.ConnContext (set in BeforeServeFunc) and the handler of each
// method reads it from the request context (design 5, 14). status.get and
// diag.* answer everybody, redacted (Redact*) unless acc.CanControl(uid);
// config.reload, tunnel.* and daemon.* need acc.CanControl(uid), else
// CodeNoPermission with PermissionData{acc.Group()}. A peer whose uid failed
// reads as one that cannot control and may not mutate. status.get gets
// APIVersion, meta, CanControl and ControlGroup (acc.Group()) here.
//
// Signatures stage (M3): the rights, meta and the redaction are not wired yet;
// every method calls d as is.
func Serve(ctx context.Context, ln net.Listener, d Daemon, acc *Access, meta Meta, log *slog.Logger) error {
	e := echo.New()
	e.Logger = log

	j := jrpc.Endpoint(e, Path)
	j.Method("config.reload", func(_ *jrpc.Context, _ struct{}) (ApplyResult, error) {
		return d.Reload()
	})
	j.Method("tunnel.enable", func(_ *jrpc.Context, p EnableParams) (EnableResult, error) {
		if p.Name == "" {
			return EnableResult{}, jrpc.NewErrorInvalidParams(nil)
		}
		return d.Enable(p.Name)
	})
	j.Method("tunnel.disable", func(_ *jrpc.Context, p EnableParams) (any, error) {
		if p.Name == "" {
			return nil, jrpc.NewErrorInvalidParams(nil)
		}
		return nil, d.Disable(p.Name)
	})
	j.Method("tunnel.disableAll", func(_ *jrpc.Context, _ struct{}) (any, error) {
		return nil, d.DisableAll()
	})
	j.Method("daemon.pause", func(_ *jrpc.Context, _ struct{}) (any, error) {
		return nil, d.Pause()
	})
	j.Method("daemon.resume", func(_ *jrpc.Context, _ struct{}) (any, error) {
		return nil, d.Resume()
	})
	j.Method("status.get", func(_ *jrpc.Context, _ struct{}) (Status, error) {
		return StatusOf(d.State()), nil
	})
	j.Method("diag.explain", func(_ *jrpc.Context, p ExplainParams) (Explanation, error) {
		return Explain(d.State(), p.Query)
	})
	j.Method("diag.routes", func(_ *jrpc.Context, _ struct{}) (Routes, error) {
		return RoutesOf(d.State()), nil
	})

	sc := echo.StartConfig{
		Listener:   ln,
		HideBanner: true,
		HidePort:   true,
		BeforeServeFunc: func(s *http.Server) error {
			s.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
				uid, err := peerUID(c)
				return context.WithValue(ctx, peerKey{}, peer{uid: uid, err: err})
			}
			return nil
		},
	}
	return sc.Start(ctx, e)
}
