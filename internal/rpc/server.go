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
func Serve(ctx context.Context, ln net.Listener, d Daemon, acc *Access, meta Meta, log *slog.Logger) error {
	e := echo.New()
	e.Logger = log

	// canControl reports whether the peer of the request of c may control.
	canControl := func(c *jrpc.Context) bool {
		p, ok := c.Echo.Request().Context().Value(peerKey{}).(peer)
		return ok && p.err == nil && acc.CanControl(p.uid)
	}
	// deny is the error of a mutating method for a peer that cannot control;
	// nil: it can.
	deny := func(c *jrpc.Context) error {
		if canControl(c) {
			return nil
		}
		return jrpc.NewError(CodeNoPermission, "permission denied", PermissionData{ControlGroup: acc.Group()})
	}

	j := jrpc.Endpoint(e, Path)
	j.Method("config.reload", func(c *jrpc.Context, _ struct{}) (ApplyResult, error) {
		if err := deny(c); err != nil {
			return ApplyResult{}, err
		}
		return d.Reload()
	})
	j.Method("tunnel.enable", func(c *jrpc.Context, p EnableParams) (EnableResult, error) {
		if err := deny(c); err != nil {
			return EnableResult{}, err
		}
		if p.Name == "" {
			return EnableResult{}, jrpc.NewErrorInvalidParams(nil)
		}
		return d.Enable(p.Name)
	})
	j.Method("tunnel.disable", func(c *jrpc.Context, p EnableParams) (any, error) {
		if err := deny(c); err != nil {
			return nil, err
		}
		if p.Name == "" {
			return nil, jrpc.NewErrorInvalidParams(nil)
		}
		return nil, d.Disable(p.Name)
	})
	j.Method("tunnel.disableAll", func(c *jrpc.Context, _ struct{}) (any, error) {
		if err := deny(c); err != nil {
			return nil, err
		}
		return nil, d.DisableAll()
	})
	j.Method("daemon.pause", func(c *jrpc.Context, _ struct{}) (any, error) {
		if err := deny(c); err != nil {
			return nil, err
		}
		return nil, d.Pause()
	})
	j.Method("daemon.resume", func(c *jrpc.Context, _ struct{}) (any, error) {
		if err := deny(c); err != nil {
			return nil, err
		}
		return nil, d.Resume()
	})
	j.Method("status.get", func(c *jrpc.Context, _ struct{}) (Status, error) {
		st := StatusOf(d.State())
		st.APIVersion = APIVersion
		st.Version, st.ConfigDir, st.LogPath = meta.Version, meta.ConfigDir, meta.LogPath
		st.ControlGroup = acc.Group()
		st.CanControl = canControl(c)
		if !st.CanControl {
			st = RedactStatus(st)
		}
		return st, nil
	})
	j.Method("diag.explain", func(c *jrpc.Context, p ExplainParams) (Explanation, error) {
		e, err := Explain(d.State(), p.Query)
		if err != nil || canControl(c) {
			return e, err
		}
		return RedactExplanation(e), nil
	})
	j.Method("diag.routes", func(c *jrpc.Context, _ struct{}) (Routes, error) {
		r := RoutesOf(d.State())
		if canControl(c) {
			return r, nil
		}
		return RedactRoutes(r), nil
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
