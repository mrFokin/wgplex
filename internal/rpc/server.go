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
	Reload() (ReloadResult, error)
	SetEnabled(name string, enabled bool) error
	DisableAll() error
	State() *State
}

// peerKey is the context key of the peer of a connection.
type peerKey struct{}

// peer is the uid of the peer of a connection, or the error getting it.
type peer struct {
	uid uint32
	err error
}

// Serve serves the wgplex RPC methods (M2: config.reload takes no params —
// the daemon reads its own config directory, design 10.2; the per-method
// rights, design 14, come in M3) at Path on ln until ctx is done, then
// shuts down gracefully. A connection whose peer uid (LOCAL_PEERCRED) fails
// allow gets HTTP 403 (decision 4). Returns nil after ctx is done.
//
// The uid is taken in http.Server.ConnContext (set in BeforeServeFunc) and
// checked by an Echo middleware on the jrpc Endpoint (Wirefork M6 fact 3).
func Serve(ctx context.Context, ln net.Listener, d Daemon, allow func(uid uint32) bool, log *slog.Logger) error {
	e := echo.New()
	e.Logger = log

	// check lets through requests whose connection peer passes allow.
	check := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p, ok := c.Request().Context().Value(peerKey{}).(peer)
			switch {
			case !ok:
				log.Warn("rpc: forbidden: no peer credentials")
			case p.err != nil:
				log.Warn("rpc: forbidden", "err", p.err)
			case !allow(p.uid):
				log.Warn("rpc: forbidden", "uid", p.uid)
			default:
				return next(c)
			}
			return c.String(http.StatusForbidden, "forbidden")
		}
	}

	j := jrpc.Endpoint(e, Path, check)
	j.Method("config.reload", func(_ *jrpc.Context, _ struct{}) (ReloadResult, error) {
		return d.Reload()
	})
	// toggle is the body of tunnel.enable and tunnel.disable (design 14:
	// a verb per direction, no boolean params).
	toggle := func(p TunnelParams, enabled bool) (any, error) {
		if p.Name == "" {
			return nil, jrpc.NewErrorInvalidParams(nil)
		}
		return nil, d.SetEnabled(p.Name, enabled)
	}
	j.Method("tunnel.enable", func(_ *jrpc.Context, p TunnelParams) (any, error) {
		return toggle(p, true)
	})
	j.Method("tunnel.disable", func(_ *jrpc.Context, p TunnelParams) (any, error) {
		return toggle(p, false)
	})
	j.Method("tunnel.disableAll", func(_ *jrpc.Context, _ struct{}) (any, error) {
		return nil, d.DisableAll()
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
