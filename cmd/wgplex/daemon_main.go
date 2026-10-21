package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/health"
	"github.com/mrFokin/wgplex/internal/netwatch"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/rpc"
)

// daemonMain is "wgplex daemon": the daemon runs as root under launchd and
// owns the WireGuard tunnels, the routing table and the local DNS resolver
// (design 4.1). It logs to stderr (-v: debug, including verbose
// wireguard-go) and returns the exit code.
//
// Not root, it reports to stderr and exits 0: "brew services start" without
// sudo installs a LaunchAgent of the user, and launchd must not restart it
// (design 4.1).
func daemonMain(cmd command) int {
	level := slog.LevelInfo
	if cmd.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if os.Geteuid() != 0 {
		log.Error("wgplex daemon must run as root: sudo brew services start --sudo-service-user=root wgplex")
		return 0
	}
	return runDaemon(log, cmd.Socket, cmd.ConfigDir)
}

// runDaemon starts the daemon listening on socket and serves until
// SIGINT/SIGTERM (exit code 0) or a failure of the resolver or
// the RPC server (1), then stops: DNS released, routes, tunnels and the
// socket removed.
//
// It reads the config directory configDir and applies it itself at startup
// (design 10.2): with a broken config the daemon works without tunnels, the
// problems are in the log and in status.get. The resolver listens on
// 127.0.0.1:53 and the RPC starts when the config is done.
//
// The socket goes first: a second daemon fails there and touches nothing
// of the running one. The socket file is removed only by closing our own
// listener (net.UnixListener unlinks its path on Close, which Serve or the
// error path does), never by path: a failed start leaves it alone.
func runDaemon(log *slog.Logger, socket, configDir string) int {
	// SIGHUP and SIGUSR1 would kill the process without cleanup (design 4.1).
	signal.Ignore(syscall.SIGHUP, syscall.SIGUSR1)
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	ln, err := rpc.Listen(socket)
	if err != nil {
		logListenError(log, socket, err)
		return 1
	}

	// Leftovers of a crash.
	if err := router.DeleteOwned(); err != nil {
		log.Warn("delete stale routes", "err", err)
	}
	releaseDNS(log)

	srv := &dns.Server{Log: log}
	d := newDaemon(ctx, srv, log, configDir)
	d.setSystem() // the upstream of the resolver before any config (Wirefork M6 fact 7)
	// Watching from before the first config: a change of the network before
	// the first apply is seen too.
	events := netwatch.Watch(ctx, dns.CaptureKey, log)
	if err := srv.Start(dnsAddr); err != nil {
		log.Error("dns server", "err", err)
		ln.Close()
		return 1
	}
	log.Info("dns server listening", "addr", dnsAddr)

	// The daemon reads the config directory itself at startup (design
	// 10.2): a broken config is logged with every problem and the daemon
	// keeps running without tunnels (design 4.1); the error of Reload was
	// made into the RPC reply it never sends here.
	_, _ = d.Reload()

	served := make(chan error, 1)
	go func() {
		served <- rpc.Serve(ctx, ln, d, allow, log)
	}()
	log.Info("rpc listening", "socket", socket)

	tick := time.NewTicker(expireEvery)
	defer tick.Stop()
	healthT := time.NewTicker(health.Interval)
	defer healthT.Stop()
	code := 0
	serving := true
loop:
	for {
		select {
		case <-ctx.Done():
			log.Info("stopping")
			break loop
		case err := <-srv.Err():
			log.Error("dns server", "err", err)
			code = 1
			break loop
		case err := <-served:
			serving = false
			log.Error("rpc server stopped", "err", err)
			code = 1
			break loop
		case now := <-tick.C:
			d.expire(now)
		case now := <-healthT.C:
			d.healthTick(ctx, now)
		case e, ok := <-events:
			if !ok {
				events = nil // ctx is done: the next round stops
				continue
			}
			d.handle(e)
		}
	}
	cancel()
	if serving {
		// Stops accepting and waits for the requests in progress.
		if err := <-served; err != nil {
			log.Warn("rpc server", "err", err)
		}
	}
	d.shutdown()
	log.Info("stopped")
	return code
}

// logListenError reports a failure to listen on socket. The daemon creates
// no directories (design 4.1): a missing directory of the socket gets its
// own message.
func logListenError(log *slog.Logger, socket string, err error) {
	dir := filepath.Dir(socket)
	if _, serr := os.Stat(dir); errors.Is(serr, fs.ErrNotExist) {
		log.Error("rpc socket: directory "+dir+" does not exist; the daemon does not create it", "socket", socket)
		return
	}
	log.Error("rpc socket", "err", err)
}

// allow lets only root use the RPC (M1: per-method rights come in M3).
func allow(uid uint32) bool {
	return uid == 0
}
