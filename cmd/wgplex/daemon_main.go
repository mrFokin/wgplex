package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/health"
	"github.com/mrFokin/wgplex/internal/netwatch"
	"github.com/mrFokin/wgplex/internal/rpc"
	"github.com/mrFokin/wgplex/internal/state"
)

// daemonMain is "wgplex daemon": the daemon runs as root under launchd and
// owns the WireGuard tunnels, the routing table and the local DNS resolver
// (design 4.1). It logs to cmd.Log (-v: debug, including verbose
// wireguard-go), group admin until a config names control_group, with fd 1
// and 2 pointed at the log, so that Go panics land there too (design 15).
// Returns the exit code.
//
// Not root, it reports to stderr and exits 0: "brew services start" without
// sudo installs a LaunchAgent of the user, and launchd must not restart it
// (design 4.1). The log not opened (its directory missing included: the
// daemon does not create it) — stderr and exit 1.
func daemonMain(cmd command) int {
	level := slog.LevelInfo
	if cmd.Verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	stderr := slog.New(slog.NewTextHandler(os.Stderr, opts))
	if os.Geteuid() != 0 {
		stderr.Error("wgplex daemon must run as root: sudo brew services start --sudo-service-user=root wgplex")
		return 0
	}
	gid, gerr := groupID("admin")
	if gerr != nil {
		gid = -1 // the group of the directory
	}
	lf, err := openLog(cmd.Log, gid)
	if err != nil {
		if dir := filepath.Dir(cmd.Log); !exists(dir) {
			stderr.Error("log: directory "+dir+" does not exist; the daemon does not create it", "log", cmd.Log)
		} else {
			stderr.Error("log", "err", err)
		}
		return 1
	}
	log := slog.New(slog.NewTextHandler(lf, opts))
	if gerr != nil {
		log.Warn("log group admin", "err", gerr)
	}
	if err := lf.Dup2Std(); err != nil {
		log.Error("log: stdout and stderr not redirected", "err", err)
	}
	return runDaemon(log, lf, cmd)
}

// groupID returns the gid of the group name: a number is taken as is (design
// 5), a name is looked up.
func groupID(name string) (int, error) {
	if gid, err := strconv.Atoi(name); err == nil {
		return gid, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

// exists reports whether path exists (an error other than "not exist" counts
// as existing: the caller's own error tells more).
func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// runDaemon starts the daemon listening on cmd.Socket and serves until
// SIGINT/SIGTERM (exit code 0) or a failure of the resolver or the RPC
// server (1), then stops: DNS released, routes, tunnels and the socket
// removed. logFile is the log (nil: none), its group follows control_group.
//
// Before the RPC it reads state.json (a broken one: a warning, the tunnels
// by autostart, design 11) and applies the config of cmd.ConfigDir (design
// 4.1, 10.2): nothing left by the previous run is removed beforehand, the
// first sync replaces it. An invalid config leaves the daemon running
// without tunnels, with the errors in status.get.
//
// The socket goes first: a second daemon fails there and touches nothing
// of the running one. The socket file is removed only by closing our own
// listener (net.UnixListener unlinks its path on Close, which Serve or the
// error path does), never by path: a failed start leaves it alone.
func runDaemon(log *slog.Logger, logFile *rotatingFile, cmd command) int {
	socket := cmd.Socket
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

	toggles, err := state.Load(cmd.State)
	if err != nil {
		log.Warn("state: tunnels by autostart, no pause, no block snapshot", "err", err)
	}

	srv := &dns.Server{Log: log}
	d := newDaemon(ctx, srv, log, cmd.ConfigDir, cmd.State, toggles, logFile)
	// state.json has the group of the log, admin, until control_group (design 15).
	if gid, err := groupID("admin"); err == nil {
		d.gid = gid
	}
	d.setSystem() // the upstream of the resolver before any config
	// Watching from before the config: a change of the network during the
	// first apply is seen too.
	events := netwatch.Watch(ctx, dns.CaptureKey, log)
	if err := srv.Start(dnsAddr); err != nil {
		log.Error("dns server", "err", err)
		ln.Close()
		return 1
	}
	log.Info("dns server listening", "addr", dnsAddr)

	// The resolver listens before the config may capture the system DNS.
	d.startup()

	served := make(chan error, 1)
	go func() {
		acc := access(d, log)
		meta := rpc.Meta{Version: version, ConfigDir: cmd.ConfigDir, LogPath: cmd.Log}
		served <- rpc.Serve(ctx, ln, d, acc, meta, log)
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

// access returns the rights of the RPC callers (design 5): the owner of the
// config directory of d by stat on every check (following a symlink, as the
// config is read), control_group of the applied config and the membership by
// Directory Services (rpc.IsMember).
func access(d *daemon, log *slog.Logger) *rpc.Access {
	return &rpc.Access{
		OwnerUID: func() (uint32, bool) { return ownerUID(d.dir) },
		ConfigGroup: func() string {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.cfg == nil {
				return ""
			}
			return d.cfg.ControlGroup
		},
		IsMember: rpc.IsMember,
		Now:      time.Now,
		Log:      log,
	}
}

// ownerUID returns the owner uid of dir; false: it cannot be stat'ed (not
// there), so only root controls.
func ownerUID(dir string) (uint32, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
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
