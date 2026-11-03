// Command wgplex runs several WireGuard tunnels at once with rule-based
// routing on macOS. "wgplex daemon" is the root daemon; the other commands
// are a client of its JSON-RPC socket, the same API as the app's.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mrFokin/wgplex/internal/rpc"
)

// version is set by the build (-ldflags "-X main.version=..."); "dev"
// without it.
var version = "dev"

const usage = `usage: wgplex [-socket path] <command> [args]
       wgplex check [-config dir] [-json]

commands:
  status [-json]              tunnels, handshakes, traffic, rule state
  explain <domain|IP> [-json] which rule and tunnel apply, and why
  routes [-json]              current routes: from configs and dynamic
  up <tunnel>                 enable a tunnel (remembered)
  down <tunnel> | -all        disable one tunnel or all (remembered)
  pause                       drop all tunnels, keep the toggles
  resume                      bring the tunnels back
  reload                      the daemon re-reads its config
  check [-config dir] [-json] check the config without the daemon and root
                              (default <prefix>/etc/wgplex)
  daemon [-v]                 run the daemon (as root); debug flags:
                              -config dir, -state path, -log path

  version                     print the versions of the CLI and the daemon
`

// callTimeout bounds one call: bringing several tunnels up takes a while.
const callTimeout = 60 * time.Second

func main() {
	cmd, err := parseArgs(os.Args[1:], pathsFor(defaultPrefix()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgplex: %v\n\n%s", err, usage)
		os.Exit(2)
	}
	switch cmd.Name {
	case "daemon":
		os.Exit(daemonMain(cmd))
	case "check":
		os.Exit(checkMain(cmd, os.Stdout, os.Stderr))
	case "version":
		os.Exit(versionMain(cmd, os.Stdout, os.Stderr))
	}
	if err := run(cmd); err != nil {
		printError(os.Stderr, err)
		os.Exit(exitCode(err))
	}
}

// exitCode is the exit code of a failed client command (design 13): 3 when
// the daemon is unavailable (no socket, refused, timeout), 1 otherwise,
// permission denied (JSON-RPC error 5) included.
func exitCode(err error) int {
	if daemonUnavailable(err) {
		return 3
	}
	return 1
}

// run runs the client command cmd and prints its result to stdout.
func run(cmd command) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	sock := cmd.Socket
	switch cmd.Name {
	case "status":
		var s rpc.Status
		if err := call(ctx, sock, "status.get", nil, &s); err != nil {
			return err
		}
		if w := versionWarning(version, s.Version); w != "" {
			fmt.Fprintln(os.Stderr, w)
		}
		if cmd.JSON {
			return printJSON(os.Stdout, s)
		}
		printStatus(os.Stdout, s, time.Now())
	case "explain":
		var e rpc.Explanation
		if err := call(ctx, sock, "diag.explain", rpc.ExplainParams{Query: cmd.Arg}, &e); err != nil {
			return err
		}
		if cmd.JSON {
			return printJSON(os.Stdout, e)
		}
		printExplain(os.Stdout, e)
	case "routes":
		var r rpc.Routes
		if err := call(ctx, sock, "diag.routes", nil, &r); err != nil {
			return err
		}
		if cmd.JSON {
			return printJSON(os.Stdout, r)
		}
		printRoutes(os.Stdout, r)
	case "up":
		var r rpc.EnableResult
		if err := call(ctx, sock, "tunnel.enable", rpc.EnableParams{Name: cmd.Arg}, &r); err != nil {
			return err
		}
		if r.StartsOnResume {
			fmt.Fprintln(os.Stdout, "starts on resume")
		}
	case "down":
		if cmd.All {
			return call(ctx, sock, "tunnel.disableAll", nil, nil)
		}
		return call(ctx, sock, "tunnel.disable", rpc.EnableParams{Name: cmd.Arg}, nil)
	case "pause":
		return call(ctx, sock, "daemon.pause", nil, nil)
	case "resume":
		return call(ctx, sock, "daemon.resume", nil, nil)
	case "reload":
		// The daemon reads its own config directory (design 10.2).
		var r rpc.ApplyResult
		if err := call(ctx, sock, "config.reload", nil, &r); err != nil {
			return err
		}
		printApply(os.Stdout, r)
	default:
		return errors.New("unknown command " + cmd.Name) // parseArgs rejects it
	}
	return nil
}

// versionMain is "wgplex version" (design 13): the versions of the CLI and
// of the daemon, one per line. A daemon that does not answer leaves the CLI
// line alone — version prints what it has, without failing. Differing
// versions warn on stderr with the command that restarts the service (plan
// M3, decision 11); the exit code stays 0.
func versionMain(cmd command, stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "wgplex", version)
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var s rpc.Status
	if err := call(ctx, cmd.Socket, "status.get", nil, &s); err != nil {
		if !daemonUnavailable(err) {
			printError(stderr, err)
		}
		return 0
	}
	fmt.Fprintln(stdout, "daemon", s.Version)
	if w := versionWarning(version, s.Version); w != "" {
		fmt.Fprintln(stderr, w)
	}
	return 0
}
