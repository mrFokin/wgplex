// Command wgplex runs several WireGuard tunnels at once with rule-based
// routing on macOS. "wgplex daemon" is the root daemon; the other commands
// are a client of its JSON-RPC socket, the same API as the app's.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mrFokin/wgplex/internal/rpc"
)

// version is set by the build (-ldflags "-X main.version=..."); "dev"
// without it.
var version = "dev"

const usage = `usage: wgplex [-socket path] <command> [args]

commands:
  status                tunnels, handshakes, traffic, rule state
  explain <domain|IP>   which rule and tunnel apply, and why
  routes                current routes: from configs and dynamic
  up <tunnel>           enable a tunnel
  down <tunnel>         disable a tunnel
  reload                the daemon re-reads the config
  daemon [-v]           run the daemon (as root)
  version               print the version
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
	case "version":
		fmt.Println("wgplex", version)
		return
	}
	if err := run(cmd); err != nil {
		printError(os.Stderr, err)
		os.Exit(1)
	}
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
		printStatus(os.Stdout, s, time.Now())
	case "explain":
		var e rpc.Explanation
		if err := call(ctx, sock, "diag.explain", rpc.ExplainParams{Query: cmd.Arg}, &e); err != nil {
			return err
		}
		printExplain(os.Stdout, e)
	case "routes":
		var r rpc.Routes
		if err := call(ctx, sock, "diag.routes", nil, &r); err != nil {
			return err
		}
		printRoutes(os.Stdout, r)
	case "up", "down":
		p := rpc.SetEnabledParams{Name: cmd.Arg, Enabled: cmd.Name == "up"}
		return call(ctx, sock, "tunnel.setEnabled", p, nil)
	case "reload":
		var r rpc.ReloadResult
		if err := call(ctx, sock, "config.reload", nil, &r); err != nil {
			return err
		}
		printReload(os.Stdout, r)
	default:
		return errors.New("unknown command " + cmd.Name) // parseArgs rejects it
	}
	return nil
}
