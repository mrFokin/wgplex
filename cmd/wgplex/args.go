package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// errUsage wraps usage errors of parseArgs (exit 2).
var errUsage = errors.New("usage")

type command struct {
	Name      string // status | explain | routes | up | down | reload | check | daemon | version
	Arg       string // explain: query; up, down: tunnel
	ConfigDir string // daemon, check: -config or the default (design 3)
	Socket    string // -socket or the default (design 3); not for check
	State     string // daemon: -state or the default (design 3)
	Log       string // daemon: -log or the default (design 3)
	Verbose   bool   // daemon: -v
}

// nargs is the number of arguments of each command.
var nargs = map[string]int{
	"status":  0,
	"explain": 1,
	"routes":  0,
	"up":      1,
	"down":    1,
	"reload":  0,
	"check":   0,
	"daemon":  0,
	"version": 0,
}

// parseArgs parses os.Args[1:]: [flags] <command> [arg] [flags]. The flags
// (design 13) are -socket path (every command but check), -config dir
// (daemon and check), -state path, -log path and -v (daemon only); they may
// go before the command or after it and its argument. A usage error is errUsage-wrapped (exit 2): no or an unknown
// command, a wrong number of arguments, an empty argument, a flag the
// command does not take.
//
// def gives the defaults (pathsFor(defaultPrefix()) in main), so parseArgs
// itself looks at nothing outside args. ConfigDir is set for daemon and
// check only, State and Log for daemon only. reload takes no -config: the
// daemon reads its own config directory (design 10.2).
func parseArgs(args []string, def paths) (command, error) {
	fs := flag.NewFlagSet("wgplex", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", def.Socket, "RPC socket `path`")
	dir := fs.String("config", def.ConfigDir, "config `dir`")
	state := fs.String("state", def.State, "state `path` (daemon)")
	logPath := fs.String("log", def.Log, "log `path` (daemon)")
	verbose := fs.Bool("v", false, "debug logging (daemon)")
	if err := fs.Parse(args); err != nil {
		return command{}, fmt.Errorf("%w: %v", errUsage, err)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return command{}, fmt.Errorf("%w: no command", errUsage)
	}
	cmd := command{Name: rest[0]}
	n, ok := nargs[cmd.Name]
	if !ok {
		return command{}, fmt.Errorf("%w: unknown command %q", errUsage, cmd.Name)
	}
	if len(rest)-1 < n {
		return command{}, fmt.Errorf("%w: %s takes %d argument(s)", errUsage, cmd.Name, n)
	}
	if n == 1 {
		cmd.Arg = rest[1]
		if cmd.Arg == "" {
			return command{}, fmt.Errorf("%w: %s: empty argument", errUsage, cmd.Name)
		}
		// An argument starting with "-" is a flag (down -all of a later
		// stage), not a tunnel name or a query.
		if strings.HasPrefix(cmd.Arg, "-") {
			return command{}, fmt.Errorf("%w: %s: flags go before the command or after its argument (got %q)", errUsage, cmd.Name, cmd.Arg)
		}
	}
	// Flags after the command and its argument.
	if err := fs.Parse(rest[1+n:]); err != nil {
		return command{}, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return command{}, fmt.Errorf("%w: %s takes %d argument(s)", errUsage, cmd.Name, n)
	}
	daemon, check := cmd.Name == "daemon", cmd.Name == "check"
	var bad error
	fs.Visit(func(f *flag.Flag) {
		var ok bool
		switch f.Name {
		case "socket":
			ok = !check
		case "config":
			ok = daemon || check
		default: // state, log, v
			ok = daemon
		}
		if bad == nil && !ok {
			bad = fmt.Errorf("%w: %s does not take -%s", errUsage, cmd.Name, f.Name)
		}
	})
	if bad != nil {
		return command{}, bad
	}
	if !check {
		cmd.Socket = *socket
	}
	if daemon || check {
		cmd.ConfigDir = *dir
	}
	if daemon {
		cmd.State, cmd.Log, cmd.Verbose = *state, *logPath, *verbose
	}
	return cmd, nil
}
