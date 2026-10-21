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
	Name      string // status | explain | routes | up | down | reload | daemon | version
	Arg       string // explain: query; up, down: tunnel
	ConfigDir string // daemon: -config or the default (design 3)
	Socket    string // -socket or the default (design 3)
	StatePath string // daemon: -state or the default (design 3, 11)
	LogPath   string // daemon: -log or the default (design 3, 15)
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
	"daemon":  0,
	"version": 0,
}

// parseArgs parses os.Args[1:]: [flags] <command> [arg] [flags]. The flags
// are -socket path (every command), -config dir, -state path and -log file
// (daemon only, design 13: the daemon reads its config directory, its state
// file and writes its log itself) and -v (daemon only); they may go before
// the command or after it and its argument. A usage error is errUsage-wrapped
// (exit 2): no or an unknown command, a wrong number of arguments, an empty
// argument, a flag the command does not take.
//
// def gives the defaults (pathsFor(defaultPrefix()) in main), so parseArgs
// itself looks at nothing outside args. ConfigDir, StatePath and LogPath are
// set for daemon only.
func parseArgs(args []string, def paths) (command, error) {
	fs := flag.NewFlagSet("wgplex", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", def.Socket, "RPC socket `path`")
	dir := fs.String("config", def.ConfigDir, "config `dir` (daemon)")
	statePath := fs.String("state", def.State, "state `file` (daemon)")
	logPath := fs.String("log", def.Log, "log `file` (daemon)")
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
		// A flag of a later stage (down -all, -json) or a flag without its
		// value lands in the argument position: no tunnel name, domain or IP
		// starts with "-" (design 13).
		if strings.HasPrefix(cmd.Arg, "-") {
			return command{}, fmt.Errorf("%w: %s: unexpected flag %q", errUsage, cmd.Name, cmd.Arg)
		}
	}
	// Flags after the command and its argument.
	if err := fs.Parse(rest[1+n:]); err != nil {
		return command{}, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return command{}, fmt.Errorf("%w: %s takes %d argument(s)", errUsage, cmd.Name, n)
	}
	var bad error
	fs.Visit(func(f *flag.Flag) {
		if bad == nil && ((f.Name == "config" || f.Name == "state" || f.Name == "log") && cmd.Name != "daemon" || f.Name == "v" && cmd.Name != "daemon") {
			bad = fmt.Errorf("%w: %s does not take -%s", errUsage, cmd.Name, f.Name)
		}
	})
	if bad != nil {
		return command{}, bad
	}
	cmd.Socket, cmd.Verbose = *socket, *verbose
	if cmd.Name == "daemon" {
		cmd.ConfigDir, cmd.StatePath, cmd.LogPath = *dir, *statePath, *logPath
	}
	return cmd, nil
}
