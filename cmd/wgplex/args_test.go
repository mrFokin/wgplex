package main

import (
	"errors"
	"testing"
)

// Tests follow design 13 (CLI) and plan m1-port, decisions 11 and 12 and
// «Открытые места контракта» (commands, flags before or after the command,
// -socket for the clients of the daemon, -config for the daemon and check,
// -state and -v only for daemon), not the implementation.

var argsDef = paths{Socket: "/def/var/run/wgplex.sock", ConfigDir: "/def/etc/wgplex", State: "/def/var/wgplex/state.json", Log: "/def/var/log/wgplex/wgplex.log"}

func TestParseArgs(t *testing.T) {
	sock, cfg, st, log := argsDef.Socket, argsDef.ConfigDir, argsDef.State, argsDef.Log
	tests := []struct {
		name string
		args []string
		want command
	}{
		// design 13: commands without an argument; -socket defaults to def.
		{"status", []string{"status"}, command{Name: "status", Socket: sock}},
		{"routes", []string{"routes"}, command{Name: "routes", Socket: sock}},
		{"version", []string{"version"}, command{Name: "version", Socket: sock}},
		{"daemon", []string{"daemon"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: log}},
		// M2 (design 13): the daemon reads the config itself; reload does
		// not take files any more.
		{"reload", []string{"reload"}, command{Name: "reload", Socket: sock}},
		// M2 (design 13): check validates the config directory locally,
		// without the daemon; -config defaults to the same directory.
		{"check", []string{"check"}, command{Name: "check", ConfigDir: cfg, Socket: sock}},

		// design 13: explain, up, down take exactly one argument.
		{"explain domain", []string{"explain", "example.com"}, command{Name: "explain", Arg: "example.com", Socket: sock}},
		{"explain ip", []string{"explain", "10.0.0.1"}, command{Name: "explain", Arg: "10.0.0.1", Socket: sock}},
		{"up", []string{"up", "de"}, command{Name: "up", Arg: "de", Socket: sock}},
		{"down", []string{"down", "de"}, command{Name: "down", Arg: "de", Socket: sock}},

		// decision 11: -socket for every client of the daemon, before or after.
		{"status socket before", []string{"-socket", "/x.sock", "status"}, command{Name: "status", Socket: "/x.sock"}},
		{"status socket after", []string{"status", "-socket", "/x.sock"}, command{Name: "status", Socket: "/x.sock"}},
		{"status socket equals", []string{"status", "-socket=/x.sock"}, command{Name: "status", Socket: "/x.sock"}},
		{"routes socket", []string{"routes", "-socket", "/x.sock"}, command{Name: "routes", Socket: "/x.sock"}},
		{"version socket", []string{"version", "-socket", "/x.sock"}, command{Name: "version", Socket: "/x.sock"}},
		{"daemon socket", []string{"daemon", "-socket", "/x.sock"}, command{Name: "daemon", ConfigDir: cfg, Socket: "/x.sock", StatePath: st, LogPath: log}},
		{"reload socket", []string{"reload", "-socket", "/x.sock"}, command{Name: "reload", Socket: "/x.sock"}},
		{"explain socket before command", []string{"-socket", "/x.sock", "explain", "a.com"}, command{Name: "explain", Arg: "a.com", Socket: "/x.sock"}},
		{"explain socket after arg", []string{"explain", "a.com", "-socket", "/x.sock"}, command{Name: "explain", Arg: "a.com", Socket: "/x.sock"}},
		{"up socket after arg", []string{"up", "de", "-socket", "/x.sock"}, command{Name: "up", Arg: "de", Socket: "/x.sock"}},
		{"down socket before", []string{"-socket", "/x.sock", "down", "de"}, command{Name: "down", Arg: "de", Socket: "/x.sock"}},

		// design 13, M2: -config for the daemon and check, before or after.
		{"daemon config after", []string{"daemon", "-config", "/cfg"}, command{Name: "daemon", ConfigDir: "/cfg", Socket: sock, StatePath: st, LogPath: log}},
		{"daemon config before", []string{"-config", "/cfg", "daemon"}, command{Name: "daemon", ConfigDir: "/cfg", Socket: sock, StatePath: st, LogPath: log}},
		{"daemon config equals", []string{"daemon", "-config=/cfg"}, command{Name: "daemon", ConfigDir: "/cfg", Socket: sock, StatePath: st, LogPath: log}},
		{"daemon config and socket", []string{"-socket", "/x.sock", "daemon", "-config", "/cfg"}, command{Name: "daemon", ConfigDir: "/cfg", Socket: "/x.sock", StatePath: st, LogPath: log}},
		{"check config after", []string{"check", "-config", "/cfg"}, command{Name: "check", ConfigDir: "/cfg", Socket: sock}},
		{"check config before", []string{"-config", "/cfg", "check"}, command{Name: "check", ConfigDir: "/cfg", Socket: sock}},
		{"check config equals", []string{"check", "-config=/cfg"}, command{Name: "check", ConfigDir: "/cfg", Socket: sock}},

		// M2 (design 13): -state only for the daemon, before or after.
		{"daemon state after", []string{"daemon", "-state", "/s.json"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: "/s.json", LogPath: log}},
		{"daemon state before", []string{"-state", "/s.json", "daemon"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: "/s.json", LogPath: log}},
		{"daemon state equals", []string{"daemon", "-state=/s.json"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: "/s.json", LogPath: log}},
		{"daemon state and config", []string{"daemon", "-config", "/cfg", "-state", "/s.json"}, command{Name: "daemon", ConfigDir: "/cfg", Socket: sock, StatePath: "/s.json", LogPath: log}},

		// M2 (design 13, 15): -log only for the daemon, before or after.
		{"daemon log after", []string{"daemon", "-log", "/l.log"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: "/l.log"}},
		{"daemon log before", []string{"-log", "/l.log", "daemon"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: "/l.log"}},
		{"daemon log equals", []string{"daemon", "-log=/l.log"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: "/l.log"}},
		{"daemon log and state", []string{"daemon", "-log", "/l.log", "-state", "/s.json"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: "/s.json", LogPath: "/l.log"}},

		// decision 11: -v only for daemon, before or after.
		{"daemon v after", []string{"daemon", "-v"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: log, Verbose: true}},
		{"daemon v before", []string{"-v", "daemon"}, command{Name: "daemon", ConfigDir: cfg, Socket: sock, StatePath: st, LogPath: log, Verbose: true}},
		{"daemon v and socket", []string{"daemon", "-v", "-socket", "/x.sock"}, command{Name: "daemon", ConfigDir: cfg, Socket: "/x.sock", StatePath: st, LogPath: log, Verbose: true}},
		{"daemon socket and v", []string{"-socket", "/x.sock", "daemon", "-v"}, command{Name: "daemon", ConfigDir: cfg, Socket: "/x.sock", StatePath: st, LogPath: log, Verbose: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args, argsDef)
			if err != nil {
				t.Fatalf("parseArgs(%q) error: %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("parseArgs(%q) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}

// design 3: the defaults come from def (derived from the prefix), not from
// constants.
func TestParseArgsDefaultsFromDef(t *testing.T) {
	def := paths{
		Socket:    "/Users/u/brew/var/run/wgplex.sock",
		ConfigDir: "/Users/u/brew/etc/wgplex",
		State:     "/Users/u/brew/var/wgplex/state.json",
		Log:       "/Users/u/brew/var/log/wgplex/wgplex.log",
	}
	got, err := parseArgs([]string{"daemon"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if got.Socket != def.Socket || got.ConfigDir != def.ConfigDir || got.StatePath != def.State || got.LogPath != def.Log {
		t.Errorf("daemon: got %+v, want socket %q, config %q, state %q and log %q", got, def.Socket, def.ConfigDir, def.State, def.Log)
	}
	got, err = parseArgs([]string{"up", "de"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if got.Socket != def.Socket || got.ConfigDir != "" || got.LogPath != "" {
		t.Errorf("up: got %+v, want socket %q and no config or log", got, def.Socket)
	}
	// design 13, M2: check reads the same default directory as the daemon
	// and is no client of it (no -socket).
	got, err = parseArgs([]string{"check"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigDir != def.ConfigDir || got.StatePath != "" || got.LogPath != "" {
		t.Errorf("check: got %+v, want config %q and no state or log", got, def.ConfigDir)
	}
}

func TestParseArgsUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		// contract: no command, unknown command.
		{"nil", nil},
		{"empty", []string{}},
		{"only flags", []string{"-socket", "/x.sock"}},
		{"empty command", []string{""}},
		{"unknown", []string{"start"}},
		{"unknown case", []string{"Status"}},
		// design 13 commands that are not in M2 (M3).
		{"pause", []string{"pause"}},
		{"resume", []string{"resume"}},

		// contract: explain, up, down need exactly one non-empty argument.
		{"explain no arg", []string{"explain"}},
		{"up no arg", []string{"up"}},
		{"down no arg", []string{"down"}},
		{"explain empty arg", []string{"explain", ""}},
		{"up empty arg", []string{"up", ""}},
		{"down empty arg", []string{"down", ""}},
		{"explain two args", []string{"explain", "a.com", "b.com"}},
		{"up two args", []string{"up", "de", "nl"}},
		{"down two args", []string{"down", "de", "nl"}},
		{"up two args around flag", []string{"up", "de", "-socket", "/x.sock", "nl"}},
		// flags of later stages land in the argument position (M3: down -all,
		// -json; design 13): not a tunnel name, domain or IP.
		{"down all not in M1", []string{"down", "-all"}},
		{"up socket without value", []string{"up", "-socket"}},
		{"explain json", []string{"explain", "-json"}},
		{"down dashdash", []string{"down", "--"}},

		// contract: other commands take no arguments.
		{"status arg", []string{"status", "de"}},
		{"routes arg", []string{"routes", "de"}},
		{"reload arg", []string{"reload", "/cfg"}},
		{"check arg", []string{"check", "/cfg"}},
		{"check two args", []string{"check", "/cfg", "/cfg2"}},
		{"check arg around flag", []string{"check", "-config", "/cfg", "x"}},
		{"daemon arg", []string{"daemon", "x"}},
		{"version arg", []string{"version", "x"}},
		{"status empty arg", []string{"status", ""}},

		// M2 (design 13): -config belongs to the daemon and check now, the
		// other client commands lost it.
		{"status config", []string{"status", "-config", "/cfg"}},
		{"explain config", []string{"explain", "a.com", "-config", "/cfg"}},
		{"routes config", []string{"routes", "-config", "/cfg"}},
		{"up config", []string{"up", "de", "-config", "/cfg"}},
		{"down config before", []string{"-config", "/cfg", "down", "de"}},
		{"reload config", []string{"reload", "-config", "/cfg"}},
		{"version config", []string{"version", "-config", "/cfg"}},
		// M2: check takes -config, not the daemon's other flags.
		{"check state", []string{"check", "-state", "/s.json"}},
		{"check log", []string{"check", "-log", "/l.log"}},
		{"check v", []string{"check", "-v"}},
		// M2 (design 13): check is not a client of the daemon, so -socket is
		// a usage error; the flag is not silently ignored.
		{"check socket", []string{"check", "-socket", "/x.sock"}},
		{"check socket before", []string{"-socket", "/x.sock", "check"}},
		{"check config and socket", []string{"-socket", "/x.sock", "check", "-config", "/cfg"}},

		// decision 11: -v only for daemon.
		{"status v", []string{"status", "-v"}},
		{"reload v", []string{"reload", "-v"}},
		{"up v", []string{"up", "de", "-v"}},
		{"version v before", []string{"-v", "version"}},

		// contract: unknown flags, including those of later stages.
		{"unknown flag", []string{"status", "-x"}},
		{"unknown flag before", []string{"-x", "status"}},
		{"json not in M1", []string{"status", "-json"}},
		// design 13: -all is a flag of down, not a tunnel name; not in M1.
		{"down all not in M1", []string{"down", "-all"}},
		// M2 (design 13, 15): -log belongs to the daemon like -config and
		// -state; other commands do not take it.
		{"status log", []string{"status", "-log", "/l.log"}},
		{"reload log", []string{"reload", "-log", "/l.log"}},
		{"up log", []string{"up", "de", "-log", "/l.log"}},
		{"version log before", []string{"-log", "/l.log", "version"}},
		// M2: -state belongs to the daemon (design 13); other commands do
		// not take it.
		{"status state", []string{"status", "-state", "/s.json"}},
		{"reload state", []string{"reload", "-state", "/s.json"}},
		{"up state", []string{"up", "de", "-state", "/s.json"}},
		{"version state", []string{"version", "-state", "/s.json"}},

		// a flag without its value.
		{"socket without value", []string{"status", "-socket"}},
		{"config without value", []string{"daemon", "-config"}},
		{"check config without value", []string{"check", "-config"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args, argsDef)
			if !errors.Is(err, errUsage) {
				t.Errorf("parseArgs(%q) = %+v, %v; want errUsage", tt.args, got, err)
			}
		})
	}
}
