package main

import (
	"errors"
	"testing"
)

// Tests follow design 13 (CLI) and plan m1-port, decisions 11 and 12 and
// «Открытые места контракта» (commands, flags before or after the command,
// -socket for all, -config only for reload, -v only for daemon), not the
// implementation.

var argsDef = paths{Socket: "/def/var/run/wgplex.sock", ConfigDir: "/def/etc/wgplex"}

func TestParseArgs(t *testing.T) {
	sock := argsDef.Socket
	cfg := argsDef.ConfigDir
	tests := []struct {
		name string
		args []string
		want command
	}{
		// design 13: commands without an argument; -socket defaults to def.
		{"status", []string{"status"}, command{Name: "status", Socket: sock}},
		{"routes", []string{"routes"}, command{Name: "routes", Socket: sock}},
		{"version", []string{"version"}, command{Name: "version", Socket: sock}},
		{"daemon", []string{"daemon"}, command{Name: "daemon", Socket: sock}},
		// decision 11: reload has -config, default def.ConfigDir.
		{"reload", []string{"reload"}, command{Name: "reload", ConfigDir: cfg, Socket: sock}},

		// design 13: explain, up, down take exactly one argument.
		{"explain domain", []string{"explain", "example.com"}, command{Name: "explain", Arg: "example.com", Socket: sock}},
		{"explain ip", []string{"explain", "10.0.0.1"}, command{Name: "explain", Arg: "10.0.0.1", Socket: sock}},
		{"up", []string{"up", "de"}, command{Name: "up", Arg: "de", Socket: sock}},
		{"down", []string{"down", "de"}, command{Name: "down", Arg: "de", Socket: sock}},

		// decision 11: -socket for every command, before or after.
		{"status socket before", []string{"-socket", "/x.sock", "status"}, command{Name: "status", Socket: "/x.sock"}},
		{"status socket after", []string{"status", "-socket", "/x.sock"}, command{Name: "status", Socket: "/x.sock"}},
		{"status socket equals", []string{"status", "-socket=/x.sock"}, command{Name: "status", Socket: "/x.sock"}},
		{"routes socket", []string{"routes", "-socket", "/x.sock"}, command{Name: "routes", Socket: "/x.sock"}},
		{"version socket", []string{"version", "-socket", "/x.sock"}, command{Name: "version", Socket: "/x.sock"}},
		{"daemon socket", []string{"daemon", "-socket", "/x.sock"}, command{Name: "daemon", Socket: "/x.sock"}},
		{"reload socket", []string{"reload", "-socket", "/x.sock"}, command{Name: "reload", ConfigDir: cfg, Socket: "/x.sock"}},
		{"explain socket before command", []string{"-socket", "/x.sock", "explain", "a.com"}, command{Name: "explain", Arg: "a.com", Socket: "/x.sock"}},
		{"explain socket after arg", []string{"explain", "a.com", "-socket", "/x.sock"}, command{Name: "explain", Arg: "a.com", Socket: "/x.sock"}},
		{"up socket after arg", []string{"up", "de", "-socket", "/x.sock"}, command{Name: "up", Arg: "de", Socket: "/x.sock"}},
		{"down socket before", []string{"-socket", "/x.sock", "down", "de"}, command{Name: "down", Arg: "de", Socket: "/x.sock"}},

		// decision 11: -config only for reload, before or after.
		{"reload config after", []string{"reload", "-config", "/cfg"}, command{Name: "reload", ConfigDir: "/cfg", Socket: sock}},
		{"reload config before", []string{"-config", "/cfg", "reload"}, command{Name: "reload", ConfigDir: "/cfg", Socket: sock}},
		{"reload config equals", []string{"reload", "-config=/cfg"}, command{Name: "reload", ConfigDir: "/cfg", Socket: sock}},
		{"reload config and socket", []string{"-socket", "/x.sock", "reload", "-config", "/cfg"}, command{Name: "reload", ConfigDir: "/cfg", Socket: "/x.sock"}},

		// decision 11: -v only for daemon, before or after.
		{"daemon v after", []string{"daemon", "-v"}, command{Name: "daemon", Socket: sock, Verbose: true}},
		{"daemon v before", []string{"-v", "daemon"}, command{Name: "daemon", Socket: sock, Verbose: true}},
		{"daemon v and socket", []string{"daemon", "-v", "-socket", "/x.sock"}, command{Name: "daemon", Socket: "/x.sock", Verbose: true}},
		{"daemon socket and v", []string{"-socket", "/x.sock", "daemon", "-v"}, command{Name: "daemon", Socket: "/x.sock", Verbose: true}},
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
	def := paths{Socket: "/Users/u/brew/var/run/wgplex.sock", ConfigDir: "/Users/u/brew/etc/wgplex"}
	got, err := parseArgs([]string{"reload"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if got.Socket != def.Socket || got.ConfigDir != def.ConfigDir {
		t.Errorf("reload: got %+v, want socket %q and config %q", got, def.Socket, def.ConfigDir)
	}
	got, err = parseArgs([]string{"up", "de"}, def)
	if err != nil {
		t.Fatal(err)
	}
	if got.Socket != def.Socket || got.ConfigDir != "" {
		t.Errorf("up: got %+v, want socket %q and no config", got, def.Socket)
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
		// design 13 commands that are not in M1 (decision 11).
		{"pause", []string{"pause"}},
		{"resume", []string{"resume"}},
		{"check", []string{"check"}},

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

		// contract: other commands take no arguments.
		{"status arg", []string{"status", "de"}},
		{"routes arg", []string{"routes", "de"}},
		{"reload arg", []string{"reload", "/cfg"}},
		{"daemon arg", []string{"daemon", "x"}},
		{"version arg", []string{"version", "x"}},
		{"status empty arg", []string{"status", ""}},

		// decision 11: -config only for reload.
		{"status config", []string{"status", "-config", "/cfg"}},
		{"explain config", []string{"explain", "a.com", "-config", "/cfg"}},
		{"routes config", []string{"routes", "-config", "/cfg"}},
		{"up config", []string{"up", "de", "-config", "/cfg"}},
		{"down config before", []string{"-config", "/cfg", "down", "de"}},
		{"daemon config is M2", []string{"daemon", "-config", "/cfg"}},
		{"version config", []string{"version", "-config", "/cfg"}},

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
		{"daemon state is M2", []string{"daemon", "-state", "/s.json"}},
		{"daemon log is M2", []string{"daemon", "-log", "/l.log"}},

		// a flag without its value.
		{"socket without value", []string{"status", "-socket"}},
		{"config without value", []string{"reload", "-config"}},
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
