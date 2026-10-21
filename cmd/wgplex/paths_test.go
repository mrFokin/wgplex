package main

import "testing"

// Tests follow design 3 (the prefix is detected at start: everything before
// "/Cellar/" of the resolved executable path, otherwise by architecture) and
// the contract of plan m1-port («Открытые места контракта»), not the
// implementation.

func TestBrewPrefix(t *testing.T) {
	tests := []struct {
		name   string
		exe    string
		goarch string
		want   string
	}{
		// design 3, rule 1: brew install, standard prefixes.
		{"cellar arm64 standard", "/opt/homebrew/Cellar/wgplex/0.1.0/bin/wgplex", "arm64", "/opt/homebrew"},
		{"cellar amd64 standard", "/usr/local/Cellar/wgplex/0.1.0/bin/wgplex", "amd64", "/usr/local"},
		// design 3, rule 1: the Cellar wins over the architecture.
		{"cellar /usr/local on arm64", "/usr/local/Cellar/wgplex/0.1.0/bin/wgplex", "arm64", "/usr/local"},
		{"cellar /opt/homebrew on amd64", "/opt/homebrew/Cellar/wgplex/0.1.0/bin/wgplex", "amd64", "/opt/homebrew"},
		// design 3, rule 1: a non-standard prefix.
		{"cellar custom prefix", "/Users/u/brew/Cellar/wgplex/0.1.0/bin/wgplex", "arm64", "/Users/u/brew"},
		{"cellar custom prefix amd64", "/Users/u/brew/Cellar/wgplex/0.1.0/bin/wgplex", "amd64", "/Users/u/brew"},
		{"cellar custom prefix unknown arch", "/Users/u/brew/Cellar/wgplex/0.1.0/bin/wgplex", "riscv64", "/Users/u/brew"},
		{"cellar prefix with spaces", "/Volumes/My Disk/brew/Cellar/wgplex/0.1.0/bin/wgplex", "arm64", "/Volumes/My Disk/brew"},
		// contract: the first "/Cellar/" counts.
		{"first cellar counts", "/a/Cellar/b/Cellar/wgplex/0.1.0/bin/wgplex", "arm64", "/a"},
		{"first cellar counts custom", "/Users/u/brew/Cellar/x/Cellar/wgplex/bin/wgplex", "amd64", "/Users/u/brew"},
		// design 3, rule 1: only the "/Cellar/" component, not a lookalike.
		{"MyCellar is not a cellar", "/Users/u/MyCellar/wgplex/bin/wgplex", "amd64", "/usr/local"},
		{"Cellarx is not a cellar", "/Users/u/Cellarx/wgplex/bin/wgplex", "amd64", "/usr/local"},
		{"lowercase cellar is not a cellar", "/Users/u/cellar/wgplex/bin/wgplex", "amd64", "/usr/local"},
		// design 3, rule 2: a development build outside the Cellar.
		{"dev build arm64", "/Users/u/src/wgplex/build/wgplex", "arm64", "/opt/homebrew"},
		{"dev build amd64", "/Users/u/src/wgplex/build/wgplex", "amd64", "/usr/local"},
		{"go run binary arm64", "/private/var/folders/x/T/go-build1/b001/exe/wgplex", "arm64", "/opt/homebrew"},
		{"go run binary amd64", "/private/var/folders/x/T/go-build1/b001/exe/wgplex", "amd64", "/usr/local"},
		// contract: an unknown architecture gives /opt/homebrew.
		{"unknown arch", "/Users/u/src/wgplex/build/wgplex", "riscv64", "/opt/homebrew"},
		{"empty arch", "/Users/u/src/wgplex/build/wgplex", "", "/opt/homebrew"},
		{"x86_64 is not a goarch", "/Users/u/src/wgplex/build/wgplex", "x86_64", "/opt/homebrew"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := brewPrefix(tt.exe, tt.goarch)
			if got != tt.want {
				t.Errorf("brewPrefix(%q, %q) = %q, want %q", tt.exe, tt.goarch, got, tt.want)
			}
			// contract: the prefix has no trailing "/".
			if len(got) > 1 && got[len(got)-1] == '/' {
				t.Errorf("brewPrefix(%q, %q) = %q has a trailing slash", tt.exe, tt.goarch, got)
			}
		})
	}
}

func TestPathsFor(t *testing.T) {
	// design 3: socket <prefix>/var/run/wgplex.sock, config
	// <prefix>/etc/wgplex, state <prefix>/var/wgplex/state.json (design 11).
	tests := []struct {
		prefix string
		want   paths
	}{
		{"/opt/homebrew", paths{
			Socket:    "/opt/homebrew/var/run/wgplex.sock",
			ConfigDir: "/opt/homebrew/etc/wgplex",
			State:     "/opt/homebrew/var/wgplex/state.json",
			Log:       "/opt/homebrew/var/log/wgplex/wgplex.log",
		}},
		{"/usr/local", paths{
			Socket:    "/usr/local/var/run/wgplex.sock",
			ConfigDir: "/usr/local/etc/wgplex",
			State:     "/usr/local/var/wgplex/state.json",
			Log:       "/usr/local/var/log/wgplex/wgplex.log",
		}},
		{"/Users/u/brew", paths{
			Socket:    "/Users/u/brew/var/run/wgplex.sock",
			ConfigDir: "/Users/u/brew/etc/wgplex",
			State:     "/Users/u/brew/var/wgplex/state.json",
			Log:       "/Users/u/brew/var/log/wgplex/wgplex.log",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			if got := pathsFor(tt.prefix); got != tt.want {
				t.Errorf("pathsFor(%q) = %+v, want %+v", tt.prefix, got, tt.want)
			}
		})
	}
}

// design 3: brewPrefix and pathsFor together give the default paths.
func TestPathsForBrewPrefix(t *testing.T) {
	got := pathsFor(brewPrefix("/Users/u/brew/Cellar/wgplex/0.1.0/bin/wgplex", "arm64"))
	want := paths{
		Socket:    "/Users/u/brew/var/run/wgplex.sock",
		ConfigDir: "/Users/u/brew/etc/wgplex",
		State:     "/Users/u/brew/var/wgplex/state.json",
		Log:       "/Users/u/brew/var/log/wgplex/wgplex.log",
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
