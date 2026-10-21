package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// paths are the default paths of wgplex, derived from the Homebrew prefix
// (design 3): the RPC socket, the config directory read by the daemon
// (design 10.2) and the state file (design 11).
type paths struct {
	Socket    string // <prefix>/var/run/wgplex.sock
	ConfigDir string // <prefix>/etc/wgplex
	State     string // <prefix>/var/wgplex/state.json
}

// brewPrefix returns HOMEBREW_PREFIX for the executable at exe (symlinks
// already resolved) built for goarch (design 3): everything before
// "/Cellar/" when exe contains it, otherwise /opt/homebrew on arm64 and
// /usr/local on amd64.
//
// The first "/Cellar/" counts; the prefix has no trailing "/". An unknown
// goarch gives /opt/homebrew.
func brewPrefix(exe, goarch string) string {
	if i := strings.Index(exe, "/Cellar/"); i >= 0 {
		return exe[:i]
	}
	return archPrefix(goarch)
}

// archPrefix is the default Homebrew prefix for goarch (design 3).
func archPrefix(goarch string) string {
	if goarch == "amd64" {
		return "/usr/local"
	}
	return "/opt/homebrew"
}

// pathsFor derives the default paths from prefix (design 3).
func pathsFor(prefix string) paths {
	return paths{
		Socket:    filepath.Join(prefix, "var", "run", "wgplex.sock"),
		ConfigDir: filepath.Join(prefix, "etc", "wgplex"),
		State:     filepath.Join(prefix, "var", "wgplex", "state.json"),
	}
}

// defaultPrefix is brewPrefix of os.Executable after EvalSymlinks and
// runtime.GOARCH; on an error of either — the goarch default.
func defaultPrefix() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return archPrefix(runtime.GOARCH)
	}
	return brewPrefix(exe, runtime.GOARCH)
}
