package main

// paths are the default paths of wgplex, derived from the Homebrew prefix
// (design 3). On M1 only these two are used.
type paths struct {
	Socket    string // <prefix>/var/run/wgplex.sock
	ConfigDir string // <prefix>/etc/wgplex
}

// brewPrefix returns HOMEBREW_PREFIX for the executable at exe (symlinks
// already resolved) built for goarch (design 3): everything before
// "/Cellar/" when exe contains it, otherwise /opt/homebrew on arm64 and
// /usr/local on amd64.
//
// The first "/Cellar/" counts; the prefix has no trailing "/". An unknown
// goarch gives /opt/homebrew.
func brewPrefix(exe, goarch string) string {
	panic("not implemented")
}

// pathsFor derives the default paths from prefix (design 3).
func pathsFor(prefix string) paths {
	panic("not implemented")
}

// defaultPrefix is brewPrefix of os.Executable after EvalSymlinks and
// runtime.GOARCH; on an error of either — the goarch default.
func defaultPrefix() string {
	panic("not implemented")
}
