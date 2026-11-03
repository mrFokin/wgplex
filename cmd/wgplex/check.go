package main

import "io"

// checkMain is "wgplex check [-config dir]" (design 13): it validates the
// config directory cmd.ConfigDir locally with config.LoadDir, as the daemon
// would, without the daemon and without root. Warnings include those of
// blockedDNSWarnings and checkWarnings for a valid config. It writes
// formatCheck's text to stdout and returns its exit code: 0 config OK
// (warnings do not matter), 1 config errors. stderr is for failures outside
// the config check.
func checkMain(cmd command, stdout, stderr io.Writer) int {
	panic("not implemented")
}

// formatCheck renders the result of a check as text and its exit code
// (design 13). err nil: "config OK", code 0. Otherwise one line
// "config error: …" per error (each element of config.Errors; any other error
// is one line), code 1. Warnings follow in both cases, one line
// "warning: …" each, after the errors. Every line ends with "\n".
func formatCheck(warnings []string, err error) (out string, code int) {
	panic("not implemented")
}
