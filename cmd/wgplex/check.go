package main

import (
	"errors"
	"io"
	"strings"

	"github.com/mrFokin/wgplex/internal/config"
)

// checkMain is "wgplex check [-config dir]" (design 13): it validates the
// config directory cmd.ConfigDir locally with config.LoadDir, as the daemon
// would, without the daemon and without root. Warnings include those of
// blockedDNSWarnings and checkWarnings for a valid config. It writes
// formatCheck's text to stdout and returns its exit code: 0 config OK
// (warnings do not matter), 1 config errors. stderr is for failures outside
// the config check.
func checkMain(cmd command, stdout, stderr io.Writer) int {
	cfg, warnings, err := config.LoadDir(cmd.ConfigDir)
	if err == nil {
		warnings = append(warnings, blockedDNSWarnings(cfg)...)
		warnings = append(warnings, checkWarnings(cfg)...)
	}
	out, code := formatCheck(warnings, err)
	if _, werr := io.WriteString(stdout, out); werr != nil {
		io.WriteString(stderr, "wgplex: "+werr.Error()+"\n")
		return 1
	}
	return code
}

// formatCheck renders the result of a check as text and its exit code
// (design 13). err nil: "config OK", code 0. Otherwise one line
// "config error: …" per error (each element of config.Errors; any other error
// is one line), code 1. Warnings follow in both cases, one line
// "warning: …" each, after the errors. Every line ends with "\n".
func formatCheck(warnings []string, err error) (out string, code int) {
	var b strings.Builder
	var errs config.Errors
	switch {
	case err == nil:
		b.WriteString("config OK\n")
	case errors.As(err, &errs):
		for _, e := range errs {
			b.WriteString("config error: " + e.Error() + "\n")
		}
		code = 1
	default:
		b.WriteString("config error: " + err.Error() + "\n")
		code = 1
	}
	for _, w := range warnings {
		b.WriteString("warning: " + w + "\n")
	}
	return b.String(), code
}
