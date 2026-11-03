package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/rpc"
)

// checkMain is "wgplex check [-config dir] [-json]" (design 13): it validates
// the config directory cmd.ConfigDir locally with config.LoadDir, as the
// daemon would, without the daemon and without root. Warnings include those
// of blockedDNSWarnings and checkWarnings for a valid config. It writes
// formatCheck's text (with -json, checkJSON's rpc.ConfigErrorData) to stdout
// and returns its exit code: 0 config OK (warnings do not matter), 1 config
// errors. stderr is for failures outside the config check.
func checkMain(cmd command, stdout, stderr io.Writer) int {
	cfg, warnings, err := config.LoadDir(cmd.ConfigDir)
	if err == nil {
		warnings = append(warnings, blockedDNSWarnings(cfg)...)
		warnings = append(warnings, checkWarnings(cfg)...)
	} else {
		err = unreadableHint(err, os.Getuid())
	}
	out, code := formatCheck(warnings, err)
	if cmd.JSON {
		out = checkJSON(warnings, err)
	}
	if _, werr := io.WriteString(stdout, out); werr != nil {
		io.WriteString(stderr, "wgplex: "+werr.Error()+"\n")
		return 1
	}
	return code
}

// unreadableHint annotates the errors of a read denied to uid (the user
// running check) with why it may be denied: check reads the config as that
// user, the daemon as root (design 13, 18). Only EACCES-like errors get it:
// EPERM already names TCC. The type of err is kept (config.Errors or one
// error), so formatCheck still prints one line per error.
func unreadableHint(err error, uid int) error {
	hint := fmt.Sprintf(" (cannot read as uid %d; the daemon reads it as root)", uid)
	var errs config.Errors
	if !errors.As(err, &errs) {
		return hintOne(err, hint)
	}
	out := make(config.Errors, len(errs))
	for i, e := range errs {
		out[i] = hintOne(e, hint)
	}
	return out
}

// hintOne returns err with hint appended when reading was denied to a user
// other than root (EACCES, not the EPERM of TCC); otherwise err as is.
func hintOne(err error, hint string) error {
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EPERM) {
		return err
	}
	return errors.New(err.Error() + hint)
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

// checkJSON renders the result of a check as the JSON of rpc.ConfigErrorData,
// the data of config.reload's CodeConfigInvalid (design 13: the structures of
// the API): one element of Errors per error as in formatCheck, empty arrays
// rather than null, a trailing "\n".
func checkJSON(warnings []string, err error) string {
	data := rpc.ConfigErrorData{Errors: []string{}, Warnings: append([]string{}, warnings...)}
	var errs config.Errors
	switch {
	case err == nil:
	case errors.As(err, &errs):
		for _, e := range errs {
			data.Errors = append(data.Errors, e.Error())
		}
	default:
		data.Errors = append(data.Errors, err.Error())
	}
	b, _ := json.MarshalIndent(data, "", "  ") // string slices always marshal
	return string(b) + "\n"
}
