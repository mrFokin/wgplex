package main

import (
	"fmt"
	"io"

	"github.com/mrFokin/wgplex/internal/config"
)

// checkMain is "wgplex check" (design 13): a local check of the config
// directory without the daemon and without root. It loads the directory with
// the same logic as the daemon (config.LoadDir, design 10.2) and adds the
// warnings the daemon adds on apply (10.2), then prints every problem and
// warning, not only the first one (10.1). Warnings do not make the check
// fail. It returns the exit code: 0 — the config is fine, 1 — the config has
// errors (2 — wrong arguments — is parseArgs). The socket is not touched.
func checkMain(w io.Writer, dir string) int {
	cfg, warnings, err := config.LoadDir(dir)
	if err == nil {
		warnings = append(warnings, blockedDNSWarnings(cfg)...)
		warnings = append(warnings, checkWarnings(cfg)...)
	}
	printCheck(w, warnings, err)
	if err != nil {
		return 1
	}
	return 0
}

// printCheck prints the report of "wgplex check" in the text format of the
// CLI: the config errors under the "config error:" header (as status and
// the RPC errors), one per line, then the warnings, and "config OK" when the
// config has no errors (warnings may be there).
func printCheck(w io.Writer, warnings []string, err error) {
	if err != nil {
		fmt.Fprintln(w, "config error:")
		for _, e := range errorList(err) {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
	for _, x := range warnings {
		fmt.Fprintf(w, "warning: %s\n", x)
	}
	if err == nil {
		fmt.Fprintln(w, "config OK")
	}
}
