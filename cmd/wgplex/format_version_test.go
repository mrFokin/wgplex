package main

import (
	"strings"
	"testing"
)

// Tests follow design 13 and plan M3 decision 11: when the version of the
// daemon differs from the version of the CLI, status and version warn on
// stderr with the command that restarts the service.

const restartCommand = "sudo brew services restart --sudo-service-user=root wgplex"

func TestVersionWarningSame(t *testing.T) {
	for _, v := range []string{"0.3.0", "dev", "v1.2.3-rc1"} {
		if got := versionWarning(v, v); got != "" {
			t.Errorf("versionWarning(%q, %q) = %q, want empty", v, v, got)
		}
	}
}

func TestVersionWarningDiffers(t *testing.T) {
	cases := []struct{ cli, daemon string }{
		{"0.3.0", "0.2.0"},
		{"0.2.0", "0.3.0"},
		{"dev", "0.3.0"},
		{"0.3.0", "0.3.0-dirty"},
	}
	for _, c := range cases {
		got := versionWarning(c.cli, c.daemon)
		if !strings.HasPrefix(got, "warning:") {
			t.Errorf("versionWarning(%q, %q) = %q, want a \"warning: ...\" line", c.cli, c.daemon, got)
		}
		for _, want := range []string{c.cli, c.daemon, restartCommand} {
			if !strings.Contains(got, want) {
				t.Errorf("versionWarning(%q, %q) = %q, want it to contain %q", c.cli, c.daemon, got, want)
			}
		}
		if strings.Count(strings.TrimRight(got, "\n"), "\n") != 0 {
			t.Errorf("versionWarning(%q, %q) is not a single line: %q", c.cli, c.daemon, got)
		}
	}
}
