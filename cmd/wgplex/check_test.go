package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 13 ("wgplex check"): "config OK" and code 0 for a valid
// config; one "config error: ..." line per error and code 1 otherwise;
// "warning: ..." lines in both cases, after the errors; every line ends
// with "\n".

func TestFormatCheckOK(t *testing.T) {
	// design 13: nil error is "config OK", code 0
	out, code := formatCheck(nil, nil)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if out != "config OK\n" {
		t.Errorf("out = %q, want %q", out, "config OK\n")
	}
}

func TestFormatCheckOKWithWarnings(t *testing.T) {
	// design 13: warnings do not change the code; they follow "config OK"
	out, code := formatCheck([]string{"w one", "w two"}, nil)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	lines := strings.SplitAfter(out, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	want := []string{"config OK\n", "warning: w one\n", "warning: w two\n"}
	if strings.Join(lines, "") != strings.Join(want, "") {
		t.Errorf("out = %q, want %q", out, strings.Join(want, ""))
	}
}

func TestFormatCheckErrors(t *testing.T) {
	// design 13: one "config error: ..." line per element of config.Errors
	err := config.Errors{errors.New("first problem"), errors.New("second problem")}
	out, code := formatCheck(nil, err)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	want := "config error: first problem\nconfig error: second problem\n"
	if out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
	if strings.Contains(out, "config OK") {
		t.Error("out has config OK despite errors")
	}
}

func TestFormatCheckErrorsThenWarnings(t *testing.T) {
	// design 13: warnings come after the errors, in both cases
	err := config.Errors{errors.New("e1"), errors.New("e2")}
	out, code := formatCheck([]string{"w1", "w2"}, err)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	want := "config error: e1\nconfig error: e2\nwarning: w1\nwarning: w2\n"
	if out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
}

func TestFormatCheckPlainError(t *testing.T) {
	// design 13: any other error is one line
	out, code := formatCheck(nil, errors.New("something broke"))
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if out != "config error: something broke\n" {
		t.Errorf("out = %q", out)
	}
}

func TestFormatCheckEveryLineEndsWithNewline(t *testing.T) {
	// design 13: each line ends with "\n"
	cases := []struct {
		warns []string
		err   error
	}{
		{nil, nil},
		{[]string{"w"}, nil},
		{nil, config.Errors{errors.New("e")}},
		{[]string{"w"}, config.Errors{errors.New("e"), errors.New("f")}},
	}
	for _, c := range cases {
		out, _ := formatCheck(c.warns, c.err)
		if !strings.HasSuffix(out, "\n") || strings.Contains(out, "\n\n") {
			t.Errorf("out = %q: want lines ending with a single newline", out)
		}
	}
}

// --- checkMain -------------------------------------------------------------

// checkRun runs checkMain on dir.
func checkRun(t *testing.T, dir string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	code = checkMain(command{Name: "check", ConfigDir: dir}, &out, &errb)
	return out.String(), errb.String(), code
}

func TestCheckMainNoConfig(t *testing.T) {
	// design 13: a directory without wgplex.yaml is code 1 and the error is
	// on stdout
	out, _, code := checkRun(t, t.TempDir())
	if code != 1 {
		t.Errorf("code = %d, want 1; stdout: %q", code, out)
	}
	if !strings.Contains(out, "config error: ") || !strings.Contains(out, "wgplex.yaml") {
		t.Errorf("stdout = %q, want a config error naming wgplex.yaml", out)
	}
}

func TestCheckMainMissingDir(t *testing.T) {
	// design 5, 10.2: a missing directory is a config error "config directory
	// ... not found"
	out, _, code := checkRun(t, filepath.Join(t.TempDir(), "nodir"))
	if code != 1 {
		t.Errorf("code = %d, want 1; stdout: %q", code, out)
	}
	if !strings.Contains(out, "config directory") || !strings.Contains(out, "not found") {
		t.Errorf("stdout = %q, want the missing directory error", out)
	}
}

func TestCheckMainValid(t *testing.T) {
	// design 13: a valid (here empty) config is "config OK", code 0.
	// A numeric control_group needs no group lookup (design 5).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte("control_group: \"0\"\ntunnels: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := checkRun(t, dir)
	if code != 0 {
		t.Errorf("code = %d, want 0; stdout: %q", code, out)
	}
	if !strings.Contains(out, "config OK") {
		t.Errorf("stdout = %q, want config OK", out)
	}
}

func TestCheckMainBrokenYAML(t *testing.T) {
	// design 10.1: an unknown key is an error; check reports it with code 1
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte("bogus_key: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := checkRun(t, dir)
	if code != 1 {
		t.Errorf("code = %d, want 1; stdout: %q", code, out)
	}
	if !strings.HasPrefix(out, "config error: ") {
		t.Errorf("stdout = %q, want a config error line", out)
	}
}
