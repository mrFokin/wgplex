package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Tests follow design 5, 10.1-10.2, not the implementation: right
// classification of one file, the directory itself, the TCC hint of a read
// denied with EPERM, and LoadDir over real directories (keys generated per
// test, rights set by chmod — no root is needed).

// --- checkFile ---------------------------------------------------------------

func TestCheckFile(t *testing.T) {
	dirUID := uint32(501)
	tests := []struct {
		name string
		f    FileStat
		warn string
		err  string // substring of the error; "" when none
	}{
		{"root-owned main file", FileStat{DirUID: dirUID, UID: 0, Mode: 0o600, Size: 10}, "", ""},
		{"directory owner", FileStat{Name: "work.conf", DirUID: dirUID, UID: dirUID, Mode: 0o600, Size: 10, Conf: true}, "", ""},
		{"not regular", FileStat{Mode: fs.ModeDir | 0o700}, "", "not a regular file"},
		{"too big", FileStat{Mode: 0o600, Size: maxFileSize + 1}, "", "a config file is at most"},
		{"foreign owner", FileStat{Name: "eval.conf", DirUID: dirUID, UID: 502, Mode: 0o600, Conf: true}, "", "owned by uid 502"},
		{"group writable", FileStat{DirUID: dirUID, Mode: 0o660}, "", "writable by group or other"},
		{"other writable", FileStat{DirUID: dirUID, Mode: 0o606}, "", "writable by group or other"},
		// design 5: only a .conf readable by group or other is a warning.
		{"conf readable by group", FileStat{Name: "work.conf", DirUID: dirUID, Mode: 0o640, Conf: true}, "readable by group or other", ""},
		{"conf readable by other", FileStat{Name: "work.conf", DirUID: dirUID, Mode: 0o644, Conf: true}, "readable by group or other", ""},
		{"main file readable by other", FileStat{DirUID: dirUID, Mode: 0o644}, "", ""},
		// An error wins over the warning of the same file.
		{"writable wins over readable", FileStat{Name: "work.conf", DirUID: dirUID, Mode: 0o770, Conf: true}, "", "writable"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			warn, err, read := checkFile(c.f)
			if (err == nil) != (c.err == "") {
				t.Errorf("checkFile: err %v, want %q", err, c.err)
			}
			if err != nil && !strings.Contains(err.Error(), c.err) {
				t.Errorf("checkFile: err %q, want %q", err, c.err)
			}
			if !strings.Contains(warn, c.warn) {
				t.Errorf("checkFile: warn %q, want %q", warn, c.warn)
			}
			if c.warn != "" && err != nil {
				t.Errorf("both warn %q and err %v", warn, err)
			}
			// Not read on a hard kind or size error: a FIFO or a huge file is
			// dangerous to read (design 5).
			if wantRead := c.err == "" || !strings.Contains(c.err, "regular") && !strings.Contains(c.err, "at most"); read != wantRead {
				t.Errorf("checkFile: read %v, want %v", read, wantRead)
			}
		})
	}
}

// --- checkDir ----------------------------------------------------------------

func TestCheckDir(t *testing.T) {
	if err := checkDir(0o700); err != nil {
		t.Errorf("0700 dir: %v", err)
	}
	if err := checkDir(0o750); err != nil {
		t.Errorf("0750 dir: %v", err)
	}
	if err := checkDir(0o770); err == nil {
		t.Error("0770 dir: no error, want group-writable")
	}
}

// --- tccError ----------------------------------------------------------------

func TestTCCError(t *testing.T) {
	err := tccError("work.conf", syscall.EPERM)
	if !strings.Contains(err.Error(), "TCC") || !strings.Contains(err.Error(), "config directory") {
		t.Errorf("EPERM text %q: want TCC named and the config directory advice", err)
	}
	if !strings.HasPrefix(err.Error(), "work.conf:") {
		t.Errorf("EPERM text %q: want the file name", err)
	}
	plain := errors.New("work.conf: no such file")
	if got := tccError("work.conf", plain); got != plain {
		t.Errorf("non-EPERM: %v, want the error as it is", got)
	}
}

// --- LoadDir -------------------------------------------------------------------

func TestLoadDirBasic(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(baseYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err) // ignored with a warning (design 10.1)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("skip me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink to a file elsewhere (design 3: symlinks are allowed).
	if err := os.WriteFile(filepath.Join(other, "de-real.conf"), []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "de-real.conf"), filepath.Join(dir, "de.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nl.conf"), []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, warns, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if cfg == nil || len(cfg.Tunnels) != 2 {
		t.Fatalf("LoadDir: cfg = %+v, want two tunnels", cfg)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "old.yaml") {
		t.Errorf("warnings = %q, want the ignored old.yaml", warns)
	}
}

func TestLoadDirNoDir(t *testing.T) {
	_, _, err := LoadDir(filepath.Join(t.TempDir(), "nosuch"))
	var errs Errors
	if !errors.As(err, &errs) || len(errs) != 1 || !strings.Contains(errs[0].Error(), "does not exist") {
		t.Fatalf("missing dir: err %v, want the no-directory config error", err)
	}
}

func TestLoadDirNoMain(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "work.conf"), []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadDir(dir)
	var errs Errors
	if !errors.As(err, &errs) || len(errs) != 1 || !strings.Contains(errs[0].Error(), "not found") {
		t.Fatalf("no wgplex.yaml: err %v, want not found", err)
	}
}

// Design 5, 10.2: a file with a rights problem is a config error; every
// problem is collected, not only the first one (here: the yaml file is
// group-writable AND references a missing .conf), and nothing is applied.
func TestLoadDirCollectsErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(baseYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "wgplex.yaml"), 0o660); err != nil { // group-writable
		t.Fatal(err)
	}
	_, _, err := LoadDir(dir)
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("err is %T, want Errors", err)
	}
	have := errsJoin(errs)
	for _, want := range []string{"writable by group or other", `conf file "nl.conf" not found`, `conf file "de.conf" not found`} {
		if !strings.Contains(have, want) {
			t.Errorf("errors %q miss %q", have, want)
		}
	}
}

// A .conf readable by group is a warning, the config is applied (design 5).
func TestLoadDirWarnsReadableConf(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(baseYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nl.conf"), []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "de.conf"), []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "de.conf"), 0o640); err != nil { // readable by group only
		t.Fatal(err)
	}
	cfg, warns, err := LoadDir(dir)
	if err != nil || cfg == nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "de.conf") ||
		!strings.Contains(warns[0], "readable by group or other") {
		t.Errorf("warnings = %q, want the readable de.conf", warns)
	}
}

// A .conf present but unreadable is a config error of its own, and build
// does not repeat "conf file not found" for it (de.conf missing excepted).
func TestLoadDirUnreadableConf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads the unreadable .conf too")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(baseYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nl.conf"), []byte(simpleConf(t)), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "de.conf"), []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadDir(dir)
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("err is %T, want Errors", err)
	}
	have := errsJoin(errs)
	if strings.Contains(have, `conf file "nl.conf" not found`) {
		t.Errorf("errors %q repeat not found for the unreadable nl.conf", have)
	}
	if !strings.Contains(have, "nl.conf: permission denied") {
		t.Errorf("errors %q, want the read error of nl.conf", have)
	}
}

// A .conf too big is a config error and is not parsed on top (design 5).
func TestLoadDirTooBigConf(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(baseYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("# pad\n", maxFileSize/6+100)
	for _, name := range []string{"nl.conf", "de.conf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(big), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := LoadDir(dir)
	var errs Errors
	if !errors.As(err, &errs) || len(errs) != 2 || !strings.Contains(errs[0].Error(), "at most") {
		t.Fatalf("too big: err %v, want one size error per file", err)
	}
}

func errsJoin(errs Errors) string {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}
