package config

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Internal tests of LoadDir, checkAccess, tccError and control_group
// (go-dev); the design-driven ones are in dir_test.go and controlgroup_test.go.

const loadDirYAML = `
tunnels:
  - name: work
    conf: work.conf
    routes: rules
services:
  s:
    cidrs: [10.1.0.0/16]
rules:
  - services: [s]
    via: [work]
`

// stubGroups replaces lookupGroup for the test: names in known exist, others
// give user.UnknownGroupError. It returns the names looked up.
func stubGroups(t *testing.T, known ...string) *[]string {
	t.Helper()
	var asked []string
	old := lookupGroup
	lookupGroup = func(name string) (*user.Group, error) {
		asked = append(asked, name)
		for _, k := range known {
			if k == name {
				return &user.Group{Name: name, Gid: "80"}, nil
			}
		}
		return nil, user.UnknownGroupError(name)
	}
	t.Cleanup(func() { lookupGroup = old })
	return &asked
}

// writeDir creates a config directory (0700) with files at the given modes.
func writeDir(t *testing.T, files map[string]string, modes map[string]fs.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		mode := fs.FileMode(0o600)
		if m, ok := modes[name]; ok {
			mode = m
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadDirErrs(t *testing.T, dir string) (Errors, []string) {
	t.Helper()
	cfg, warns, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected an error")
	}
	if cfg != nil {
		t.Error("LoadDir: cfg must be nil on error")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("LoadDir: error is %T, want Errors", err)
	}
	return errs, warns
}

func hasMsg(errs Errors, parts ...string) bool {
	for _, e := range errs {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(e.Error(), p)
		}
		if ok {
			return true
		}
	}
	return false
}

func TestLoadDirInternalOK(t *testing.T) {
	stubGroups(t, "admin")
	conf := simpleConf(t)
	dir := writeDir(t, map[string]string{
		"wgplex.yaml": loadDirYAML,
		"work.conf":   conf,
		"other.conf":  "garbage", // not referenced: not read
		"old.yaml":    "x: [",    // ignored with a warning, not checked
		"notes.txt":   "",
	}, map[string]fs.FileMode{"other.conf": 0o666, "old.yaml": 0o666})
	cfg, warns, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if cfg.ControlGroup != "admin" || len(cfg.Tunnels) != 1 {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "old.yaml: ignored") {
		t.Errorf("warnings = %q, want only old.yaml ignored", warns)
	}
}

func TestLoadDirInternalMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	errs, _ := loadDirErrs(t, dir)
	if len(errs) != 1 || errs[0].Error() != "config directory "+dir+" not found" {
		t.Errorf("errs = %v", errs)
	}
}

func TestLoadDirInternalNoMain(t *testing.T) {
	errs, _ := loadDirErrs(t, writeDir(t, nil, nil))
	if len(errs) != 1 || errs[0].Error() != "wgplex.yaml not found" {
		t.Errorf("errs = %v", errs)
	}
}

func TestLoadDirInternalCollectsAll(t *testing.T) {
	asked := stubGroups(t)
	yaml := "control_group: nosuchgroup\n" + loadDirYAML + "  - services: [missing]\n"
	dir := writeDir(t, map[string]string{"wgplex.yaml": yaml, "work.conf": simpleConf(t)},
		map[string]fs.FileMode{"wgplex.yaml": 0o620, "work.conf": 0o666})
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	errs, _ := loadDirErrs(t, dir)
	for _, want := range [][]string{
		{dir, "writable by group or others"},
		{"wgplex.yaml", "writable by group or others"},
		{"work.conf", "writable by group or others"},
		{`unknown service "missing"`},
		{"control_group", "nosuchgroup"},
	} {
		if !hasMsg(errs, want...) {
			t.Errorf("no error with %q in:\n%v", want, errs)
		}
	}
	if len(*asked) != 1 || (*asked)[0] != "nosuchgroup" {
		t.Errorf("looked up %q", *asked)
	}
}

func TestLoadDirInternalConfWarn(t *testing.T) {
	stubGroups(t, "admin")
	dir := writeDir(t, map[string]string{"wgplex.yaml": loadDirYAML, "work.conf": simpleConf(t)},
		map[string]fs.FileMode{"wgplex.yaml": 0o644, "work.conf": 0o640})
	_, warns, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "work.conf: readable by group or others") {
		t.Errorf("warnings = %q", warns)
	}
}

func TestLoadDirInternalNotRead(t *testing.T) {
	stubGroups(t, "admin")
	t.Run("unreadable main", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads 0000 files")
		}
		dir := writeDir(t, map[string]string{"wgplex.yaml": loadDirYAML}, map[string]fs.FileMode{"wgplex.yaml": 0})
		errs, _ := loadDirErrs(t, dir)
		if len(errs) != 1 || !errors.Is(errs[0], fs.ErrPermission) || strings.Contains(errs[0].Error(), "TCC") {
			t.Errorf("errs = %v, want only the EACCES error without TCC", errs)
		}
	})
}

func TestLoadDirInternalSymlink(t *testing.T) {
	stubGroups(t, "admin")
	dir := writeDir(t, map[string]string{"wgplex.yaml": loadDirYAML}, nil)
	target := filepath.Join(t.TempDir(), "real.conf")
	if err := os.WriteFile(target, []byte(simpleConf(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "work.conf")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if err := os.Chmod(target, 0o606); err != nil {
		t.Fatal(err)
	}
	errs, _ := loadDirErrs(t, dir)
	if !hasMsg(errs, "work.conf", "writable by group or others") {
		t.Errorf("errs = %v", errs)
	}
}

func TestLoadDirInternalUnreadNotFound(t *testing.T) {
	stubGroups(t, "admin")
	yaml := loadDirYAML + `
  - services: [s]
    via: [gone]
`
	yaml = strings.Replace(yaml, "services:\n", `  - name: gone
    conf: gone.conf
    routes: rules
  - name: pipe
    conf: pipe.conf
    routes: rules
  - name: big
    conf: big.conf
    routes: rules
services:
`, 1)
	files := map[string]string{
		"wgplex.yaml": yaml,
		"big.conf":    strings.Repeat("#\n", MaxFileSize/2+1),
	}
	modes := map[string]fs.FileMode{}
	if os.Getuid() != 0 {
		files["work.conf"] = simpleConf(t)
		modes["work.conf"] = 0
	}
	dir := writeDir(t, files, modes)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	errs, _ := loadDirErrs(t, dir)
	for _, name := range []string{"work.conf", "pipe.conf", "big.conf"} {
		if hasMsg(errs, `conf file "`+name+`" not found`) {
			t.Errorf("%s exists but is reported not found:\n%v", name, errs)
		}
	}
	if !hasMsg(errs, `tunnel "gone"`, `conf file "gone.conf" not found`) {
		t.Errorf("missing gone.conf not reported:\n%v", errs)
	}
	if !hasMsg(errs, "pipe.conf", "not a regular file") || !hasMsg(errs, "big.conf", "larger than") {
		t.Errorf("own errors of unread files missing:\n%v", errs)
	}
	if os.Getuid() != 0 && !hasMsg(errs, "work.conf", "permission denied") {
		t.Errorf("EACCES of work.conf missing:\n%v", errs)
	}
}

func TestCheckGroupInternal(t *testing.T) {
	asked := stubGroups(t, "staff")
	if w, err := checkGroup("12345"); w != "" || err != nil || len(*asked) != 0 {
		t.Errorf("numeric gid: %q, %v, looked up %q", w, err, *asked)
	}
	if w, err := checkGroup("staff"); w != "" || err != nil {
		t.Errorf("staff: %q, %v", w, err)
	}
	lookupGroup = func(string) (*user.Group, error) { return nil, errors.New("ds down") }
	if w, err := checkGroup("staff"); err != nil || !strings.Contains(w, "ds down") {
		t.Errorf("lookup failure: %q, %v, want a warning", w, err)
	}
}

// A directory entry that is not a directory is an error (checkAccess with
// isDir); the other cases of checkAccess are in dir_test.go.
func TestCheckAccessInternalDirNotDir(t *testing.T) {
	fi := fileInfo{Name: "/d", Mode: 0o600, UID: 501, Size: 10}
	if _, err := checkAccess(fi, 501, true, false); err == nil || !strings.Contains(err.Error(), "not a directory") || !strings.Contains(err.Error(), "/d") {
		t.Errorf("err = %v, want not a directory", err)
	}
}
