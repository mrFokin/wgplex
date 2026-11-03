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

// Implementation tests of LoadDir, checkAccess, tccError and control_group
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

func TestLoadDirImplOK(t *testing.T) {
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

func TestLoadDirImplMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nope")
	errs, _ := loadDirErrs(t, dir)
	if len(errs) != 1 || errs[0].Error() != "config directory "+dir+" not found" {
		t.Errorf("errs = %v", errs)
	}
}

func TestLoadDirImplNoMain(t *testing.T) {
	errs, _ := loadDirErrs(t, writeDir(t, nil, nil))
	if len(errs) != 1 || errs[0].Error() != "wgplex.yaml not found" {
		t.Errorf("errs = %v", errs)
	}
}

func TestLoadDirImplCollectsAll(t *testing.T) {
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

func TestLoadDirImplConfWarn(t *testing.T) {
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

func TestLoadDirImplNotRead(t *testing.T) {
	stubGroups(t, "admin")
	t.Run("fifo", func(t *testing.T) {
		dir := writeDir(t, map[string]string{"wgplex.yaml": loadDirYAML}, nil)
		if err := syscall.Mkfifo(filepath.Join(dir, "work.conf"), 0o600); err != nil {
			t.Fatal(err)
		}
		errs, _ := loadDirErrs(t, dir)
		if !hasMsg(errs, "work.conf", "not a regular file") {
			t.Errorf("errs = %v", errs)
		}
	})
	t.Run("big", func(t *testing.T) {
		dir := writeDir(t, map[string]string{
			"wgplex.yaml": loadDirYAML,
			"work.conf":   strings.Repeat("#\n", MaxFileSize/2+1),
		}, nil)
		errs, _ := loadDirErrs(t, dir)
		if !hasMsg(errs, "work.conf", "larger than") {
			t.Errorf("errs = %v", errs)
		}
	})
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

func TestLoadDirImplSymlink(t *testing.T) {
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

func TestCheckGroupImpl(t *testing.T) {
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

func TestCheckAccessImpl(t *testing.T) {
	reg := func(mode fs.FileMode, uid uint32) fileInfo {
		return fileInfo{Name: "a.conf", Mode: mode, UID: uid, Size: 10}
	}
	for _, tc := range []struct {
		name  string
		fi    fileInfo
		isDir bool
		err   string
		warn  bool
	}{
		{name: "owner", fi: reg(0o600, 501)},
		{name: "root", fi: reg(0o600, 0)},
		{name: "stranger", fi: reg(0o600, 777), err: "owner uid 777"},
		{name: "group read", fi: reg(0o640, 501), warn: true},
		{name: "other write", fi: reg(0o606, 501), err: "writable", warn: true},
		{name: "device", fi: reg(fs.ModeDevice|0o600, 501), err: "not a regular file"},
		{name: "big", fi: fileInfo{Name: "a.conf", Mode: 0o600, UID: 501, Size: MaxFileSize + 1}, err: "larger than"},
		{name: "dir", fi: fileInfo{Name: "/d", Mode: fs.ModeDir | 0o755, UID: 501, Size: 1 << 30}, isDir: true},
		{name: "dir not dir", fi: reg(0o600, 501), isDir: true, err: "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := checkAccess(tc.fi, 501, tc.isDir, true)
			if (warn != "") != tc.warn {
				t.Errorf("warn = %q", warn)
			}
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err) || !strings.Contains(err.Error(), tc.fi.Name)) {
				t.Errorf("err = %v, want containing %q", err, tc.err)
			}
		})
	}
	if warn, _ := checkAccess(reg(0o644, 501), 501, false, false); warn != "" {
		t.Errorf("main file warned: %q", warn)
	}
}

func TestControlGroupDefaultImpl(t *testing.T) {
	cfg, _ := mustLoad(t, filesOf("ipv6_filter: false\n", nil))
	if cfg.ControlGroup != "admin" {
		t.Errorf("default = %q", cfg.ControlGroup)
	}
	cfg, _ = mustLoad(t, filesOf("control_group: staff\n", nil))
	if cfg.ControlGroup != "staff" {
		t.Errorf("explicit = %q", cfg.ControlGroup)
	}
}

func TestTCCErrorImpl(t *testing.T) {
	p := "/Users/x/Documents/work.conf"
	eperm := tccError(p, &fs.PathError{Op: "open", Path: p, Err: syscall.EPERM})
	if !strings.Contains(eperm.Error(), "TCC") || !strings.Contains(eperm.Error(), "config directory") ||
		strings.Count(eperm.Error(), p) != 1 || !errors.Is(eperm, syscall.EPERM) {
		t.Errorf("EPERM: %v", eperm)
	}
	eacces := tccError(p, &fs.PathError{Op: "open", Path: p, Err: syscall.EACCES})
	if strings.Contains(eacces.Error(), "TCC") || !strings.Contains(eacces.Error(), p) {
		t.Errorf("EACCES: %v", eacces)
	}
	if got := tccError(p, errors.New("boom")).Error(); got != p+": boom" {
		t.Errorf("plain: %q", got)
	}
}
