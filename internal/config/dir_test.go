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

// Tests follow design 5, 10.1, not the implementation: LoadDir reads
// wgplex.yaml and .conf files referenced by tunnels, checks access
// (checkAccess), looks up control_group. Symlinks are followed; errors are
// collected, not stopped at the first; TCC message on EPERM.

// --- checkAccess (design 5) ------------------------------------------------

func TestCheckAccessOwner(t *testing.T) {
	// design 5: owner must be root or dirUID
	tests := []struct {
		name   string
		uid    uint32
		dirUID uint32
		wantOK bool
	}{
		{"root owner", 0, 501, true},
		{"dir owner", 501, 501, true},
		{"other user", 502, 501, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fileInfo{
				Name: "test.conf",
				Mode: 0o600,
				UID:  tt.uid,
				Size: 100,
			}
			warn, err := checkAccess(fi, tt.dirUID, false, false)
			if tt.wantOK {
				if err != nil {
					t.Errorf("checkAccess: unexpected error: %v", err)
				}
				if warn != "" {
					t.Errorf("checkAccess: unexpected warning: %s", warn)
				}
			} else {
				if err == nil {
					t.Error("checkAccess: expected error for wrong owner, got nil")
				}
				if !strings.Contains(err.Error(), "test.conf") {
					t.Errorf("checkAccess: error must mention file name, got: %v", err)
				}
			}
		})
	}
}

func TestCheckAccessWritable(t *testing.T) {
	// design 5: Mode&0o022 != 0 (writable by group or others) is an error
	tests := []struct {
		name   string
		mode   fs.FileMode
		wantOK bool
	}{
		{"0600", 0o600, true},
		{"0640", 0o640, true},
		{"0644", 0o644, true},
		{"0666", 0o666, false},
		{"0620", 0o620, false},
		{"0602", 0o602, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fileInfo{
				Name: "file.conf",
				Mode: tt.mode,
				UID:  0,
				Size: 100,
			}
			_, err := checkAccess(fi, 0, false, false)
			if tt.wantOK {
				if err != nil {
					t.Errorf("checkAccess(%s): unexpected error: %v", tt.name, err)
				}
			} else {
				if err == nil {
					t.Errorf("checkAccess(%s): expected error for writable mode, got nil", tt.name)
				}
			}
		})
	}
}

func TestCheckAccessConfReadable(t *testing.T) {
	// design 5: .conf readable by group or others (Mode&0o044 != 0) is a
	// warning, not an error; other files and the directory never warn
	tests := []struct {
		name       string
		mode       fs.FileMode
		isDir      bool
		conf       bool
		wantWarn   bool
		wantErrNil bool
	}{
		{".conf 0640", 0o640, false, true, true, true},
		{".conf 0644", 0o644, false, true, true, true},
		{".conf 0666", 0o666, false, true, false, false}, // writable → error
		{".conf 0600", 0o600, false, true, false, true},
		{".conf 0604", 0o604, false, true, true, true},
		{"wgplex.yaml 0640", 0o640, false, false, false, true},
		{"dir 0755", 0o755 | fs.ModeDir, true, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fileInfo{
				Name: "test.conf",
				Mode: tt.mode,
				UID:  0,
				Size: 100,
			}
			warn, err := checkAccess(fi, 0, tt.isDir, tt.conf)
			if tt.wantErrNil && err != nil {
				t.Errorf("checkAccess: unexpected error: %v", err)
			}
			if !tt.wantErrNil && err == nil {
				t.Error("checkAccess: expected error, got nil")
			}
			if tt.wantWarn {
				if warn == "" {
					t.Error("checkAccess: expected warning for readable .conf, got none")
				}
			} else {
				if warn != "" {
					t.Errorf("checkAccess: unexpected warning: %s", warn)
				}
			}
		})
	}
}

func TestCheckAccessRegularFile(t *testing.T) {
	// design 5: only regular files (Mode.Type() == 0) are read, unless isDir
	tests := []struct {
		name   string
		mode   fs.FileMode
		isDir  bool
		wantOK bool
	}{
		{"regular file", 0o600, false, true},
		{"directory", 0o700 | fs.ModeDir, true, true},
		{"symlink checked after resolution", 0o600 | fs.ModeSymlink, false, false},
		{"FIFO", 0o600 | fs.ModeNamedPipe, false, false},
		{"device", 0o600 | fs.ModeDevice, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fileInfo{
				Name: "test.conf",
				Mode: tt.mode,
				UID:  0,
				Size: 100,
			}
			_, err := checkAccess(fi, 0, tt.isDir, false)
			if tt.wantOK {
				if err != nil {
					t.Errorf("checkAccess: unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("checkAccess(%s): expected error, got nil", tt.name)
				}
			}
		})
	}
}

func TestCheckAccessFileSize(t *testing.T) {
	// design 5: file size > MaxFileSize is an error; isDir doesn't check size
	tests := []struct {
		name   string
		size   int64
		isDir  bool
		wantOK bool
	}{
		{"small file", 1000, false, true},
		{"1 MiB exactly", MaxFileSize, false, true},
		{"over 1 MiB", MaxFileSize + 1, false, false},
		{"large directory", MaxFileSize + 1000, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := fileInfo{
				Name: "test.conf",
				Mode: 0o600,
				UID:  0,
				Size: tt.size,
			}
			if tt.isDir {
				fi.Mode = 0o700 | fs.ModeDir
			}
			_, err := checkAccess(fi, 0, tt.isDir, false)
			if tt.wantOK {
				if err != nil {
					t.Errorf("checkAccess: unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("checkAccess: expected error for oversized file, got nil")
				}
			}
		})
	}
}

// --- tccError (design 5) ---------------------------------------------------

func TestTCCError(t *testing.T) {
	// design 5: EPERM wraps with TCC hint; other errors unchanged
	tests := []struct {
		name      string
		err       error
		wantInMsg string
	}{
		{"EPERM", &fs.PathError{Op: "open", Path: "/tmp/test.conf", Err: syscall.EPERM}, "TCC"},
		{"EACCES", &fs.PathError{Op: "open", Path: "/tmp/test.conf", Err: syscall.EACCES}, ""},
		{"ENOENT", &fs.PathError{Op: "open", Path: "/tmp/test.conf", Err: syscall.ENOENT}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tccError("/tmp/test.conf", tt.err)
			msg := got.Error()
			if tt.wantInMsg != "" {
				if !strings.Contains(msg, tt.wantInMsg) {
					t.Errorf("tccError: want %q in message, got: %s", tt.wantInMsg, msg)
				}
				if !strings.Contains(msg, "/tmp/test.conf") {
					t.Errorf("tccError: want path in message, got: %s", msg)
				}
			} else {
				if strings.Contains(msg, "TCC") {
					t.Errorf("tccError: TCC hint on non-EPERM error: %s", msg)
				}
			}
		})
	}
}

// --- LoadDir integration (design 5, 10.1) ----------------------------------

func TestLoadDirMissing(t *testing.T) {
	// design 5: missing directory is "config directory … not found"
	dir := filepath.Join(t.TempDir(), "nonexistent")
	_, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for missing directory, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "config directory") || !strings.Contains(msg, "not found") {
		t.Errorf("LoadDir: want 'config directory … not found', got: %s", msg)
	}
}

func TestLoadDirGroupWritable(t *testing.T) {
	// design 5: directory writable by group is an error, and other errors are collected too
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Skip("cannot set directory mode:", err)
	}
	yamlPath := filepath.Join(dir, "wgplex.yaml")
	if err := os.WriteFile(yamlPath, []byte("unknown_key: true\ntunnels: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for group-writable directory, got nil")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("LoadDir: error is not Errors: %T", err)
	}
	// design 5: all errors collected
	if len(errs) < 2 {
		t.Errorf("LoadDir: want at least 2 errors (directory mode + YAML), got %d: %v", len(errs), err)
	}
}

func TestLoadDirConfPermissions(t *testing.T) {
	// design 5: .conf 0640 is a warning and the config stays usable, 0666 is
	// an error, 0600 gives no warning
	yaml := `tunnels:
  - name: t1
    conf: t1.conf
    routes: rules
`
	conf := makeConf(t, "Address = 10.1.0.2/32", "Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.0.0/16").text

	tests := []struct {
		name     string
		mode     fs.FileMode
		wantWarn bool
		wantErr  bool
	}{
		{"0640", 0o640, true, false},
		{"0666", 0o666, false, true},
		{"0600", 0o600, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			confPath := filepath.Join(dir, "t1.conf")
			if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(confPath, tt.mode); err != nil {
				t.Fatal(err)
			}

			cfg, warns, err := LoadDir(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LoadDir: expected error for %s, got nil", tt.name)
				}
				if cfg != nil {
					t.Error("LoadDir: cfg must be nil on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadDir: unexpected error for %s: %v", tt.name, err)
			}
			if cfg == nil || len(cfg.Tunnels) != 1 {
				t.Fatalf("LoadDir: config not usable: %+v", cfg)
			}
			if tt.wantWarn && len(warns) == 0 {
				t.Errorf("LoadDir: expected warning for %s, got none", tt.name)
			}
			if !tt.wantWarn && len(warns) > 0 {
				t.Errorf("LoadDir: unexpected warnings for %s: %v", tt.name, warns)
			}
		})
	}
}

func TestLoadDirOwner(t *testing.T) {
	// design 5: file owner must be root or dirUID
	if os.Getuid() != 0 {
		t.Skip("need root to test ownership checks")
	}
	dir := t.TempDir()
	dirStat, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	dirUID := dirStat.Sys().(*syscall.Stat_t).Uid

	yaml := `tunnels:
  - name: t1
    conf: t1.conf
    routes: rules
`
	conf := makeConf(t, "Address = 10.1.0.2/32", "Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.0.0/16").text

	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "t1.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	// wrong owner (neither root nor dirUID)
	wrongUID := uint32(502)
	if dirUID == 502 {
		wrongUID = 503
	}
	if err := os.Chown(confPath, int(wrongUID), -1); err != nil {
		t.Skip("cannot chown:", err)
	}

	_, _, err = LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for wrong file owner, got nil")
	}
}

func TestLoadDirSymlink(t *testing.T) {
	// design 5: symlinks are followed, target is checked
	dir := t.TempDir()
	yaml := `tunnels:
  - name: t1
    conf: link.conf
    routes: rules
`
	conf := makeConf(t, "Address = 10.1.0.2/32", "Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.0.0/16").text

	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(dir, "real.conf")
	linkPath := filepath.Join(dir, "link.conf")
	if err := os.WriteFile(realPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	cfg, _, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: unexpected error with symlink: %v", err)
	}
	if len(cfg.Tunnels) != 1 {
		t.Errorf("LoadDir: want 1 tunnel, got %d", len(cfg.Tunnels))
	}
}

func TestLoadDirSymlinkTargetChecked(t *testing.T) {
	// design 5: rights are checked on the target of a symlink
	dir := t.TempDir()
	other := t.TempDir()
	yaml := `tunnels:
  - name: t1
    conf: link.conf
    routes: rules
`
	conf := makeConf(t, "Address = 10.1.0.2/32", "Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.0.0/16").text
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(other, "real.conf")
	if err := os.WriteFile(target, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.conf")); err != nil {
		t.Skip("cannot create symlink:", err)
	}
	if _, _, err := LoadDir(dir); err == nil {
		t.Fatal("LoadDir: expected error for symlink to a world-writable file, got nil")
	}
}

func TestLoadDirFIFO(t *testing.T) {
	// design 5: FIFO instead of .conf is an error (non-regular file)
	dir := t.TempDir()
	yaml := `tunnels:
  - name: t1
    conf: fifo.conf
    routes: rules
`
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "fifo.conf")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skip("cannot create FIFO:", err)
	}

	_, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for FIFO, got nil")
	}
}

func TestLoadDirOversized(t *testing.T) {
	// design 5: file > MaxFileSize is an error
	dir := t.TempDir()
	yaml := `tunnels:
  - name: t1
    conf: big.conf
    routes: rules
`
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	bigPath := filepath.Join(dir, "big.conf")
	// create a file larger than MaxFileSize
	data := make([]byte, MaxFileSize+1)
	if err := os.WriteFile(bigPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for oversized file, got nil")
	}
}

func TestLoadDirCollectsErrors(t *testing.T) {
	// design 5, 10.1: every problem is collected, not only the first
	dir := t.TempDir()
	yaml := `control_group: nosuchgroup123456
tunnels:
  - name: t1
    conf: loose.conf
    routes: rules
  - name: t2
    conf: fifo.conf
    routes: rules
`
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := makeConf(t, "Address = 10.1.0.2/32", "Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.0.0/16").text
	loose := filepath.Join(dir, "loose.conf")
	if err := os.WriteFile(loose, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.conf"), 0o600); err != nil {
		t.Skip("cannot create FIFO:", err)
	}

	_, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected errors, got nil")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("LoadDir: error is not Errors: %T", err)
	}
	// loose.conf mode, fifo.conf not regular, unknown control_group
	if len(errs) < 3 {
		t.Errorf("LoadDir: want at least 3 errors, got %d: %v", len(errs), errs)
	}
}
