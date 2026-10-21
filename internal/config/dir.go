package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The daemon reads the config directory itself (design 10.2), at startup and
// by config.reload: only the main file and the .conf files the tunnels
// reference (design 5 — in Wirefork the client sent every *.conf). Every
// file read is a regular file of at most maxFileSize, owned by root or the
// owner of the directory and not writable by group or other — otherwise a
// config error (design 5: a stranger could redirect the traffic). A .conf
// readable by group or other is a warning only (10.1, as wg-quick). Symlinks
// are allowed: the checks follow them. A read denied with EPERM names TCC
// (design 5, 18): a launchd daemon without Full Disk Access cannot read
// ~/Documents, ~/Desktop, ~/Downloads, iCloud Drive or removable volumes.

// maxFileSize is the limit of one config file read from the directory
// (design 5).
const maxFileSize = 1 << 20

// FileStat is what the file checks of design 5 need of one file: the facts
// of one stat (of the file itself, a symlink resolved) and the owner of the
// config directory, taken by stat at every check.
type FileStat struct {
	Name   string      // base name: wgplex.yaml or a .conf reference
	DirUID uint32      // owner of the config directory
	UID    uint32      // owner of the file itself
	Mode   fs.FileMode // type and permission bits
	Size   int64
	Conf   bool // a .conf referenced by a tunnel (false: the main file)
}

// checkFile reports what one file means for the config (design 5): err a
// config error (the config is not applied, design 10.2), warn an advisory
// (the config is applied); read says whether the file may be read at all.
// A file may carry one problem, the checks in the order of the design: kind
// and size (the file is not read: a FIFO or a device on the place of a
// referenced .conf would hang the daemon, design 5), then owner, write
// bits, and — only for a clean .conf — the readability warning.
func checkFile(f FileStat) (warn string, err error, read bool) {
	if !f.Mode.IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", f.Name), false
	}
	if f.Size > maxFileSize {
		return "", fmt.Errorf("%s: %d bytes, a config file is at most %d", f.Name, f.Size, maxFileSize), false
	}
	if f.UID != 0 && f.UID != f.DirUID {
		return "", fmt.Errorf("%s: owned by uid %d, want root or the config directory owner (uid %d)", f.Name, f.UID, f.DirUID), true
	}
	if f.Mode&(0o020|0o002) != 0 {
		return "", fmt.Errorf("%s: writable by group or other", f.Name), true
	}
	if f.Conf && f.Mode&(0o040|0o004) != 0 {
		return fmt.Sprintf("%s: readable by group or other", f.Name), nil, true
	}
	return "", nil, true
}

// checkDir reports the problem of the config directory itself (design 5).
// Its owner root or the directory owner is the directory owner, so only the
// write bits are a threat there: another user could put files in.
func checkDir(mode fs.FileMode) error {
	if mode&(0o020|0o002) != 0 {
		return errors.New("config directory: writable by group or other")
	}
	return nil
}

// tccError passes err as it is, unless it is EPERM of a read (design 5, 18):
// then the text names TCC and advises moving the file into the config
// directory. No path of the file in the hint: the TCC places are listed.
func tccError(name string, err error) error {
	if !errors.Is(err, syscall.EPERM) {
		return err
	}
	return fmt.Errorf("%s: permission denied; a daemon without Full Disk Access cannot read files in ~/Documents, ~/Desktop, ~/Downloads, iCloud Drive or on removable volumes (macOS TCC), move it into the config directory", name)
}

// statOwner is the uid of the owner of fi (syscall.Stat_t): 0 when not
// available.
func statOwner(fi fs.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return 0
}

// readFile stats path (a symlink resolved by the stat itself), checks it
// against dirUID (design 5, with Conf factoring the warning) and reads it.
// It returns the content, the warning of a readable .conf, and the problem
// (nil when fine). Not readable (not regular, over the limit) — nil and the
// error before any read (checkFile). A failed read (missing aside) is nil
// and the error; a rights problem on a read file still yields the content —
// the caller collects the error and goes on (every problem is collected,
// design 10.1). A missing file is nil without an error: the caller reports
// "not found" itself (here for the main file, build for a referenced
// .conf). Errors are prefixed with the file name.
func readFile(path, name string, dirUID uint32, conf bool) ([]byte, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", tccError(name, err)
	}
	warn, cerr, read := checkFile(FileStat{Name: name, DirUID: dirUID, UID: statOwner(fi), Mode: fi.Mode(), Size: fi.Size(), Conf: conf})
	if !read {
		return nil, "", cerr
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", tccError(name, err)
	}
	if cerr != nil {
		return data, "", cerr
	}
	return data, warn, nil
}

// LoadDir reads the config directory dir and loads the config from it
// (design 10.2): the daemon reads it itself, at startup and by config.reload.
// Only the main file and the .conf files the tunnels reference are read
// (design 5; LoadDir follows symlinks); other *.yaml in the directory are
// ignored with a warning (design 10.1). The rights of the directory and of
// every file read are checked (design 5): a problem there is a config
// error — with any error in err the config is nil and must not be applied
// (10.2); a .conf readable by group or other is a warning only. Every
// problem is collected, not only the first one.
//
// A directory that does not exist is a config error of its own («no
// directory», design 10.2). A missing or unreadable main file, or a YAML
// syntax error, is reported alone: nothing else can be checked without it.
func LoadDir(dir string) (cfg *Config, warnings []string, err error) {
	fi, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, warnings, Errors{fmt.Errorf("config directory %s does not exist", dir)}
		}
		return nil, warnings, Errors{fmt.Errorf("config directory %s: %v", dir, err)}
	}
	dirUID := statOwner(fi)
	var errs []error
	if err := checkDir(fi.Mode()); err != nil {
		errs = append(errs, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, warnings, Errors{fmt.Errorf("config directory %s: %v", dir, err)}
	}
	for _, e := range entries {
		if name := e.Name(); name != mainFile && filepath.Ext(name) == ".yaml" {
			warnings = append(warnings, fmt.Sprintf("%s: ignored, the main file is %s", name, mainFile))
		}
	}

	data, _, err := readFile(filepath.Join(dir, mainFile), mainFile, dirUID, false)
	if err != nil {
		errs = append(errs, err)
		if data == nil {
			return nil, warnings, Errors(errs)
		}
	}
	if data == nil {
		return nil, warnings, Errors{errors.New(mainFile + " not found")}
	}
	raw, err := parseYAML(data)
	if err != nil {
		return nil, warnings, Errors{fmt.Errorf("%s: %w", mainFile, err)}
	}

	// Only the .conf files the tunnels reference (design 5); a missing one
	// is build's own "conf file not found". One present but unreadable is
	// nil: its read error above, not a second "not found" of build. A
	// rights problem on a read file does not stop parsing (warnings).
	files := map[string][]byte{}
	for _, name := range confNames(raw) {
		data, warn, err := readFile(filepath.Join(dir, name), name, dirUID, true)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		switch {
		case err != nil:
			errs = append(errs, err)
			if data != nil {
				files[name] = data
			} else {
				files[name] = nil
			}
		case data == nil:
		default:
			files[name] = data
		}
	}
	cfg, ws, bes := build(raw, files)
	warnings = append(warnings, ws...)
	errs = append(errs, bes...)
	if len(errs) > 0 {
		return nil, warnings, Errors(errs)
	}
	return cfg, warnings, nil
}

// confNames lists the .conf files of raw in tunnel order without
// duplicates; a name with a path (conf must be a bare file name, design
// 10.1) is not read: build reports it itself.
func confNames(raw *rawConfig) []string {
	seen := map[string]bool{}
	var res []string
	for _, t := range raw.Tunnels {
		if t.Conf == "" || strings.Contains(t.Conf, "/") || seen[t.Conf] {
			continue
		}
		seen[t.Conf] = true
		res = append(res, t.Conf)
	}
	return res
}
