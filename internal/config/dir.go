package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// MaxFileSize is the largest config file read (design 5): a bigger one is a
// config error.
const MaxFileSize = 1 << 20

// LoadDir reads the config directory dir (design 5, 10.2) and runs Load on
// the result. Only wgplex.yaml and the .conf files its tunnels reference are
// read, following symlinks; other *.yaml files give an "ignored" warning (as
// in Load), anything else is not looked at.
//
// The owner of dir is taken from its stat on every call. dir itself and every
// file read (after resolving a symlink) must pass checkAccess.
//
// On failure err is Errors with every problem found: dir missing ("config
// directory … not found"), dir or a file failing checkAccess, a file that
// cannot be read (with the TCC hint of tccError on EPERM), Load's errors, an
// unknown control_group (lookupGroup gives user.UnknownGroupError; a numeric
// gid is not looked up). A file failing checkAccess on owner or mode is still
// passed to Load so that its own errors are collected too, and the config is
// rejected anyway; a file that is not read (not regular, over MaxFileSize, an
// open or read error) gives only its error. On error cfg is nil.
//
// When wgplex.yaml exists but cannot be read, Load is not run: it would only
// add a misleading "wgplex.yaml not found". A failed lookup of control_group
// other than user.UnknownGroupError is a warning, not an error: a transient
// Directory Services failure must not reject the config at boot.
func LoadDir(dir string) (cfg *Config, warnings []string, err error) {
	var errs []error

	st, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, Errors{fmt.Errorf("config directory %s not found", dir)}
	}
	if err != nil {
		return nil, nil, Errors{tccError(dir, err)}
	}
	dirUID := statUID(st)
	if _, err := checkAccess(infoOf(dir, st), dirUID, true, false); err != nil {
		errs = append(errs, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, Errors(append(errs, tccError(dir, err)))
	}
	present := map[string]bool{}
	unread := map[string]bool{} // present but not read: an error of its own is reported
	files := map[string][]byte{}
	for _, e := range entries {
		present[e.Name()] = true
		if e.Name() != mainFile && path.Ext(e.Name()) == ".yaml" {
			files[e.Name()] = nil // not read; only for Load's "ignored" warning
		}
	}

	read := func(name string, conf bool) bool {
		data, warn, ok, err := readFile(filepath.Join(dir, name), name, dirUID, conf)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			files[name] = data
		} else {
			delete(files, name) // e.g. a referenced *.yaml placeholder
			unread[name] = true
		}
		return ok
	}

	var raw *rawConfig
	mainRead := false
	if present[mainFile] {
		mainRead = read(mainFile, false)
		if mainRead {
			raw, _ = parseYAML(files[mainFile]) // a syntax error is reported by Load
		}
	}
	if raw != nil {
		seen := map[string]bool{}
		for _, t := range raw.Tunnels {
			// Names that are not plain entries of dir (missing, with a path,
			// "..") are left to build, which reports them.
			if !present[t.Conf] || t.Conf == mainFile || seen[t.Conf] {
				continue
			}
			seen[t.Conf] = true
			read(t.Conf, true)
		}
	}

	if !present[mainFile] || mainRead {
		var ws []string
		cfg, ws, err = Load(files)
		warnings = append(warnings, ws...)
		var le Errors
		if errors.As(err, &le) {
			errs = append(errs, suppressNotFound(le, unread)...)
		} else if err != nil {
			errs = append(errs, err)
		}
	}

	if raw != nil {
		w, err := checkGroup(controlGroup(raw))
		if w != "" {
			warnings = append(warnings, w)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return nil, warnings, Errors(errs)
	}
	return cfg, warnings, nil
}

// suppressNotFound drops Load's "conf file … not found" errors about files
// that unread lists, that is files present in the directory whose own error
// (permissions, TCC, not regular, too large) is already reported: saying
// "not found" about an existing file only misleads.
func suppressNotFound(errs Errors, unread map[string]bool) Errors {
	out := make(Errors, 0, len(errs))
next:
	for _, err := range errs {
		for name := range unread {
			if strings.HasSuffix(err.Error(), fmt.Sprintf("conf file %q not found", name)) {
				continue next
			}
		}
		out = append(out, err)
	}
	return out
}

// readFile reads path (shown as name) for LoadDir. ok is false when the file
// is not read: a stat, open or read error (via tccError), not a regular file,
// over MaxFileSize. A file failing checkAccess only on owner or mode is read
// (ok true) and err is set.
//
// The file is checked by Stat before opening (a FIFO would block the open)
// and again by Fstat of the opened file, whose result is the one reported, so
// a swap between the two is caught. O_NONBLOCK keeps open from hanging if a
// FIFO appears in between.
func readFile(path, name string, dirUID uint32, conf bool) (data []byte, warn string, ok bool, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", false, tccError(path, err)
	}
	if !readable(st) {
		warn, err = checkAccess(infoOf(name, st), dirUID, false, conf)
		return nil, warn, false, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", false, tccError(path, err)
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil {
		return nil, "", false, tccError(path, err)
	}
	warn, accessErr := checkAccess(infoOf(name, st), dirUID, false, conf)
	if !readable(st) {
		return nil, warn, false, accessErr
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, warn, false, tccError(path, err)
	}
	if len(data) > MaxFileSize {
		return nil, warn, false, fmt.Errorf("%s: larger than %d bytes", name, MaxFileSize)
	}
	return data, warn, true, accessErr
}

// readable reports whether st is a regular file small enough to read.
func readable(st fs.FileInfo) bool {
	return st.Mode().IsRegular() && st.Size() <= MaxFileSize
}

func infoOf(name string, st fs.FileInfo) fileInfo {
	return fileInfo{Name: name, Mode: st.Mode(), UID: statUID(st), Size: st.Size()}
}

func statUID(st fs.FileInfo) uint32 {
	return st.Sys().(*syscall.Stat_t).Uid
}

// checkGroup checks that control_group g exists (design 5): a numeric gid is
// accepted unchecked, user.UnknownGroupError is an error, any other lookup
// failure is a warning.
func checkGroup(g string) (warn string, err error) {
	if strings.Trim(g, "0123456789") == "" {
		return "", nil
	}
	_, err = lookupGroup(g)
	var unknown user.UnknownGroupError
	switch {
	case err == nil:
		return "", nil
	case errors.As(err, &unknown):
		return "", fmt.Errorf("control_group: group %q not found", g)
	default:
		return fmt.Sprintf("control_group: cannot look up group %q: %v", g, err), nil
	}
}

// fileInfo is what checkAccess needs of a file or of the directory (after
// resolving a symlink, os.Stat).
type fileInfo struct {
	Name string // base name of the file, or the directory path; used in messages
	Mode fs.FileMode
	UID  uint32
	Size int64
}

// checkAccess checks fi by design 5. err when the owner is neither root nor
// dirUID; when fi is writable by group or others (Mode&0o022 != 0); unless
// isDir, when fi is not a regular file (Mode.Type() != 0) or is larger than
// MaxFileSize. For isDir, fi must be a directory; size is not checked.
//
// warn (no error) for a .conf (conf true) readable by group or others
// (Mode&0o044 != 0), as wg-quick does; never for the main file or the
// directory, and not together with an error (the config is rejected anyway). Both messages name fi.Name.
func checkAccess(fi fileInfo, dirUID uint32, isDir, conf bool) (warn string, err error) {
	var problems []string
	if fi.UID != 0 && fi.UID != dirUID {
		problems = append(problems, fmt.Sprintf("owner uid %d is neither root nor the owner of the config directory (uid %d)", fi.UID, dirUID))
	}
	if fi.Mode&0o022 != 0 {
		problems = append(problems, fmt.Sprintf("writable by group or others (mode %04o)", fi.Mode.Perm()))
	}
	switch {
	case isDir:
		if !fi.Mode.IsDir() {
			problems = append(problems, "not a directory")
		}
	case fi.Mode.Type() != 0:
		problems = append(problems, "not a regular file")
	case fi.Size > MaxFileSize:
		problems = append(problems, fmt.Sprintf("larger than %d bytes", MaxFileSize))
	}
	if len(problems) > 0 {
		err = fmt.Errorf("%s: %s", fi.Name, strings.Join(problems, "; "))
	}
	if err == nil && conf && !isDir && fi.Mode&0o044 != 0 {
		warn = fmt.Sprintf("%s: readable by group or others (mode %04o), 0600 is recommended", fi.Name, fi.Mode.Perm())
	}
	return warn, err
}

// tccError wraps err of opening or reading path. When err is EPERM
// (errors.Is(err, fs.ErrPermission) and syscall.EPERM), the message names
// macOS TCC (privacy protection of ~/Documents, ~/Desktop, ~/Downloads,
// iCloud Drive, removable volumes) and advises moving the file into the
// config directory (design 5). Other errors keep path and err only.
func tccError(path string, err error) error {
	base := fmt.Errorf("%s: %w", path, err)
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Path == path {
		base = fmt.Errorf("%w", err) // the text already has the path
	}
	if errors.Is(err, fs.ErrPermission) && errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("%w (macOS TCC privacy protection denies the daemon access to ~/Documents, ~/Desktop, ~/Downloads, iCloud Drive and removable volumes; move the file into the config directory)", base)
	}
	return base
}

// lookupGroup looks up control_group by name; replaced in tests.
var lookupGroup = user.LookupGroup
