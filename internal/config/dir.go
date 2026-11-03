package config

import (
	"io/fs"
	"os/user"
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
func LoadDir(dir string) (cfg *Config, warnings []string, err error) {
	panic("not implemented")
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
// directory. Both messages name fi.Name.
func checkAccess(fi fileInfo, dirUID uint32, isDir, conf bool) (warn string, err error) {
	panic("not implemented")
}

// tccError wraps err of opening or reading path. When err is EPERM
// (errors.Is(err, fs.ErrPermission) and syscall.EPERM), the message names
// macOS TCC (privacy protection of ~/Documents, ~/Desktop, ~/Downloads,
// iCloud Drive, removable volumes) and advises moving the file into the
// config directory (design 5). Other errors keep path and err only.
func tccError(path string, err error) error {
	panic("not implemented")
}

// lookupGroup looks up control_group by name; replaced in tests.
var lookupGroup = user.LookupGroup
