package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// logRotateSize is the size at which the log is rotated (design 15).
const logRotateSize = 5 << 20

// logFileMode is the mode of the log file and its archives (design 15).
const logFileMode = 0o640

// rotatingFile is the daemon log <prefix>/var/log/wgplex/wgplex.log
// (design 15). It counts the bytes written under a mutex; at logRotateSize
// the file becomes path.1 (an old .1 becomes .2, an old .2 is removed), a new
// file is opened and fd 1 and 2 are pointed at it again (Dup2Std), so that Go
// panics land in the current file. The file and its archives are 0640, owner
// root (logOwner), group gid.
//
// A negative gid means "no group set": openLog leaves the group of a file it
// did not create, and files it creates get the group of their directory until
// SetGroup names one.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64 // bytes in f
	gid  int
	std  []int // fds Dup2Std attached to f; repeated after a rotation
	// reopen: a rotation moved the file away (or found it gone) but opening
	// a new one failed; f is the old file and every Write tries to open
	// path again.
	reopen bool
}

// logOpenFile opens the log file; replaced in tests to make the open after a
// rotation fail.
var logOpenFile = os.OpenFile

// logOwner is the owner given to the log files: root (design 15) when the
// process runs as root, as the daemon does; otherwise -1, the owner left as
// is, since only root may give a file to another user (tests, a daemon run
// by hand).
func logOwner() int {
	if os.Geteuid() == 0 {
		return 0
	}
	return -1
}

// openLog opens path for appending (created 0640 with group gid); the byte
// count starts from the size of an existing file. The directory is not
// created (design 4.1): a missing one is an error.
func openLog(path string, gid int) (*rotatingFile, error) {
	l := &rotatingFile{path: path, gid: gid}
	f, size, err := l.open()
	if err != nil {
		return nil, err
	}
	l.f, l.size = f, size
	return l, nil
}

// Write appends p and rotates when the file reaches logRotateSize
// (design 15): .1 → .2 (an existing .2 removed, a missing one is not an
// error), the file → .1, a new file opened and Dup2Std repeated. When the
// new file could not be opened, the next Write tries again.
func (l *rotatingFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.f.Write(p)
	l.size += int64(n)
	if err != nil {
		return n, err
	}
	if l.reopen {
		return n, l.openNew()
	}
	if l.size < logRotateSize {
		return n, nil
	}
	return n, l.rotate()
}

// SetGroup changes the group of the file and its existing archives to gid
// (control_group of an applied config, design 15) and remembers gid for
// files created later. A negative gid means "no group set": nothing is
// changed.
func (l *rotatingFile) SetGroup(gid int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gid = gid
	if gid < 0 {
		return nil
	}
	if err := l.f.Chown(logOwner(), gid); err != nil {
		return fmt.Errorf("log %s: %w", l.path, err)
	}
	for _, name := range []string{l.path + ".1", l.path + ".2"} {
		if err := os.Chown(name, logOwner(), gid); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("log %s: %w", name, err)
		}
	}
	return nil
}

// Dup2Std points fd 1 and 2 at the current file (design 15). Write repeats it
// after a rotation — only once Dup2Std has been called: a rotatingFile that
// was never attached to fd 1 and 2 leaves them alone.
func (l *rotatingFile) Dup2Std() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.std = []int{1, 2}
	return l.dup2()
}

// dup2 makes every fd in l.std a copy of the current file (the darwin
// syscall.Dup2 is missing on arm64, hence golang.org/x/sys/unix). The file
// itself stays open.
func (l *rotatingFile) dup2() error {
	for _, fd := range l.std {
		if err := unix.Dup2(int(l.f.Fd()), fd); err != nil {
			return fmt.Errorf("dup2 %s to fd %d: %w", l.path, fd, err)
		}
	}
	return nil
}

// rotate moves the file to .1, shifts the archives and opens a new file
// (openNew). A file already gone from path (removed by hand) has nothing to
// archive: the archives stay, a new file is opened. When moving the file
// fails, it stays the current one and the next attempt is after another
// logRotateSize rather than on every write.
func (l *rotatingFile) rotate() error {
	if _, err := os.Lstat(l.path); err == nil {
		if err := l.shift(); err != nil {
			l.size = 0
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		l.size = 0
		return fmt.Errorf("log rotate: %w", err)
	}
	l.reopen = true
	return l.openNew()
}

// shift removes .2, moves .1 to .2 and the file to .1; a missing .2 or .1,
// or the file itself gone meanwhile, is not an error.
func (l *rotatingFile) shift() error {
	if err := os.Remove(l.path + ".2"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("log rotate: %w", err)
	}
	for _, mv := range [][2]string{{l.path + ".1", l.path + ".2"}, {l.path, l.path + ".1"}} {
		if err := os.Rename(mv[0], mv[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("log rotate: %w", err)
		}
	}
	return nil
}

// openNew opens a new file at path in place of the current one and repeats
// dup2. On error the current file stays and reopen stays set: the next Write
// tries again.
func (l *rotatingFile) openNew() error {
	f, size, err := l.open()
	if err != nil {
		return err
	}
	old := l.f
	l.f, l.size, l.reopen = f, size, false
	err = l.dup2()
	old.Close()
	return err
}

// open opens the log file for appending, makes it 0640 and gives it the owner
// logOwner and the group gid (when set), and returns its current size.
func (l *rotatingFile) open() (*os.File, int64, error) {
	f, err := logOpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, 0, fmt.Errorf("log %s: %w", l.path, err)
	}
	if err := f.Chmod(logFileMode); err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("log %s: %w", l.path, err)
	}
	if uid := logOwner(); uid >= 0 || l.gid >= 0 {
		if err := f.Chown(uid, l.gid); err != nil {
			f.Close()
			return nil, 0, fmt.Errorf("log %s: %w", l.path, err)
		}
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("log %s: %w", l.path, err)
	}
	return f, fi.Size(), nil
}
