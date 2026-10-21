package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// The daemon log (design 15): the daemon writes <prefix>/var/log/wgplex/
// wgplex.log itself and points fd 1 and 2 at it, so that writes to stdout,
// stderr and Go panics land in the log too. At logLimit bytes the file is
// rotated: the previous file becomes wgplex.log.1, the one before it
// wgplex.log.2, older history is removed, and fd 1 and 2 are pointed at the
// new file again — otherwise they would keep writing into the archive.
const (
	logLimit   = 5 << 20 // rotation threshold, design 15
	logBackups = 2       // the archives kept: .1 and .2, design 15
	logMode    = 0o640   // log file and archives, design 15
	logGroup   = "admin" // group of the log until control_group (M3), design 15
)

// logCounter is the rotation counter of logFile (design 15): the bytes in
// the current file. It holds no file operations, so the rotation decision is
// tested without a file system.
type logCounter struct {
	written int64
	limit   int64
}

// add accounts n written bytes.
func (c *logCounter) add(n int64) { c.written += n }

// reached reports whether the file has reached the rotation threshold.
func (c *logCounter) reached() bool { return c.written >= c.limit }

// set starts the counter at written bytes: the size of a file left by a
// previous run.
func (c *logCounter) set(written int64) { c.written = written }

// logArchive is the name of the i-th archive of path: wgplex.log.1, .2.
func logArchive(path string, i int) string {
	return path + "." + strconv.Itoa(i)
}

// logRotation describes one rotation of path (design 15): the oldest archive
// is removed, .1 becomes .2 and the log becomes .1. It returns the file to
// remove and the renames oldest first.
func logRotation(path string) (remove string, renames [][2]string) {
	return logArchive(path, logBackups), [][2]string{
		{logArchive(path, 1), logArchive(path, logBackups)},
		{path, logArchive(path, 1)},
	}
}

// logFile is the rotating log file of the daemon. Write, the rotation and
// the redirect to fd 1 and 2 are serialized by mu: slog handlers are called
// from several goroutines.
type logFile struct {
	path     string
	limit    int64
	redirect func(*os.File) error // points fd 1 and 2 at the file, nil in tests

	mu      sync.Mutex
	file    *os.File
	counter logCounter
}

// openLog opens (creating it if needed) the log at path with the counter set
// to its current size, so that a file left by a previous run still rotates
// at limit. redirect, when set, points fd 1 and 2 at the file.
func openLog(path string, limit int64, redirect func(*os.File) error) (*logFile, error) {
	l := &logFile{path: path, limit: limit, redirect: redirect}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.openLocked(); err != nil {
		return nil, err
	}
	return l, nil
}

// openDaemonLog prepares the log of the daemon (design 15): it opens the
// file and points fd 1 and 2 at it. The daemon creates no directories
// (design 4.1): a missing directory of path is an error for daemonMain to
// report to stderr before anything is written to the log.
func openDaemonLog(path string) (*logFile, error) {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("log directory %s does not exist; the daemon does not create it", dir)
	case err != nil:
		return nil, fmt.Errorf("log directory %s: %w", dir, err)
	case !info.IsDir():
		return nil, fmt.Errorf("log directory %s is not a directory", dir)
	}
	return openLog(path, logLimit, redirectStdio)
}

// openLocked opens (creating it if needed) the file at l.path, makes it a log
// file and points fd 1 and 2 at it. The counter follows the size of the file.
func (l *logFile) openLocked() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logMode)
	if err != nil {
		return err
	}
	if err := setLogAttrs(l.path); err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", l.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if l.redirect != nil {
		if err := l.redirect(f); err != nil {
			f.Close()
			return err
		}
	}
	l.file = f
	l.counter = logCounter{written: info.Size(), limit: l.limit}
	return nil
}

// Write appends p to the current file and rotates the file once it reaches
// the limit (design 15). The record that reaches the limit stays in the
// rotated file; a failed rotation is reported to stderr and retried by the
// next write.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		if err := l.openLocked(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.counter.add(int64(n))
	if l.counter.reached() {
		if rerr := l.rotateLocked(); rerr != nil {
			fmt.Fprintf(os.Stderr, "wgplex: log rotation: %v\n", rerr)
		}
	}
	return n, err
}

// rotateLocked rotates the current file and opens a new one (design 15): the
// fd 1 and 2 are pointed at the new file again. On an error the writer stays
// usable: the next write opens the file again.
func (l *logFile) rotateLocked() error {
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		if err != nil {
			return fmt.Errorf("close %s: %w", l.path, err)
		}
	}
	if err := rotateFiles(l.path); err != nil {
		return err
	}
	if err := l.openLocked(); err != nil {
		return err
	}
	// The archives keep the mode of the file they were, but a file left by
	// hand or by an older version may differ: the log files are 0640 too.
	for i := 1; i <= logBackups; i++ {
		if err := setLogAttrs(logArchive(l.path, i)); err != nil {
			return fmt.Errorf("%s: %w", logArchive(l.path, i), err)
		}
	}
	return nil
}

// Close closes the current file. fd 1 and 2 stay open: they are the standard
// streams of the process.
func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// rotateFiles applies one rotation of path on disk (design 15): the oldest
// archive is removed (missing is fine), .1 becomes .2, path becomes .1.
func rotateFiles(path string) error {
	remove, renames := logRotation(path)
	if err := os.Remove(remove); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", remove, err)
	}
	for _, r := range renames {
		if err := os.Rename(r[0], r[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("rename %s: %w", r[0], err)
		}
	}
	return nil
}

// setLogAttrs makes path a log file: 0640, owner root, group admin (design
// 15). The group is set only when the daemon runs as root: the file belongs
// to root anyway, and a test run under a user has no right to chown.
func setLogAttrs(path string) error {
	if err := os.Chmod(path, logMode); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return nil
	}
	g, err := user.LookupGroup(logGroup)
	if err != nil {
		return fmt.Errorf("group %s: %w", logGroup, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("group %s: %w", logGroup, err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	return nil
}

// redirectStdio points fd 1 and 2 at f (design 15): the standard streams and
// Go panics write to the current log file. After a rotation they are pointed
// at the new file again, otherwise they would write into the archive.
func redirectStdio(f *os.File) error {
	fd := int(f.Fd())
	for _, dst := range []int{1, 2} {
		if err := syscall.Dup2(fd, dst); err != nil {
			return fmt.Errorf("dup2 fd %d: %w", dst, err)
		}
	}
	return nil
}
