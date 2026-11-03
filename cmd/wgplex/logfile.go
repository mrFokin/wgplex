package main

import (
	"os"
	"sync"
)

// logRotateSize is the size at which the log is rotated (design 15).
const logRotateSize = 5 << 20

// rotatingFile is the daemon log <prefix>/var/log/wgplex/wgplex.log
// (design 15). It counts the bytes written under a mutex; at logRotateSize
// the file becomes path.1 (an old .1 becomes .2, an old .2 is removed), a new
// file is opened and fd 1 and 2 are pointed at it again (Dup2Std), so that Go
// panics land in the current file. The file and its archives are 0640, owner
// root, group gid.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64 // bytes in f
	gid  int
}

// openLog opens path for appending (created 0640 with group gid); the byte
// count starts from the size of an existing file. The directory is not
// created (design 4.1): a missing one is an error.
func openLog(path string, gid int) (*rotatingFile, error) {
	panic("not implemented")
}

// Write appends p and rotates when the file reaches logRotateSize
// (design 15): .1 → .2 (an existing .2 removed, a missing one is not an
// error), the file → .1, a new file opened and Dup2Std repeated.
func (l *rotatingFile) Write(p []byte) (int, error) {
	panic("not implemented")
}

// SetGroup changes the group of the file and its existing archives to gid
// (control_group of an applied config, design 15) and remembers gid for
// files created later.
func (l *rotatingFile) SetGroup(gid int) error {
	panic("not implemented")
}

// Dup2Std points fd 1 and 2 at the current file (design 15). Write repeats it
// after a rotation.
func (l *rotatingFile) Dup2Std() error {
	panic("not implemented")
}
