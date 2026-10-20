package rpc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// probeTimeout bounds the check whether an existing socket file answers.
const probeTimeout = time.Second

// Listen listens on the unix socket path: a socket that answers (another
// daemon) is an error; a stale file is removed; the socket is chmod 0666,
// access is checked per connection.
//
// A file at path that is not a socket is an error and is left alone. The
// listener removes the file when closed (net.UnixListener).
func Listen(path string) (net.Listener, error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case fi.Mode().Type() != fs.ModeSocket:
		return nil, fmt.Errorf("%s exists and is not a socket", path)
	default:
		if c, err := net.DialTimeout("unix", path, probeTimeout); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s answers: wgplex daemon is already running", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// connect(2) needs write permission on the socket file; the uid check
	// limits access (decision 8).
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// peerUID returns the uid of the peer of c (LOCAL_PEERCRED); c is a *net.UnixConn.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer uid: %T is not a unix connection", c)
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peer uid: %w", err)
	}
	var (
		cred *unix.Xucred
		gerr error
	)
	if err := rc.Control(func(fd uintptr) {
		cred, gerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("peer uid: %w", err)
	}
	if gerr != nil {
		return 0, fmt.Errorf("peer uid: %w", gerr)
	}
	return cred.Uid, nil
}
