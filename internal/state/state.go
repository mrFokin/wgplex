// Package state keeps <prefix>/var/wgplex/state.json: what the daemon
// remembers across restarts (design 11).
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// fileMode is the mode of state.json (design 11).
const fileMode = 0o640

// State is the content of state.json (design 11): the tunnel toggles, the
// pause and the block snapshot.
type State struct {
	// Tunnels are the explicit toggles by tunnel name (tunnel.enable,
	// tunnel.disable, tunnel.disableAll). A tunnel without an entry follows
	// its autostart (design 10.2). A pause does not change them.
	Tunnels map[string]bool `json:"tunnels,omitempty"`
	// Paused is daemon.pause (design 12): no tunnel is brought up, the
	// toggles are kept.
	Paused bool `json:"paused,omitempty"`
	// Block is the block snapshot of the last successful apply (design 9.1):
	// what a fallback: block rule keeps closed while the daemon has no config
	// (a broken config at start). None: no snapshot, or a config without
	// block rules.
	Block *Block `json:"block,omitempty"`
}

// Block is the block snapshot (design 9.1): the CIDRs and the domains of the
// fallback: block rules of the last successfully applied config, without keys.
type Block struct {
	CIDRs   []string `json:"cidrs,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// Load reads the state file at path. No file: empty State, nil error.
// Unreadable or broken (an empty file included): empty State and the error;
// the caller logs a warning and goes on by autostart (design 11). Unknown
// fields and "tunnels": null are fine.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	if len(data) == 0 {
		return State{}, fmt.Errorf("state %s: empty file", path)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("state %s: %w", path, err)
	}
	return s, nil
}

// Save writes s to path atomically: a temporary file in the directory of path,
// mode 0640, group gid given to the temporary file before the rename, then
// rename (design 11, 15). gid < 0: the group is not set. On error no
// temporary file is left. The directory is not created.
func (s State) Save(path string, gid int) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("state %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("state %s: %w", path, err)
	}
	if err := writeTemp(tmp, data, path, gid); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("state %s: %w", path, err)
	}
	return nil
}

// writeTemp fills tmp with data, gives it group gid (gid < 0: not set, owner
// root), syncs and closes it; on any error the temporary file is removed.
func writeTemp(tmp *os.File, data []byte, path string, gid int) error {
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("state %s: %w", path, err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		return fail(err)
	}
	if gid >= 0 {
		if err := tmp.Chown(-1, gid); err != nil {
			return fail(err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("state %s: %w", path, err)
	}
	return nil
}

// Prune drops the toggles of tunnels not in names (the tunnels of the applied
// config, design 11) and reports whether it dropped any.
func (s *State) Prune(names []string) bool {
	keep := make(map[string]bool, len(names))
	for _, n := range names {
		keep[n] = true
	}
	dropped := false
	for n := range s.Tunnels {
		if !keep[n] {
			delete(s.Tunnels, n)
			dropped = true
		}
	}
	return dropped
}
