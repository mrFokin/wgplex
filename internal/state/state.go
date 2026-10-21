// Package state stores the daemon state, state.json (design 11): the
// toggles of M2, with the M3 fields (paused, the block snapshot, design
// 21.1) still to come. Nothing secret goes here: only tunnel names, bools
// and (M3) CIDRs and domains.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// State is the content of state.json (design 11).
type State struct {
	// Tunnels maps the tunnel names toggled explicitly (tunnel.setEnabled,
	// tunnel.disableAll, design 11) to their state (design 11). A tunnel
	// without a record follows its autostart (design 10.2).
	Tunnels map[string]bool `json:"tunnels"`
}

// Load reads State from path. A missing file is not an error: the state is
// empty. An unreadable or broken file is the error: the caller logs it as a
// warning and goes on with the empty state (tunnels by autostart, design
// 11). Fields of later stages (paused, block) are ignored here.
func Load(path string) (State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{Tunnels: map[string]bool{}}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("%s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", path, err)
	}
	if s.Tunnels == nil {
		s.Tunnels = map[string]bool{}
	}
	return s, nil
}

// Save writes State at path atomically (design 11): a temporary file in the
// same directory and rename, the file mode 0644. The directory (and no
// missing parent of it) is not created (design 4.1): its absence is the
// returned error, the caller logs it and the daemon goes on without the
// file.
func Save(path string, s State) error {
	if s.Tunnels == nil {
		s.Tunnels = map[string]bool{}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
