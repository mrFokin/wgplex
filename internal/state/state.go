// Package state keeps <prefix>/var/wgplex/state.json: what the daemon
// remembers across restarts (design 11).
package state

// State is the content of state.json (design 11). On M2 it holds the tunnel
// toggles only; the pause (paused) and the block snapshot (block) are added
// as fields later.
type State struct {
	// Tunnels are the explicit toggles by tunnel name (tunnel.setEnabled,
	// tunnel.disableAll). A tunnel without an entry follows its autostart
	// (design 10.2).
	Tunnels map[string]bool `json:"tunnels,omitempty"`
}

// Load reads the state file at path. No file: empty State, nil error.
// Unreadable or broken (an empty file included): empty State and the error;
// the caller logs a warning and goes on by autostart (design 11). Unknown
// fields and "tunnels": null are fine.
func Load(path string) (State, error) {
	panic("not implemented")
}

// Save writes s to path atomically: a temporary file in the directory of path,
// mode 0640, then rename (design 11). On error no temporary file is left.
// The directory is not created.
func (s State) Save(path string) error {
	panic("not implemented")
}

// Prune drops the toggles of tunnels not in names (the tunnels of the applied
// config, design 11) and reports whether it dropped any.
func (s *State) Prune(names []string) bool {
	panic("not implemented")
}
