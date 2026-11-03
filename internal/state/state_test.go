package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Tests follow design 11, not the implementation: state.json holds the
// explicit tunnel toggles, is written atomically (a temporary file in the
// same directory and a rename), is 0640; a missing file, "tunnels": null and
// unknown fields are fine; a broken or empty file is an error with an empty
// State (the caller warns and goes on by autostart); Prune drops toggles of
// tunnels no longer in the config.

// --- Load ------------------------------------------------------------------

func TestLoadNoFile(t *testing.T) {
	// design 11: no file is not an error, the state is empty
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: unexpected error for a missing file: %v", err)
	}
	if len(s.Tunnels) != 0 {
		t.Errorf("Load: want no toggles, got %v", s.Tunnels)
	}
}

func TestLoadToggles(t *testing.T) {
	// design 11: explicit toggles are read
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"tunnels":{"t1":true,"t2":false}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if s.Tunnels["t1"] != true || s.Tunnels["t2"] != false || len(s.Tunnels) != 2 {
		t.Errorf("Tunnels = %v, want map[t1:true t2:false]", s.Tunnels)
	}
}

func TestLoadBroken(t *testing.T) {
	// design 11: a broken file is an error with an empty State
	tests := []struct {
		name string
		data string
	}{
		{"truncated JSON", `{"tunnels":{"t1":`},
		{"not JSON", "tunnels: t1\n"},
		{"wrong type", `{"tunnels":["t1"]}`},
		{"empty file", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o640); err != nil {
				t.Fatal(err)
			}
			s, err := Load(path)
			if err == nil {
				t.Fatalf("Load: expected error for %s, got nil", tt.name)
			}
			if len(s.Tunnels) != 0 {
				t.Errorf("Load: want an empty State on error, got %v", s.Tunnels)
			}
		})
	}
}

func TestLoadNullTunnels(t *testing.T) {
	// design 11: "tunnels": null is fine
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"tunnels":null}`), 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: unexpected error for null tunnels: %v", err)
	}
	if len(s.Tunnels) != 0 {
		t.Errorf("Load: want no toggles, got %v", s.Tunnels)
	}
}

func TestLoadUnknownField(t *testing.T) {
	// design 11: unknown fields are fine (forward compatibility)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"tunnels":{"t1":true},"future":42}`), 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: unexpected error for an unknown field: %v", err)
	}
	if !s.Tunnels["t1"] {
		t.Errorf("Tunnels = %v, want t1 true", s.Tunnels)
	}
}

// --- Save ------------------------------------------------------------------

func TestSaveLoadRoundTrip(t *testing.T) {
	// design 11: Save then Load gives the same toggles
	path := filepath.Join(t.TempDir(), "state.json")
	want := State{Tunnels: map[string]bool{"work": true, "home": false}}
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if len(got.Tunnels) != len(want.Tunnels) {
		t.Fatalf("Tunnels = %v, want %v", got.Tunnels, want.Tunnels)
	}
	for name, on := range want.Tunnels {
		if got.Tunnels[name] != on {
			t.Errorf("Tunnels[%q] = %v, want %v", name, got.Tunnels[name], on)
		}
	}
}

func TestSaveAtomic(t *testing.T) {
	// design 11: the file is whole JSON, no temporary file is left, mode 0640
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := State{Tunnels: map[string]bool{"t1": true}}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var decoded struct {
		Tunnels map[string]bool `json:"tunnels"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("state file is not whole JSON: %v\n%s", err, data)
	}
	if !decoded.Tunnels["t1"] {
		t.Errorf("saved tunnels = %v, want t1 true", decoded.Tunnels)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "state.json" {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o640 {
		t.Errorf("state mode = %04o, want 0640", perm)
	}
}

func TestSaveOverwrite(t *testing.T) {
	// design 11: a later Save replaces the file entirely
	path := filepath.Join(t.TempDir(), "state.json")
	if err := (State{Tunnels: map[string]bool{"old": true}}).Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := (State{Tunnels: map[string]bool{"new": false}}).Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := got.Tunnels["old"]; ok {
		t.Errorf("old toggle kept after overwrite: %v", got.Tunnels)
	}
	if on, ok := got.Tunnels["new"]; !ok || on {
		t.Errorf("Tunnels = %v, want new false", got.Tunnels)
	}
}

func TestSaveMissingDir(t *testing.T) {
	// design 11: Save does not create the directory; the error leaves no file
	dir := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(dir, "state.json")
	if err := (State{Tunnels: map[string]bool{"t1": true}}).Save(path); err == nil {
		t.Fatal("Save: expected an error for a missing directory, got nil")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Save: created the directory or a file there: %v", err)
	}
}

// --- Prune -----------------------------------------------------------------

func TestPrune(t *testing.T) {
	// design 11: Prune drops only toggles of tunnels not in the config and
	// reports whether it dropped any
	tests := []struct {
		name    string
		tunnels map[string]bool
		names   []string
		want    map[string]bool
		dropped bool
	}{
		{
			name:    "nothing to drop",
			tunnels: map[string]bool{"a": true, "b": false},
			names:   []string{"a", "b"},
			want:    map[string]bool{"a": true, "b": false},
			dropped: false,
		},
		{
			name:    "drop one",
			tunnels: map[string]bool{"a": true, "gone": true},
			names:   []string{"a"},
			want:    map[string]bool{"a": true},
			dropped: true,
		},
		{
			name:    "drop all",
			tunnels: map[string]bool{"x": true, "y": false},
			names:   nil,
			want:    map[string]bool{},
			dropped: true,
		},
		{
			name:    "empty state",
			tunnels: map[string]bool{},
			names:   []string{"a"},
			want:    map[string]bool{},
			dropped: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := State{Tunnels: tt.tunnels}
			if got := s.Prune(tt.names); got != tt.dropped {
				t.Errorf("Prune = %v, want %v", got, tt.dropped)
			}
			if len(s.Tunnels) != len(tt.want) {
				t.Fatalf("Tunnels = %v, want %v", s.Tunnels, tt.want)
			}
			for name := range tt.want {
				if _, ok := s.Tunnels[name]; !ok {
					t.Errorf("Tunnels = %v, want %v", s.Tunnels, tt.want)
				}
			}
		})
	}
}

func TestPruneKeepsValues(t *testing.T) {
	// design 11: an explicit "off" toggle is kept, not treated as missing
	s := State{Tunnels: map[string]bool{"a": false}}
	if s.Prune([]string{"a"}) {
		t.Error("Prune: dropped a toggle of a tunnel that is in the config")
	}
	if on, ok := s.Tunnels["a"]; !ok || on {
		t.Errorf("Tunnels = %v, want a false", s.Tunnels)
	}
}
