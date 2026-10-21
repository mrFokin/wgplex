package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests follow design 11 (state.json: atomic write, a broken file is the
// caller's warning, tunnels without records by autostart) and design 4.1
// (no missing parent directory is created), not the implementation.

func TestLoadMissing(t *testing.T) {
	st, err := Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("Load of a missing file: %v", err)
	}
	if len(st.Tunnels) != 0 {
		t.Errorf("Tunnels = %v, want empty", st.Tunnels)
	}
}

// design 11: an unreadable or broken file is an error, the caller warns and
// keeps the empty state.
func TestLoadBroken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{tunnels: work"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load of a broken file succeeded")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := State{Tunnels: map[string]bool{"work": true, "home": false}}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Tunnels) != len(want.Tunnels) ||
		!got.Tunnels["work"] || got.Tunnels["home"] {
		t.Errorf("Load = %v, want %v", got.Tunnels, want.Tunnels)
	}
}

// design 11: the M3 fields (paused, block) are additive; their save by a
// later stage must not lose the M2 records, the M2 code reads and keeps
// tunnels.
func TestLoadIgnoresLaterFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	text := `{"tunnels": {"work": true}, "paused": true, "block": {"cidrs": ["10.0.0.0/8"]}}
`
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(st.Tunnels) != 1 || !st.Tunnels["work"] {
		t.Errorf("Tunnels = %v, want work: true", st.Tunnels)
	}
	// The M3 record survives an M2 rewrite: the field is only unknown here.
	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"tunnels"`) {
		t.Errorf("file = %q, want the tunnels field", b)
	}
}

// The format is plain and obvious (task M2.b): the toggle field is tunnels.
func TestSaveFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, State{Tunnels: map[string]bool{"work": true, "home": false}}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "tunnels": {
    "home": false,
    "work": true
  }
}
`
	if string(b) != want {
		t.Errorf("file = %q, want %q", b, want)
	}
}

// design 4.1: no missing directory, of the file or its parent, is created.
func TestSaveMissingDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "var", "wgplex", "state.json") // var/wgplex missing
	if err := Save(path, State{}); err == nil {
		t.Error("Save in a missing directory succeeded")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Save created %s: %v", dir, err)
	}
	if _, err := os.Stat(dir + "/var"); err == nil {
		t.Error("Save created var")
	}
}

// design 11: the write is atomic — no temporary file left behind.
func TestSaveNoTempLeft(t *testing.T) {
	dir := t.TempDir()
	if err := Save(filepath.Join(dir, "state.json"), State{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The only file is state.json itself: the temporary one went into the
	// rename.
	if len(entries) != 1 || entries[0].Name() != "state.json" || strings.Contains(entries[0].Name(), ".tmp") {
		t.Errorf("files = %v, want only state.json", entries)
	}
}

// design 11: Save replace with a rename, not with a rewrite in place: the
// mode comes from Save (0644), not from the previous file.
func TestSaveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, State{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o644 {
		t.Errorf("mode = %v, want 0644", got)
	}
}

// A nil map in the M2 state is normalized: the saved file holds an empty
// toggles object, not null.
func TestSaveNilTunnels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, State{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("file = %q, want nil tunnels as an empty object", b)
	}
}
