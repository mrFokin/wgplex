package state

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInternalLoad(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		want    map[string]bool
		wantErr bool
	}{
		{"toggles", `{"tunnels":{"nl":true,"home":false}}`, map[string]bool{"nl": true, "home": false}, false},
		{"null", `{"tunnels":null}`, nil, false},
		{"unknown fields", `{"tunnels":{"a":true},"paused":true,"block":{"x":1}}`, map[string]bool{"a": true}, false},
		{"empty object", `{}`, nil, false},
		{"empty file", ``, nil, true},
		{"broken", `{"tunnels":`, nil, true},
		{"wrong type", `{"tunnels":{"a":"yes"}}`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(p, []byte(c.data), 0o640); err != nil {
				t.Fatal(err)
			}
			s, err := Load(p)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if len(s.Tunnels) != len(c.want) || (len(c.want) > 0 && !reflect.DeepEqual(s.Tunnels, c.want)) {
				t.Fatalf("Tunnels = %v, want %v", s.Tunnels, c.want)
			}
		})
	}
}

func TestInternalLoadUnreadable(t *testing.T) {
	dir := t.TempDir()
	// A directory in place of the file: read fails.
	p := filepath.Join(dir, "state.json")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err == nil || len(s.Tunnels) != 0 {
		t.Fatalf("Load = %+v, %v; want empty and an error", s, err)
	}
}

func TestInternalSaveRenameFails(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory in place of the file: rename fails.
	p := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(filepath.Join(p, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (State{Tunnels: map[string]bool{"a": true}}).Save(p, -1); err == nil {
		t.Fatal("Save: no error")
	}
	internalOnlyFile(t, dir, "state.json")
}

// internalOnlyFile fails unless dir holds just name (no temporary files left).
func internalOnlyFile(t *testing.T, dir, name string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != name {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("dir has %v, want only %s", names, name)
	}
}
