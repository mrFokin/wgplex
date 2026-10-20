package main

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// Tests follow design 9.3 (the client reads every *.yaml and *.conf of the
// config folder, following symlinks, keyed by the base name), not the
// implementation.

func m6Write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestM6ReadConfigDir(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()

	m6Write(t, filepath.Join(dir, "wgplex.yaml"), "tunnels: []\n")
	m6Write(t, filepath.Join(dir, "work.conf"), "[Interface]\n# work\n")
	m6Write(t, filepath.Join(dir, "old.yaml"), "x: 1\n") // the daemon warns about it (design 9.3)
	m6Write(t, filepath.Join(dir, "notes.txt"), "skip me\n")
	m6Write(t, filepath.Join(dir, "work.conf.bak"), "skip me\n")
	m6Write(t, filepath.Join(dir, "wgplex.yml"), "skip me\n")
	// A symlink to a file elsewhere (design 3: symlinks are allowed).
	m6Write(t, filepath.Join(other, "de-real.conf"), "[Interface]\n# de\n")
	if err := os.Symlink(filepath.Join(other, "de-real.conf"), filepath.Join(dir, "de.conf")); err != nil {
		t.Fatal(err)
	}
	// Folders are skipped, whatever their name.
	if err := os.Mkdir(filepath.Join(dir, "sub.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	m6Write(t, filepath.Join(dir, "nested", "inner.conf"), "skip me\n")

	got, err := readConfigDir(dir)
	if err != nil {
		t.Fatalf("readConfigDir: %v", err)
	}
	want := map[string]string{
		"wgplex.yaml": "tunnels: []\n",
		"work.conf":   "[Interface]\n# work\n",
		"old.yaml":    "x: 1\n",
		"de.conf":     "[Interface]\n# de\n",
	}
	if !maps.Equal(got, want) {
		t.Errorf("readConfigDir = %q\nwant %q", got, want)
	}
}

func TestM6ReadConfigDirEmpty(t *testing.T) {
	got, err := readConfigDir(t.TempDir())
	if err != nil {
		t.Fatalf("readConfigDir: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty folder: %q, want nothing", got)
	}
}

func TestM6ReadConfigDirMissing(t *testing.T) {
	if _, err := readConfigDir(filepath.Join(t.TempDir(), "nosuch")); err == nil {
		t.Error("missing folder: no error")
	}
}
