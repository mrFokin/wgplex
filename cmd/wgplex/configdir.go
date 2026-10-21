package main

import (
	"os"
	"path/filepath"
)

// readConfigDir reads every *.yaml and *.conf in dir, following symlinks,
// keyed by base name — on M1 the client sends them over (solution 5, the
// Wirefork delivery; in M2 the daemon reads the directory itself, 10.2).
func readConfigDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".conf" {
			continue
		}
		path := filepath.Join(dir, name)
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		files[name] = string(data)
	}
	return files, nil
}
