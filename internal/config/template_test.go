package config

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Design 10.3: the release template share/wgplex/wgplex.yaml is entirely
// commented out; an empty config is valid (design 10.2): no tunnels, the
// system DNS is left alone, and the config counts as configured.

// templatePath finds the template relative to this source file (the repo root
// is two levels above internal/config).
func templatePath(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(self), "..", "..", "share", "wgplex", "wgplex.yaml")
}

func readTemplate(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(templatePath(t))
	if err != nil {
		t.Fatalf("template is missing: %v", err)
	}
	return data
}

// design 10.3: the template, installed as wgplex.yaml (0600) into a 0700
// directory, loads without errors and yields an empty config.
func TestTemplateLoadsAsEmptyConfig(t *testing.T) {
	data := readTemplate(t)

	dir := filepath.Join(t.TempDir(), "wgplex")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wgplex.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir(template): %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadDir(template): nil config without error (configured must be true)")
	}
	if n := len(cfg.Tunnels); n != 0 {
		t.Errorf("tunnels = %d, want 0", n)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("rules = %d, want 0", len(cfg.Rules))
	}
	if cfg.NeedsDNS() {
		t.Error("NeedsDNS() = true, want false: an empty config must not capture DNS (design 10.3)")
	}
}

// design 10.3: the template is entirely commented out and has no
// realistic private keys (CLAUDE.md: no keys in fixtures).
func TestTemplateIsCommentedAndKeyFree(t *testing.T) {
	data := readTemplate(t)

	// A WireGuard key is 32 bytes in base64: 43 chars and a trailing '='.
	key := regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
	privLine := regexp.MustCompile(`(?i)^\s*#?\s*PrivateKey\s*[:=]\s*(\S+)`)

	for i, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim != "" && !strings.HasPrefix(trim, "#") {
			t.Errorf("line %d is not commented out: %q", i+1, trim)
		}
		if key.MatchString(line) {
			t.Errorf("line %d looks like a real WireGuard key: %q", i+1, trim)
		}
		if m := privLine.FindStringSubmatch(line); m != nil && !strings.HasPrefix(m[1], "<") {
			t.Errorf("line %d: PrivateKey must be a placeholder like <private-key>: %q", i+1, trim)
		}
	}
}
