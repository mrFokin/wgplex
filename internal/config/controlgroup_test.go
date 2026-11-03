package config

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// Tests follow design 5, 10.1: control_group defaults to "admin"; a named
// group must exist (lookupGroup); a numeric gid is accepted unchecked;
// unknown YAML keys are an error. The group lookup is replaced through the
// lookupGroup variable so that tests need neither Directory Services nor a
// particular set of groups on the machine.

// cgWithGroup replaces lookupGroup for the duration of the test. found maps
// a group name to whether it exists; calls records every name looked up.
func cgWithGroup(t *testing.T, found map[string]bool, calls *[]string) {
	t.Helper()
	old := lookupGroup
	lookupGroup = func(name string) (*user.Group, error) {
		if calls != nil {
			*calls = append(*calls, name)
		}
		if found[name] {
			return &user.Group{Name: name, Gid: "20"}, nil
		}
		return nil, user.UnknownGroupError(name)
	}
	t.Cleanup(func() { lookupGroup = old })
}

// cgWriteDir writes a config directory with wgplex.yaml text and returns it.
func cgWriteDir(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, mainFile), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestControlGroupDefault(t *testing.T) {
	// design 10.1: control_group defaults to "admin"
	cfg, _, err := Load(map[string][]byte{mainFile: []byte("tunnels: []\n")})
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if cfg.ControlGroup != "admin" {
		t.Errorf("ControlGroup = %q, want %q", cfg.ControlGroup, "admin")
	}
}

func TestControlGroupSet(t *testing.T) {
	// design 10.1: a set value is kept
	cfg, _, err := Load(map[string][]byte{mainFile: []byte("control_group: staff\ntunnels: []\n")})
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if cfg.ControlGroup != "staff" {
		t.Errorf("ControlGroup = %q, want %q", cfg.ControlGroup, "staff")
	}
}

func TestControlGroupExistingAccepted(t *testing.T) {
	// design 5: a group that exists is accepted
	var calls []string
	cgWithGroup(t, map[string]bool{"wgplex-test-group": true}, &calls)
	dir := cgWriteDir(t, "control_group: wgplex-test-group\ntunnels: []\n")

	cfg, _, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: unexpected error: %v", err)
	}
	if cfg.ControlGroup != "wgplex-test-group" {
		t.Errorf("ControlGroup = %q, want %q", cfg.ControlGroup, "wgplex-test-group")
	}
	if len(calls) != 1 || calls[0] != "wgplex-test-group" {
		t.Errorf("lookupGroup calls = %v, want one call for wgplex-test-group", calls)
	}
}

func TestControlGroupMissingIsError(t *testing.T) {
	// design 5: a nonexistent named group is a config error, not a warning
	cgWithGroup(t, map[string]bool{}, nil)
	dir := cgWriteDir(t, "control_group: wgplex-no-such-group\ntunnels: []\n")

	cfg, _, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir: expected error for a nonexistent control_group, got nil")
	}
	if cfg != nil {
		t.Error("LoadDir: cfg must be nil on error")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("LoadDir: error is not Errors: %T", err)
	}
	if !strings.Contains(err.Error(), "wgplex-no-such-group") {
		t.Errorf("error must name the group, got: %v", err)
	}
}

func TestControlGroupNumericNotLookedUp(t *testing.T) {
	// design 5: a numeric gid is accepted without a lookup
	var calls []string
	cgWithGroup(t, map[string]bool{}, &calls) // nothing "exists"
	dir := cgWriteDir(t, "control_group: \"1234\"\ntunnels: []\n")

	cfg, _, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: unexpected error for a numeric gid: %v", err)
	}
	if cfg.ControlGroup != "1234" {
		t.Errorf("ControlGroup = %q, want %q", cfg.ControlGroup, "1234")
	}
	if len(calls) != 0 {
		t.Errorf("lookupGroup called for a numeric gid: %v", calls)
	}
}

func TestControlGroupRealGroup(t *testing.T) {
	// design 5: a real group of this machine is accepted through the real
	// lookupGroup (no substituted table)
	name := ""
	if u, err := user.Current(); err == nil {
		if g, err := user.LookupGroupId(u.Gid); err == nil {
			name = g.Name
		}
	}
	if name == "" {
		for _, candidate := range []string{"admin", "wheel", "staff", "nogroup"} {
			if _, err := user.LookupGroup(candidate); err == nil {
				name = candidate
				break
			}
		}
	}
	if name == "" {
		t.Skip("no known group on this machine")
	}
	if _, err := user.LookupGroup(name); err != nil {
		t.Skipf("LookupGroup(%q): %v", name, err)
	}

	dir := cgWriteDir(t, "control_group: "+name+"\ntunnels: []\n")
	cfg, _, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: unexpected error for existing group %q: %v", name, err)
	}
	if cfg.ControlGroup != name {
		t.Errorf("ControlGroup = %q, want %q", cfg.ControlGroup, name)
	}
}

func TestControlGroupUnknownKey(t *testing.T) {
	// design 10.1: unknown YAML keys are an error (strict parsing)
	_, _, err := Load(map[string][]byte{mainFile: []byte("control_groups: admin\ntunnels: []\n")})
	if err == nil {
		t.Fatal("Load: expected error for an unknown key, got nil")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("Load: error is not Errors: %T", err)
	}
}
