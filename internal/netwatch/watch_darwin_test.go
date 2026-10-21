package netwatch

import (
	"regexp"
	"strings"
	"testing"
)

// Wirefork M7 plan "Модель → Netwatch", review step 3 remark 8: watchScript adds the
// global keys and the capture key, the service patterns
// (anchored, whole keys), and n.watch last.
func TestM7WatchScript(t *testing.T) {
	defer m7NoPanic(t)
	script := watchScript(m7CaptureKey)
	if !strings.HasSuffix(script, "\n") {
		t.Errorf("script %q: want a trailing newline (scutil reads lines)", script)
	}
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != "n.watch" {
		t.Fatalf("script %q: want n.watch last", script)
	}
	if strings.Count(script, "n.watch") != 1 {
		t.Errorf("script %q: want exactly one n.watch", script)
	}

	keys := map[string]bool{}
	var patterns []*regexp.Regexp
	for _, l := range lines[:len(lines)-1] {
		f := strings.Fields(l)
		switch {
		case len(f) == 2 && f[0] == "n.add":
			keys[f[1]] = true
		case len(f) == 3 && f[0] == "n.add" && f[2] == "pattern":
			p := f[1]
			if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
				t.Errorf("pattern %q: want anchored with ^…$", p)
			}
			re, err := regexp.Compile(p)
			if err != nil {
				t.Errorf("pattern %q: %v", p, err)
				continue
			}
			patterns = append(patterns, re)
		default:
			t.Errorf("line %q: want \"n.add <key>\" or \"n.add <pattern> pattern\"", l)
		}
	}

	for _, k := range []string{
		"State:/Network/Global/IPv4",
		"State:/Network/Global/IPv6",
		"State:/Network/Global/DNS",
		m7CaptureKey,
	} {
		if !keys[k] {
			t.Errorf("key %q not added; script %q", k, script)
		}
	}

	matched := func(k string) bool {
		for _, re := range patterns {
			if re.MatchString(k) {
				return true
			}
		}
		return false
	}
	const id = "1C3A2B4D-0000-4000-8000-000000000001"
	const svc = "State:/Network/Service/" + id
	for _, c := range []struct {
		key  string
		want bool
	}{
		{svc + "/IPv4", true},
		{svc + "/IPv6", true},
		{svc + "/DNS", true},
		{"Setup:/Network/Service/" + id + "/DNS", true},
		// Whole keys only (anchors).
		{svc + "/IPv4/x", false},
		{"x" + svc + "/IPv4", false},
		{svc + "/DNSx", false},
		// One path segment for the service ID.
		{"State:/Network/Service/a/b/IPv4", false},
		{"State:/Network/Service//IPv4", false},
		// Not ours: AirPort noise (Wirefork M7 fact 3), other entities.
		{svc + "/AirPort", false},
		{svc + "/Proxies", false},
		{"Setup:/Network/Service/" + id + "/IPv4", false},
		{"State:/Network/Interface/en0/AirPort", false},
	} {
		if got := matched(c.key); got != c.want {
			t.Errorf("patterns match %q: %v, want %v", c.key, got, c.want)
		}
	}
}

// The capture key passed in is the one added (not a fixed one).
func TestM7WatchScriptCaptureKey(t *testing.T) {
	defer m7NoPanic(t)
	const other = "State:/Network/Service/00000000-0000-0000-0000-000000000000/DNS"
	script := watchScript(other)
	if !strings.Contains(script, "n.add "+other+"\n") {
		t.Errorf("script %q: want n.add of %q", script, other)
	}
}
