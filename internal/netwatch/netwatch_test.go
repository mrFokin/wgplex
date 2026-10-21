package netwatch

import (
	"strings"
	"testing"
	"time"
)

// Tests follow design 6, 8 and the Wirefork M7 plan ("Модель → Netwatch",
// decisions 2, 4; facts 2–5), not the implementation. Time is passed
// explicitly.

var m7T0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// m7CaptureKey has the form of dns.CaptureKey: a service DNS key.
const m7CaptureKey = "State:/Network/Service/50054742-C5CE-4C74-866E-FBD7AC0A16AE/DNS"

// The debounce of the plan: 500 ms of quiet, at most 3 s from the first event.
const (
	m7Quiet = 500 * time.Millisecond
	m7Max   = 3 * time.Second
)

// m7NoPanic turns a panic of the code under test into a test failure; use
// as `defer m7NoPanic(t)`.
func m7NoPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		t.Fatalf("panic: %v", r)
	}
}

// --- parseChangedKey ---------------------------------------------------------------

// Fact 2: n.watch prints `  14:36:45.351 (+0.000) changedKey [1] = <key>`;
// the key is taken exactly, a trailing space kept.
func TestM7ParseChangedKey(t *testing.T) {
	defer m7NoPanic(t)
	cases := []struct {
		line string
		key  string
		ok   bool
	}{
		{"  14:36:45.351 (+0.000) changedKey [1] = State:/Network/Global/IPv4", "State:/Network/Global/IPv4", true},
		{"  14:36:45.352 (+0.001) changedKey [0] = State:/Network/Global/DNS", "State:/Network/Global/DNS", true},
		{"  09:01:02.003 (+12.345) changedKey [17] = State:/Network/Service/8A1F0C2E-1111-2222-3333-444455556666/IPv6",
			"State:/Network/Service/8A1F0C2E-1111-2222-3333-444455556666/IPv6", true},
		{"  14:36:45.351 (+0.000) changedKey [2] = State:/Network/Global/IPv6", "State:/Network/Global/IPv6", true},
		{"  14:36:45.351 (+0.000) changedKey [3] = " + m7CaptureKey, m7CaptureKey, true},
		// A key may end in a space: kept as printed.
		{"  14:36:45.351 (+0.000) changedKey [1] = Setup:/Network/Service/X/DNS ", "Setup:/Network/Service/X/DNS ", true},
		// Other output of scutil.
		{"", "", false},
		{"> ", "", false},
		{"  14:36:45.351 (+0.000) notification callback (store address = 0x600000c0c000).", "", false},
		{"  No such key", "", false},
		{"<dictionary> {", "", false},
		{"  Name : da_fokin", "", false},
	}
	for _, c := range cases {
		key, ok := parseChangedKey(c.line)
		if key != c.key || ok != c.ok {
			t.Errorf("parseChangedKey(%q) = %q, %v; want %q, %v", c.line, key, ok, c.key, c.ok)
		}
	}
}

// --- classify ---------------------------------------------------------------------

// Wirefork M7 plan "Netwatch": global and service keys → Network, the capture key →
// Capture (only: its own write must not look like a network change);
// AirPort, the user keys (not watched, design 4.1) and the rest are not
// ours.
func TestM7Classify(t *testing.T) {
	defer m7NoPanic(t)
	const svc = "8A1F0C2E-1111-2222-3333-444455556666"
	cases := []struct {
		key  string
		want Event
	}{
		{"State:/Network/Global/IPv4", Network},
		{"State:/Network/Global/IPv6", Network},
		{"State:/Network/Global/DNS", Network},
		{"State:/Network/Service/" + svc + "/IPv4", Network},
		{"State:/Network/Service/" + svc + "/IPv6", Network},
		{"State:/Network/Service/" + svc + "/DNS", Network},
		{"State:/Network/Service/en0/DNS", Network},
		{"Setup:/Network/Service/" + svc + "/DNS", Network},
		{m7CaptureKey, Capture},
		// Not ours.
		{"State:/Network/Interface/en0/AirPort", 0},
		{"State:/Network/Interface/en0/AirPort/Power", 0},
		{"Setup:/Network/Service/" + svc + "/IPv4", 0}, // Setup: only DNS
		{"State:/Network/Service/" + svc + "/Proxies", 0},
		{"State:/Network/Global/Proxies", 0},
		{"State:/Network/Service/" + svc + "/sub/DNS", 0}, // [^/]+: one level
		{"State:/Users/Other", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := classify(c.key, m7CaptureKey); got != c.want {
			t.Errorf("classify(%q) = %#x, want %#x", c.key, got, c.want)
		}
	}
	// Another capture key: the default one is just a service DNS key.
	if got := classify(m7CaptureKey, "State:/Network/Service/00000000-0000-0000-0000-000000000000/DNS"); got != Network {
		t.Errorf("classify(another service DNS key) = %#x, want Network", got)
	}
}

// --- debouncer --------------------------------------------------------------------

// Decision 2: nothing pending — nothing due, nothing to wait for.
func TestM7DebouncerEmpty(t *testing.T) {
	defer m7NoPanic(t)
	d := newDebouncer(m7Quiet, m7Max)
	if e, next := d.due(m7T0); e != 0 || !next.IsZero() {
		t.Errorf("empty: due = %#x, %v; want 0, zero", e, next)
	}
}

// Fact 2, decision 2: a burst of keys within 50 ms is one event after 500 ms
// of quiet, the masks merged by OR; then nothing is pending.
func TestM7DebouncerBurst(t *testing.T) {
	defer m7NoPanic(t)
	d := newDebouncer(m7Quiet, m7Max)
	ms := time.Millisecond
	d.add(m7T0, Network)
	d.add(m7T0.Add(10*ms), Network)
	d.add(m7T0.Add(20*ms), Wake)
	d.add(m7T0.Add(50*ms), Network)
	last := m7T0.Add(50 * ms)

	for _, at := range []time.Duration{50 * ms, 100 * ms, 300 * ms, 549 * ms} {
		now := m7T0.Add(at)
		e, next := d.due(now)
		if e != 0 {
			t.Errorf("due at +%v = %#x, want nothing before 500 ms of quiet", at, e)
		}
		if next.IsZero() || !next.After(now) || next.After(last.Add(m7Quiet)) {
			t.Errorf("due at +%v: look again at %v, want after now and not after %v", at, next, last.Add(m7Quiet))
		}
	}
	e, _ := d.due(last.Add(m7Quiet))
	if e != Network|Wake {
		t.Errorf("due after 500 ms of quiet = %#x, want Network|Wake (%#x)", e, Network|Wake)
	}
	if e, next := d.due(last.Add(m7Quiet + time.Second)); e != 0 || !next.IsZero() {
		t.Errorf("after delivery: due = %#x, %v; want 0, zero", e, next)
	}

	// A new event starts a new window.
	t2 := last.Add(10 * time.Second)
	d.add(t2, Capture)
	if e, _ := d.due(t2.Add(m7Quiet - ms)); e != 0 {
		t.Errorf("second window: due early = %#x", e)
	}
	if e, _ := d.due(t2.Add(m7Quiet)); e != Capture {
		t.Errorf("second window: due = %#x, want Capture only", e)
	}
}

// Decision 2: a steady stream (every 100 ms, never 500 ms of quiet) is
// delivered not later than 3 s after its first event.
func TestM7DebouncerStream(t *testing.T) {
	defer m7NoPanic(t)
	d := newDebouncer(m7Quiet, m7Max)
	step := 100 * time.Millisecond
	var fired []time.Duration
	var masks []Event
	evs := []Event{Network, Wake, Network, Resync}
	for i := 0; time.Duration(i)*step <= 5*time.Second; i++ {
		at := time.Duration(i) * step
		now := m7T0.Add(at)
		if e, _ := d.due(now); e != 0 {
			fired = append(fired, at)
			masks = append(masks, e)
		}
		d.add(now, evs[i%len(evs)])
	}
	if len(fired) == 0 {
		t.Fatal("a steady stream was never delivered")
	}
	if fired[0] != m7Max {
		t.Errorf("first delivery at +%v, want +%v (3 s after the first event)", fired[0], m7Max)
	}
	if masks[0] != Network|Wake|Resync {
		t.Errorf("first delivery = %#x, want Network|Wake|Resync", masks[0])
	}
	if len(fired) > 1 {
		t.Errorf("deliveries at %v, want one within 5 s (the next window ends at +6 s)", fired)
	}
}

// Decision 2: the quiet boundary is inclusive: due exactly 500 ms after the
// last event.
func TestM7DebouncerQuietBoundary(t *testing.T) {
	defer m7NoPanic(t)
	d := newDebouncer(m7Quiet, m7Max)
	d.add(m7T0, Wake)
	if e, next := d.due(m7T0.Add(m7Quiet - time.Nanosecond)); e != 0 || next.IsZero() {
		t.Errorf("just before: due = %#x, %v; want 0 and a time to look again", e, next)
	}
	if e, _ := d.due(m7T0.Add(m7Quiet)); e != Wake {
		t.Errorf("at 500 ms: due = %#x, want Wake", e)
	}
}

// --- slept ------------------------------------------------------------------------

// Fact 5, decision 2: a sleep is wall − mono > 5 s between two ticks.
func TestM7Slept(t *testing.T) {
	defer m7NoPanic(t)
	s := time.Second
	cases := []struct {
		wall, mono time.Duration
		want       bool
	}{
		{2 * s, 2 * s, false},
		{2*s + 300*time.Millisecond, 2 * s, false}, // a late tick
		{7 * s, 2 * s, false},                      // exactly 5 s: not more
		{7*s + time.Millisecond, 2 * s, true},
		{time.Hour, 2 * s, true},
		{8 * time.Hour, 2 * s, true},
		{2 * s, 10 * s, false}, // the wall clock was set back
		{-time.Hour, 2 * s, false},
	}
	for _, c := range cases {
		if got := slept(c.wall, c.mono); got != c.want {
			t.Errorf("slept(wall %v, mono %v) = %v, want %v", c.wall, c.mono, got, c.want)
		}
	}
}

// Event.String (doc comment): names joined by "|", "none" for 0.
func TestM7EventString(t *testing.T) {
	defer m7NoPanic(t)
	if got := Event(0).String(); got != "none" {
		t.Errorf("Event(0): %q, want \"none\"", got)
	}
	if got := (Network | Wake).String(); got != "network|wake" {
		t.Errorf("Network|Wake: %q, want \"network|wake\"", got)
	}
	if got := Network.String(); got != "network" {
		t.Errorf("Network: %q, want \"network\"", got)
	}
	if got := Wake.String(); got != "wake" {
		t.Errorf("Wake: %q, want \"wake\"", got)
	}
	// Every event has its own single name; all of them together give all names.
	all := []Event{Network, Capture, Wake, Resync}
	seen := map[string]bool{}
	var mask Event
	for _, e := range all {
		n := e.String()
		if n == "" || n == "none" || strings.Contains(n, "|") || seen[n] {
			t.Errorf("Event %d: name %q, want a distinct single name", e, n)
		}
		seen[n] = true
		mask |= e
	}
	parts := strings.Split(mask.String(), "|")
	if len(parts) != len(all) {
		t.Errorf("all events: %q, want %d names", mask.String(), len(all))
	}
	for _, p := range parts {
		if !seen[p] {
			t.Errorf("all events: name %q not of a single event", p)
		}
	}
}
