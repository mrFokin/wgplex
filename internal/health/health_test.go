package health

import (
	"strings"
	"testing"
	"time"

	"github.com/mrFokin/wgplex/internal/tunnel"
)

// Tests follow design 9, not
// the implementation. Time is passed explicitly; all times are wall times
// without a monotonic reading (time.Date).

var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func testTime(d time.Duration) time.Time { return t0.Add(d) }

var (
	noPing   = PingResult{}
	pingFail = PingResult{Done: true}
)

func pingOK(rtt time.Duration) PingResult { return PingResult{Done: true, OK: true, RTT: rtt} }

// noPanic turns a panic of the code under test into a test failure; use
// as `defer noPanic(t)`.
func noPanic(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		t.Fatalf("panic: %v", r)
	}
}

// never is a zero handshake time: never.
var never time.Time

// step is one poll and the state wanted after it.
type step struct {
	at     time.Duration // since t0
	hs     time.Time     // newest handshake; zero: never
	tx, rx uint64
	ping   PingResult
	want   State
}

func stateName(s State) string {
	switch s {
	case Unknown:
		return "Unknown"
	case Alive:
		return "Alive"
	case Dead:
		return "Dead"
	}
	return "State(?)"
}

// run observes the steps on h, checking the state after each, and returns
// the last Health.
func run(t *testing.T, what string, h Health, steps []step) Health {
	t.Helper()
	for i, st := range steps {
		h = h.Observe(Sample{At: testTime(st.at), Handshake: st.hs, Tx: st.tx, Rx: st.rx, Ping: st.ping})
		if h.State != st.want {
			t.Errorf("%s: step %d (at %v): State %s, want %s (Reason %q)",
				what, i, st.at, stateName(h.State), stateName(st.want), h.Reason)
		}
		if h.Alive() != (h.State != Dead) {
			t.Errorf("%s: step %d: Alive() = %v with State %s", what, i, h.Alive(), stateName(h.State))
		}
		if h.State != Dead && h.Reason != "" {
			t.Errorf("%s: step %d: Reason %q with State %s, want empty", what, i, h.Reason, stateName(h.State))
		}
		if h.State == Dead && h.Reason == "" {
			t.Errorf("%s: step %d: Dead without a Reason", what, i)
		}
	}
	return h
}

// --- start ---------------------------------------------------------------------

// design 9 "Начало": Unknown after the tunnel is up, routable.
func TestHealthNew(t *testing.T) {
	defer noPanic(t)
	h := New(t0)
	if h.State != Unknown {
		t.Errorf("New: State %s, want Unknown", stateName(h.State))
	}
	if !h.Alive() {
		t.Error("New: Alive() false, want true (Unknown is routable)")
	}
	if h.Fails != 0 || h.Reason != "" || !h.LastOK.IsZero() || h.RTT != 0 {
		t.Errorf("New: %+v, want no fails, reason, last OK or RTT", h)
	}
}

// Alive() is State != Dead.
func TestHealthAliveMethod(t *testing.T) {
	defer noPanic(t)
	for _, c := range []struct {
		s    State
		want bool
	}{{Unknown, true}, {Alive, true}, {Dead, false}} {
		if got := (Health{State: c.s}).Alive(); got != c.want {
			t.Errorf("Health{State: %s}.Alive() = %v, want %v", stateName(c.s), got, c.want)
		}
	}
}

// --- active check ----------------------------------------------------------------

// design 9 "Активная проверка": dead after 3 failures in a row, alive after
// 1 success; Fails counts consecutive failures. No traffic in these
// samples, so the passive verdict stays put.
func TestHealthPing(t *testing.T) {
	defer noPanic(t)
	ok := pingOK(12 * time.Millisecond)
	cases := []struct {
		name  string
		pings []PingResult
		state State
		fails int
	}{
		{"1 failure", []PingResult{pingFail}, Unknown, 1},
		{"2 failures: still routable", []PingResult{pingFail, pingFail}, Unknown, 2},
		{"3 failures: dead", []PingResult{pingFail, pingFail, pingFail}, Dead, 3},
		{"5 failures: dead", []PingResult{pingFail, pingFail, pingFail, pingFail, pingFail}, Dead, 5},
		{"1 success: alive", []PingResult{ok}, Alive, 0},
		{"dead, then 1 success: alive", []PingResult{pingFail, pingFail, pingFail, ok}, Alive, 0},
		{"a success breaks the series", []PingResult{pingFail, pingFail, ok, pingFail, pingFail}, Alive, 2},
		{"alive, 2 failures: still alive", []PingResult{ok, pingFail, pingFail}, Alive, 2},
		{"alive, 3 failures: dead", []PingResult{ok, pingFail, pingFail, pingFail}, Dead, 3},
		{"no ping made: nothing changes", []PingResult{noPing, noPing, noPing, noPing}, Unknown, 0},
	}
	for _, c := range cases {
		h := New(t0)
		for i, p := range c.pings {
			h = h.Observe(Sample{At: testTime(time.Duration(i+1) * Interval), Ping: p})
		}
		if h.State != c.state || h.Fails != c.fails {
			t.Errorf("%s: State %s, Fails %d; want %s, %d", c.name, stateName(h.State), h.Fails, stateName(c.state), c.fails)
		}
		if h.Alive() != (c.state != Dead) {
			t.Errorf("%s: Alive() = %v", c.name, h.Alive())
		}
		if c.state == Dead && !strings.Contains(h.Reason, "failures") {
			t.Errorf("%s: Reason %q, want it to tell of ping failures", c.name, h.Reason)
		}
		if c.state != Dead && h.Reason != "" {
			t.Errorf("%s: Reason %q, want empty when not dead", c.name, h.Reason)
		}
	}
}

// A success sets LastOK (the sample time) and
// RTT; a failure keeps them (RTT of the last successful ping).
func TestHealthPingLastOK(t *testing.T) {
	defer noPanic(t)
	h := New(t0)
	h = h.Observe(Sample{At: testTime(10 * time.Second), Ping: pingOK(12 * time.Millisecond)})
	if !h.LastOK.Equal(testTime(10*time.Second)) || h.RTT != 12*time.Millisecond {
		t.Errorf("after OK: LastOK %v RTT %v, want %v 12ms", h.LastOK, h.RTT, testTime(10*time.Second))
	}
	h = h.Observe(Sample{At: testTime(20 * time.Second), Ping: pingOK(34 * time.Millisecond)})
	if !h.LastOK.Equal(testTime(20*time.Second)) || h.RTT != 34*time.Millisecond {
		t.Errorf("after 2nd OK: LastOK %v RTT %v, want %v 34ms", h.LastOK, h.RTT, testTime(20*time.Second))
	}
	h = h.Observe(Sample{At: testTime(30 * time.Second), Ping: pingFail})
	if !h.LastOK.Equal(testTime(20*time.Second)) || h.RTT != 34*time.Millisecond || h.Fails != 1 {
		t.Errorf("after a failure: LastOK %v RTT %v Fails %d, want %v 34ms 1", h.LastOK, h.RTT, h.Fails, testTime(20*time.Second))
	}
	h = h.Observe(Sample{At: testTime(40 * time.Second), Ping: noPing})
	if h.Fails != 1 || !h.LastOK.Equal(testTime(20*time.Second)) {
		t.Errorf("after no ping: Fails %d LastOK %v, want 1 %v", h.Fails, h.LastOK, testTime(20*time.Second))
	}
}

// The reason of a dead active check tells of
// the 3 failures (status sample "ping 1.1.1.1: 3 failures").
func TestHealthPingReason(t *testing.T) {
	defer noPanic(t)
	h := New(t0)
	for i := 1; i <= FailsToDead; i++ {
		h = h.Observe(Sample{At: testTime(time.Duration(i) * Interval), Ping: pingFail})
	}
	if h.State != Dead || !strings.Contains(h.Reason, "3 failures") {
		t.Errorf("State %s Reason %q, want Dead with \"3 failures\"", stateName(h.State), h.Reason)
	}
}

// --- passive check ------------------------------------------------------------------

// design 9 "Пассивная проверка — точнее": dead when on two
// polls in a row tx grew and rx did not, and the handshake (not earlier than
// up or reset) is older than 180 s; alive when rx grew or the handshake is at
// most 180 s old; no traffic — no change. The first poll only records tx/rx.
func TestHealthPassive(t *testing.T) {
	defer noPanic(t)
	s := time.Second
	hs60 := testTime(60 * s)
	cases := []struct {
		name  string
		steps []step
	}{
		{"no traffic for 10 minutes: never dead", func() []step {
			var st []step
			for i := 1; i <= 60; i++ {
				st = append(st, step{at: time.Duration(i) * Interval, tx: 500, rx: 300, want: Unknown})
			}
			return st
		}()},
		{"tx grows without rx, never a handshake: the window runs from up", []step{
			{at: 10 * s, tx: 0, want: Unknown}, // base
			{at: 100 * s, tx: 148, want: Unknown},
			{at: 180 * s, tx: 296, want: Unknown}, // exactly 180 s: not older
			{at: 190 * s, tx: 444, want: Dead},
			{at: 200 * s, tx: 444, want: Dead},          // no traffic: verdict stays
			{at: 210 * s, tx: 592, rx: 32, want: Alive}, // rx grew: evidence of life
		}},
		{"handshake before up counts from up", []step{
			{at: 10 * s, hs: testTime(-time.Hour), tx: 0, want: Unknown},
			{at: 180 * s, hs: testTime(-time.Hour), tx: 100, want: Unknown},
			{at: 190 * s, hs: testTime(-time.Hour), tx: 200, want: Dead},
		}},
		{"tx grows without rx after a handshake: 180 s from it", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 70 * s, hs: hs60, tx: 100, rx: 0, want: Alive},
			{at: 240 * s, hs: hs60, tx: 200, rx: 0, want: Alive}, // 180 s: fresh
			{at: 250 * s, hs: hs60, tx: 300, rx: 0, want: Dead},  // 190 s
		}},
		{"rx grows: alive even with an old handshake", []step{
			{at: 10 * s, tx: 100, rx: 100, want: Unknown},
			{at: 10 * time.Minute, tx: 200, rx: 101, want: Alive},
			{at: 20 * time.Minute, tx: 300, rx: 102, want: Alive},
		}},
		{"fresh handshake without traffic: alive", []step{
			{at: 10 * s, tx: 10, rx: 10, want: Unknown},
			{at: 20 * s, hs: testTime(15 * s), tx: 10, rx: 10, want: Alive},
		}},
		{"first poll only records: old traffic is not growth", []step{
			{at: 10 * time.Minute, tx: 1000, rx: 0, want: Unknown},
			{at: 10*time.Minute + 10*s, tx: 1000, rx: 0, want: Unknown},
			{at: 10*time.Minute + 20*s, tx: 1001, rx: 0, want: Unknown}, // one poll: not enough
			{at: 10*time.Minute + 30*s, tx: 1002, rx: 0, want: Dead},
		}},
		{"first poll only records: rx is not growth either", []step{
			{at: 10 * time.Minute, tx: 0, rx: 500, want: Unknown},
			{at: 10*time.Minute + 10*s, tx: 0, rx: 500, want: Unknown},
		}},
	}
	for _, c := range cases {
		run(t, c.name, New(t0), c.steps)
	}
}

// A poll with tx growth and no rx growth at an old handshake
// counts; dead needs two such polls in a row. A poll where rx grew or tx did
// not zeroes the count; the first poll after New or Reset is the base and
// does not count.
func TestHealthPassiveTwoPolls(t *testing.T) {
	defer noPanic(t)
	s := time.Second
	cases := []struct {
		name  string
		steps []step
	}{
		{"one poll with tx growth at an old handshake: not dead", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 148, want: Unknown},
			{at: 210 * s, tx: 148, want: Unknown}, // no traffic: verdict stays
		}},
		{"two polls in a row: dead", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 148, want: Unknown},
			{at: 210 * s, tx: 296, want: Dead},
		}},
		{"rx growth in between zeroes the count", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 148, want: Unknown},
			{at: 210 * s, tx: 296, rx: 92, want: Alive},
			{at: 220 * s, tx: 444, rx: 92, want: Alive}, // count 1: verdict stays
			{at: 230 * s, tx: 592, rx: 92, want: Dead},  // count 2
		}},
		{"tx and rx growing together zero the count", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 148, want: Unknown},
			{at: 210 * s, tx: 296, rx: 1, want: Alive},
			{at: 220 * s, tx: 444, rx: 1, want: Alive},
		}},
		{"a poll without tx growth in between zeroes the count", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 148, want: Unknown},
			{at: 210 * s, tx: 148, want: Unknown},
			{at: 220 * s, tx: 296, want: Unknown}, // count 1 again
			{at: 230 * s, tx: 444, want: Dead},
		}},
		// The count does not depend on the handshake being fresh: a poll at
		// hs+175 s counts, the one at hs+185 s is the second.
		{"a poll with a fresh handshake counts", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 20 * s, hs: testTime(20 * s), tx: 148, rx: 92, want: Alive},
			{at: 195 * s, hs: testTime(20 * s), tx: 296, rx: 92, want: Alive}, // count 1, hs 175 s old
			{at: 205 * s, hs: testTime(20 * s), tx: 444, rx: 92, want: Dead},  // count 2, hs 185 s old
		}},
		{"rx growth between the fresh and the old poll zeroes the count", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 20 * s, hs: testTime(20 * s), tx: 148, rx: 92, want: Alive},
			{at: 195 * s, hs: testTime(20 * s), tx: 296, rx: 92, want: Alive},  // count 1
			{at: 200 * s, hs: testTime(20 * s), tx: 296, rx: 184, want: Alive}, // rx grew: count 0
			{at: 205 * s, hs: testTime(20 * s), tx: 444, rx: 184, want: Alive}, // count 1
		}},
		{"alternating growth and quiet: never dead", []step{
			{at: 10 * s, want: Unknown}, // base
			{at: 200 * s, tx: 100, want: Unknown},
			{at: 210 * s, tx: 100, want: Unknown},
			{at: 220 * s, tx: 200, want: Unknown},
			{at: 230 * s, tx: 200, want: Unknown},
			{at: 240 * s, tx: 300, want: Unknown},
			{at: 250 * s, tx: 300, want: Unknown},
		}},
	}
	for _, c := range cases {
		run(t, c.name, New(t0), c.steps)
	}
}

// design 9 "Сброс": the first poll after Reset is the base;
// tx growth against the counters before the reset does not count, and the
// count of before the reset does not carry over.
func TestHealthPassiveTwoPollsReset(t *testing.T) {
	defer noPanic(t)
	s := time.Second
	h := run(t, "before reset", New(t0), []step{
		{at: 10 * s, want: Unknown}, // base
		{at: 200 * s, tx: 100, want: Unknown},
	})
	r := 205 * s
	h = h.Reset(testTime(r))
	run(t, "after reset", h, []step{
		{at: r + 10*s, tx: 500, want: Unknown},  // base: growth since 200 s does not count
		{at: r + 190*s, tx: 600, want: Unknown}, // count 1
		{at: r + 200*s, tx: 700, want: Dead},    // count 2
	})
}

// `no handshake for 3m10s while sending`.
func TestHealthPassiveReason(t *testing.T) {
	defer noPanic(t)
	hs := testTime(60 * time.Second)
	h := run(t, "reason", New(t0), []step{
		{at: 10 * time.Second, want: Unknown},
		{at: 70 * time.Second, hs: hs, tx: 100, want: Alive},
		{at: 250 * time.Second, hs: hs, tx: 200, want: Dead},
	})
	if !strings.Contains(h.Reason, "no handshake for 3m10s") {
		t.Errorf("Reason %q, want \"no handshake for 3m10s ...\"", h.Reason)
	}
}

// design 9 "Итоговый вердикт": dead when any verdict is dead.
func TestHealthVerdictsOR(t *testing.T) {
	defer noPanic(t)
	s := time.Second
	ok := pingOK(10 * time.Millisecond)

	// Ping succeeds every time, but data does not pass: dead.
	h := run(t, "ping OK, passive dead", New(t0), []step{
		{at: 10 * s, ping: ok, want: Alive},
		{at: 100 * s, tx: 100, ping: ok, want: Alive},
		{at: 190 * s, tx: 200, ping: ok, want: Dead},
		{at: 200 * s, tx: 300, ping: ok, want: Dead},
	})
	if !strings.Contains(h.Reason, "no handshake") {
		t.Errorf("ping OK, passive dead: Reason %q, want the passive one", h.Reason)
	}

	// Data passes, ping fails 3 times: dead.
	hs := func(d time.Duration) time.Time { return testTime(d) }
	h = run(t, "passive alive, ping dead", New(t0), []step{
		{at: 10 * s, tx: 10, rx: 10, ping: pingFail, want: Unknown}, // base
		{at: 20 * s, hs: hs(15 * s), tx: 20, rx: 20, ping: pingFail, want: Alive},
		{at: 30 * s, hs: hs(15 * s), tx: 30, rx: 30, ping: pingFail, want: Dead},
		{at: 40 * s, hs: hs(15 * s), tx: 40, rx: 40, ping: ok, want: Alive},
	})
	if h.Fails != 0 {
		t.Errorf("passive alive, ping dead, then OK: Fails %d, want 0", h.Fails)
	}
}

// --- Reset ---------------------------------------------------------------------------

// design 9 "Сброс": after a wake the handshake is hours old (wall time), but
// the window runs from the reset: no false "dead" for 180 s.
func TestHealthResetAfterSleep(t *testing.T) {
	defer noPanic(t)
	s := time.Second
	hs := testTime(5 * s)
	h := run(t, "before sleep", New(t0), []step{
		{at: 10 * s, tx: 100, rx: 100, want: Unknown}, // base
		{at: 20 * s, hs: hs, tx: 200, rx: 200, want: Alive},
	})
	wake := 2 * time.Hour

	// Control: without Reset two polls after the wake see tx grow, no rx and
	// an old handshake: dead on the second.
	run(t, "no reset", h, []step{
		{at: wake + 10*s, hs: hs, tx: 300, rx: 200, want: Alive},
		{at: wake + 20*s, hs: hs, tx: 400, rx: 200, want: Dead},
	})

	h = h.Reset(testTime(wake))
	if h.State != Alive || h.Fails != 0 {
		t.Errorf("after Reset: State %s Fails %d, want Alive 0 (verdicts stay)", stateName(h.State), h.Fails)
	}
	run(t, "after reset", h, []step{
		{at: wake + 10*s, hs: hs, tx: 300, rx: 200, want: Alive}, // base
		{at: wake + 20*s, hs: hs, tx: 400, rx: 200, want: Alive},
		{at: wake + 180*s, hs: hs, tx: 500, rx: 200, want: Alive},
		{at: wake + 190*s, hs: hs, tx: 600, rx: 200, want: Dead},
	})
}

// design 9 "Сброс": the reset zeroes the failure counter.
func TestHealthResetFails(t *testing.T) {
	defer noPanic(t)
	h := New(t0)
	h = h.Observe(Sample{At: testTime(10 * time.Second), Ping: pingFail})
	h = h.Observe(Sample{At: testTime(20 * time.Second), Ping: pingFail})
	h = h.Reset(testTime(25 * time.Second))
	if h.Fails != 0 {
		t.Errorf("after Reset: Fails %d, want 0", h.Fails)
	}
	h = h.Observe(Sample{At: testTime(30 * time.Second), Ping: pingFail})
	if h.State == Dead || h.Fails != 1 {
		t.Errorf("2 failures, Reset, 1 failure: State %s Fails %d, want not dead, 1", stateName(h.State), h.Fails)
	}
	h = h.Observe(Sample{At: testTime(40 * time.Second), Ping: pingFail})
	h = h.Observe(Sample{At: testTime(50 * time.Second), Ping: pingFail})
	if h.State != Dead {
		t.Errorf("3 failures after Reset: State %s, want Dead", stateName(h.State))
	}
}

// design 9 "Сброс": a dead tunnel stays dead until evidence of life.
func TestHealthResetKeepsDead(t *testing.T) {
	defer noPanic(t)
	s := time.Second

	// Dead by ping.
	h := New(t0)
	for i := 1; i <= FailsToDead; i++ {
		h = h.Observe(Sample{At: testTime(time.Duration(i) * Interval), Ping: pingFail})
	}
	h = h.Reset(testTime(35 * s))
	if h.State != Dead || h.Alive() || h.Fails != 0 {
		t.Errorf("ping dead, Reset: State %s Alive %v Fails %d, want Dead false 0", stateName(h.State), h.Alive(), h.Fails)
	}
	h = run(t, "ping dead, reset", h, []step{
		{at: 40 * s, want: Dead},
		{at: 50 * s, want: Dead},
		{at: 60 * s, ping: pingOK(20 * time.Millisecond), want: Alive},
	})

	// Dead by the passive check; after Reset the first poll is the base, rx
	// growth after it revives.
	h = run(t, "passive dead", New(t0), []step{
		{at: 10 * s, want: Unknown},
		{at: 180 * s, tx: 50, want: Unknown},
		{at: 190 * s, tx: 100, want: Dead},
	})
	h = h.Reset(testTime(200 * s))
	if h.State != Dead {
		t.Errorf("passive dead, Reset: State %s, want Dead", stateName(h.State))
	}
	run(t, "passive dead, reset", h, []step{
		{at: 210 * s, tx: 100, want: Dead},
		{at: 220 * s, tx: 100, want: Dead},
		{at: 230 * s, tx: 100, rx: 64, want: Alive},
	})
}

// --- Poke ------------------------------------------------------------------------------

// design 9 "Повторный handshake": a dead tunnel is poked at most every 30 s;
// a tunnel not dead never.
func TestHealthPoke(t *testing.T) {
	defer noPanic(t)
	h := New(t0)
	if _, due := h.Poke(testTime(time.Hour)); due {
		t.Error("Unknown: Poke due, want never")
	}
	alive := h.Observe(Sample{At: testTime(10 * time.Second), Ping: pingOK(time.Millisecond)})
	if _, due := alive.Poke(testTime(time.Hour)); due {
		t.Error("Alive: Poke due, want never")
	}

	dead := h
	for i := 1; i <= FailsToDead; i++ {
		dead = dead.Observe(Sample{At: testTime(time.Duration(i) * Interval), Ping: pingFail})
	}
	if dead.State != Dead {
		t.Fatalf("fixture: State %s, want Dead", stateName(dead.State))
	}
	td := testTime(30 * time.Second) // dead since
	steps := []struct {
		at   time.Duration // since td
		want bool
	}{
		{PokeEvery, true},
		{PokeEvery + time.Second, false},
		{2*PokeEvery - time.Second, false},
		{2 * PokeEvery, true},
		{2*PokeEvery + 10*time.Second, false},
		{4 * PokeEvery, true},
	}
	cur := dead
	for _, st := range steps {
		var due bool
		cur, due = cur.Poke(td.Add(st.at))
		if due != st.want {
			t.Errorf("Poke at dead+%v: %v, want %v", st.at, due, st.want)
		}
		if cur.State != Dead {
			t.Errorf("Poke changed State to %s", stateName(cur.State))
		}
	}

	// Revived: no more pokes.
	revived := cur.Observe(Sample{At: td.Add(5 * PokeEvery), Ping: pingOK(time.Millisecond)})
	if _, due := revived.Poke(td.Add(10 * PokeEvery)); due {
		t.Error("revived: Poke due, want never")
	}
}

// --- SampleOf --------------------------------------------------------------------------

// SampleOf takes the newest handshake and the sums of tx/rx.
func TestSampleOf(t *testing.T) {
	defer noPanic(t)
	at := testTime(time.Minute)
	ping := pingOK(7 * time.Millisecond)
	cases := []struct {
		name   string
		peers  []tunnel.PeerStats
		hs     time.Time
		tx, rx uint64
	}{
		{"none", nil, time.Time{}, 0, 0},
		{"one", []tunnel.PeerStats{{LastHandshake: testTime(10 * time.Second), RxBytes: 5, TxBytes: 7}}, testTime(10 * time.Second), 7, 5},
		{"newest of several, sums", []tunnel.PeerStats{
			{LastHandshake: testTime(10 * time.Second), RxBytes: 10, TxBytes: 20},
			{RxBytes: 5, TxBytes: 7}, // never
			{LastHandshake: testTime(40 * time.Second), RxBytes: 1, TxBytes: 1},
			{LastHandshake: testTime(-time.Hour), RxBytes: 1 << 40, TxBytes: 1 << 41},
		}, testTime(40 * time.Second), 20 + 7 + 1 + 1<<41, 10 + 5 + 1 + 1<<40},
		{"all never", []tunnel.PeerStats{{TxBytes: 92}, {}}, time.Time{}, 92, 0},
	}
	for _, c := range cases {
		s := SampleOf(at, c.peers, ping)
		if !s.At.Equal(at) {
			t.Errorf("%s: At %v, want %v", c.name, s.At, at)
		}
		if !s.Handshake.Equal(c.hs) || s.Handshake.IsZero() != c.hs.IsZero() {
			t.Errorf("%s: Handshake %v, want %v", c.name, s.Handshake, c.hs)
		}
		if s.Tx != c.tx || s.Rx != c.rx {
			t.Errorf("%s: Tx %d Rx %d, want %d %d", c.name, s.Tx, s.Rx, c.tx, c.rx)
		}
		if s.Ping != ping {
			t.Errorf("%s: Ping %+v, want %+v", c.name, s.Ping, ping)
		}
	}
}
