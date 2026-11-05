package health

import (
	"testing"
	"time"
)

// Tests follow design 9.2 (return to a priority tunnel), not the implementation.
// A tunnel may take rules back only when its active check has been Alive for
// ReturnAfter (5 minutes) in a row. Times are offsets from t0 (health_test.go).

// rtnFeed feeds ok pings every Interval from..to (inclusive) and returns the result.
func rtnFeed(h Health, from, to time.Duration) Health {
	for at := from; at <= to; at += Interval {
		h = h.Observe(Sample{At: testTime(at), Ping: pingOK(time.Millisecond)})
	}
	return h
}

func rtnWant(t *testing.T, h Health, at time.Duration, want bool, what string) {
	t.Helper()
	defer noPanic(t)
	if got := h.Returnable(testTime(at)); got != want {
		t.Errorf("%s: Returnable(+%v) = %v, want %v", what, at, got, want)
	}
}

func TestReturnAfterIsFiveMinutes(t *testing.T) {
	if ReturnAfter != 5*time.Minute {
		t.Errorf("ReturnAfter = %v, want 5m (design 9.2)", ReturnAfter)
	}
}

func TestReturnable(t *testing.T) {
	first := 10 * time.Second // the first successful ping

	t.Run("design 9.2: 4:59 no, 5:00 yes", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, first+ReturnAfter)
		rtnWant(t, h, first+ReturnAfter-time.Second, false, "4:59 after first success")
		rtnWant(t, h, first+ReturnAfter, true, "5:00 after first success")
		rtnWant(t, h, first+ReturnAfter+time.Hour, true, "much later")
	})

	t.Run("design 9.2: just after the first success is not enough", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, first)
		rtnWant(t, h, first, false, "at the first success")
		rtnWant(t, h, first+time.Minute, false, "1 min")
	})

	t.Run("design 9.2: unknown after New does not count", func(t *testing.T) {
		h := New(testTime(0))
		rtnWant(t, h, 0, false, "fresh")
		rtnWant(t, h, time.Hour, false, "an hour of Unknown")
	})

	t.Run("design 9.2: no check, only passive alive: never", func(t *testing.T) {
		h := New(testTime(0))
		var rx uint64
		for at := 10 * time.Second; at <= 20*time.Minute; at += Interval {
			rx += 100
			h = h.Observe(Sample{At: testTime(at), Handshake: testTime(at - time.Second), Tx: rx, Rx: rx, Ping: noPing})
		}
		if !h.Alive() {
			t.Fatalf("setup: passive evidence should make the tunnel Alive, state %v", h.State)
		}
		rtnWant(t, h, 20*time.Minute, false, "passive Alive")
		rtnWant(t, h, 24*time.Hour, false, "passive Alive, much later")
	})

	t.Run("design 9.2: passive alive does not start the countdown of the check", func(t *testing.T) {
		// Passive Alive for 10 minutes, then the first ping success: count from it.
		h := New(testTime(0))
		var rx uint64
		for at := 10 * time.Second; at < 10*time.Minute; at += Interval {
			rx += 100
			h = h.Observe(Sample{At: testTime(at), Handshake: testTime(at), Tx: rx, Rx: rx, Ping: noPing})
		}
		okAt := 10 * time.Minute
		h = h.Observe(Sample{At: testTime(okAt), Handshake: testTime(okAt), Tx: rx, Rx: rx, Ping: pingOK(time.Millisecond)})
		rtnWant(t, h, okAt+ReturnAfter-time.Second, false, "4:59 after the first ping success")
		rtnWant(t, h, okAt+ReturnAfter, true, "5:00 after the first ping success")
	})

	t.Run("design 9.2: a failure mid-countdown restarts it from the next success", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, 2*time.Minute)
		// One failed ping: below FailsToDead, the verdict stays Alive, the countdown is gone.
		failAt := 2*time.Minute + Interval
		h = h.Observe(Sample{At: testTime(failAt), Ping: pingFail})
		if !h.Alive() {
			t.Fatalf("setup: one failure must not kill the tunnel, state %v", h.State)
		}
		okAt := failAt + Interval
		h = rtnFeed(h, okAt, okAt+ReturnAfter)
		// Counting from the first success would have been satisfied long ago.
		rtnWant(t, h, first+ReturnAfter, false, "5:00 from the original first success")
		rtnWant(t, h, okAt+ReturnAfter-time.Second, false, "4:59 after the success that followed the failure")
		rtnWant(t, h, okAt+ReturnAfter, true, "5:00 after the success that followed the failure")
	})

	t.Run("design 9.2: a failure right before 5:00 resets the countdown", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, first+ReturnAfter-Interval)
		failAt := first + ReturnAfter - 5*time.Second
		h = h.Observe(Sample{At: testTime(failAt), Ping: pingFail})
		rtnWant(t, h, first+ReturnAfter, false, "after a failure at 4:55")
		rtnWant(t, h, first+ReturnAfter+time.Hour, false, "no new success yet")
	})

	t.Run("design 9: dead is never returnable, recovery counts from the first success", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, first+ReturnAfter)
		deadAt := first + ReturnAfter + Interval
		for i := 0; i < FailsToDead; i++ {
			h = h.Observe(Sample{At: testTime(deadAt + time.Duration(i)*Interval), Ping: pingFail})
		}
		if h.State != Dead {
			t.Fatalf("setup: want Dead after %d failures, state %v", FailsToDead, h.State)
		}
		rtnWant(t, h, deadAt+time.Hour, false, "dead")

		okAt := deadAt + time.Hour
		h = rtnFeed(h, okAt, okAt+ReturnAfter)
		rtnWant(t, h, okAt+ReturnAfter-time.Second, false, "4:59 after recovery")
		rtnWant(t, h, okAt+ReturnAfter, true, "5:00 after recovery")
	})
}

func TestReturnableReset(t *testing.T) {
	first := 10 * time.Second

	t.Run("design 9.2: reset (network change, wake) restarts the countdown from the reset", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, first+ReturnAfter)
		rtnWant(t, h, first+ReturnAfter, true, "before the reset")

		resetAt := first + ReturnAfter + time.Minute
		h = h.Reset(testTime(resetAt))
		if !h.Alive() {
			t.Fatalf("setup: Reset keeps the verdict, state %v", h.State)
		}
		rtnWant(t, h, resetAt, false, "right after reset")
		rtnWant(t, h, resetAt+ReturnAfter-time.Second, false, "4:59 after reset")
		rtnWant(t, h, resetAt+ReturnAfter, true, "5:00 after reset")
	})

	t.Run("design 9.2: reset mid-countdown", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, 4*time.Minute)
		resetAt := 4 * time.Minute
		h = h.Reset(testTime(resetAt))
		// The original countdown would be done at first+5m; the reset moved it.
		rtnWant(t, h, first+ReturnAfter, false, "original deadline")
		rtnWant(t, h, resetAt+ReturnAfter-time.Second, false, "4:59 after reset")
		rtnWant(t, h, resetAt+ReturnAfter, true, "5:00 after reset")
	})

	t.Run("design 9.2: reset with live pings afterwards still counts from the reset", func(t *testing.T) {
		h := rtnFeed(New(testTime(0)), first, 4*time.Minute)
		resetAt := 4 * time.Minute
		h = h.Reset(testTime(resetAt))
		h = rtnFeed(h, resetAt+Interval, resetAt+ReturnAfter)
		rtnWant(t, h, resetAt+ReturnAfter-time.Second, false, "4:59 after reset")
		rtnWant(t, h, resetAt+ReturnAfter, true, "5:00 after reset")
	})

	t.Run("design 9.2: reset of an unknown tunnel gives no countdown", func(t *testing.T) {
		h := New(testTime(0)).Reset(testTime(time.Minute))
		rtnWant(t, h, time.Minute+ReturnAfter, false, "5:00 after reset of Unknown")
		rtnWant(t, h, time.Hour, false, "an hour later")
	})

	t.Run("design 9: reset of a dead tunnel keeps it not returnable", func(t *testing.T) {
		h := New(testTime(0))
		for i := 0; i < FailsToDead; i++ {
			h = h.Observe(Sample{At: testTime(time.Duration(i+1) * Interval), Ping: pingFail})
		}
		if h.State != Dead {
			t.Fatalf("setup: want Dead, state %v", h.State)
		}
		h = h.Reset(testTime(time.Minute))
		rtnWant(t, h, time.Minute+ReturnAfter, false, "dead after reset")
		rtnWant(t, h, time.Hour, false, "dead, much later")
	})

	t.Run("design 9.2: reset of a passive-only Alive tunnel gives no countdown", func(t *testing.T) {
		h := New(testTime(0)).Observe(Sample{At: testTime(10 * time.Second), Handshake: testTime(5 * time.Second), Tx: 1, Rx: 1, Ping: noPing})
		if !h.Alive() {
			t.Fatalf("setup: fresh handshake makes the tunnel Alive, state %v", h.State)
		}
		h = h.Reset(testTime(time.Minute))
		rtnWant(t, h, time.Minute+ReturnAfter, false, "passive only")
	})
}
