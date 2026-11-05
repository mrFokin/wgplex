package netwatch

import (
	"context"
	"log/slog"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// watchKeys gives the global keys and the capture key, and the service
// patterns (anchored, whole keys) for SCDynamicStoreSetNotificationKeys.
func TestWatchKeys(t *testing.T) {
	defer noPanic(t)
	keyList, patternList := watchKeys(captureKey)

	keys := map[string]bool{}
	for _, k := range keyList {
		keys[k] = true
	}
	var patterns []*regexp.Regexp
	for _, p := range patternList {
		if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
			t.Errorf("pattern %q: want anchored with ^…$", p)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			t.Errorf("pattern %q: %v", p, err)
			continue
		}
		patterns = append(patterns, re)
	}

	for _, k := range []string{
		"State:/Network/Global/IPv4",
		"State:/Network/Global/IPv6",
		"State:/Network/Global/DNS",
		captureKey,
	} {
		if !keys[k] {
			t.Errorf("key %q not watched; keys %q", k, keyList)
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
		// Not ours: AirPort noise, other entities.
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

// The capture key passed in is the one watched (not a fixed one).
func TestWatchKeysCaptureKey(t *testing.T) {
	defer noPanic(t)
	const other = "State:/Network/Service/00000000-0000-0000-0000-000000000000/DNS"
	keys, _ := watchKeys(other)
	if !slices.Contains(keys, other) {
		t.Errorf("keys %q: want %q", keys, other)
	}
}

// Watch creates an SC session (no root needed) and, when ctx is done,
// stops the run loop and closes the channel promptly.
func TestWatchStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := Watch(ctx, captureKey, slog.New(slog.DiscardHandler))
	time.Sleep(200 * time.Millisecond) // let the run loop start
	cancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed 2 s after cancel")
		}
	}
}

// watchOnce on a live session returns nil soon after ctx is done (the run
// loop is stopped, not left to time out).
func TestWatchOnceStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		done <- watchOnce(ctx, captureKey, make(chan Event, 64), false)
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watchOnce: %v", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("watchOnce returned %v after cancel, want promptly", d)
		}
	case <-time.After(2 * probeEvery):
		t.Fatal("watchOnce did not return after cancel")
	}
}
