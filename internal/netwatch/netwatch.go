// Package netwatch reports the events the daemon reacts to (design 6, 8,
// 10): network changes, the DNS capture key, wake from sleep and a periodic
// resync. The parsing of scutil output, the mapping of keys to events and
// the debouncing are pure; Watch (watch_darwin.go) runs scutil.
package netwatch

import (
	"regexp"
	"strings"
	"time"
)

// Event is a bit mask of events.
type Event uint8

const (
	Network Event = 1 << iota // global or service IPv4/IPv6/DNS keys changed
	Capture                   // the DNS capture key changed
	Wake                      // the machine slept
	Resync                    // periodic or after a scutil restart
)

// String formats e for logs: "network|wake"; "none" for 0.
func (e Event) String() string {
	var names []string
	for i, n := range []string{"network", "capture", "wake", "resync"} {
		if e&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}

// The keys and patterns watched (Netwatch model of the Wirefork M7 plan); a pattern
// is a regex(3) one for scutil "n.add <pattern> pattern" and matches whole
// keys. AirPort keys are noise and are not watched (Wirefork M7 fact 3).

var (
	networkKeys     = []string{"State:/Network/Global/IPv4", "State:/Network/Global/IPv6", "State:/Network/Global/DNS"}
	networkPatterns = []string{
		"^State:/Network/Service/[^/]+/(IPv4|IPv6|DNS)$",
		"^Setup:/Network/Service/[^/]+/DNS$",
	}
	networkRes = func() []*regexp.Regexp {
		res := make([]*regexp.Regexp, len(networkPatterns))
		for i, p := range networkPatterns {
			res[i] = regexp.MustCompile(p)
		}
		return res
	}()
)

// parseChangedKey returns the key of a `scutil` n.watch line
// "  14:36:45.351 (+0.000) changedKey [1] = <key>", exactly as printed
// (a trailing space kept); ok false for any other line.
func parseChangedKey(line string) (key string, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	_, rest, ok := strings.Cut(line, "changedKey [")
	if !ok {
		return "", false
	}
	_, key, ok = strings.Cut(rest, "] = ")
	if !ok || key == "" {
		return "", false
	}
	return key, true
}

// classify maps a changed key to its event; 0: not ours. The capture key is
// compared first: it has the form of a service DNS key.
func classify(key, captureKey string) Event {
	switch {
	case key == captureKey:
		return Capture
	}
	for _, k := range networkKeys {
		if key == k {
			return Network
		}
	}
	for _, re := range networkRes {
		if re.MatchString(key) {
			return Network
		}
	}
	return 0
}

// debouncer merges events: due after quiet without new ones, or max after
// the first one.
type debouncer struct {
	quiet, max  time.Duration
	first, last time.Time // of the pending events
	pending     Event
}

func newDebouncer(quiet, max time.Duration) *debouncer {
	return &debouncer{quiet: quiet, max: max}
}

// add records e at now; 0 is ignored.
func (d *debouncer) add(now time.Time, e Event) {
	if e == 0 {
		return
	}
	if d.pending == 0 {
		d.first = now
	}
	d.last = now
	d.pending |= e
}

// due returns the pending events when due at now (0: none or not yet) and
// when to look again (zero: nothing pending).
func (d *debouncer) due(now time.Time) (Event, time.Time) {
	if d.pending == 0 {
		return 0, time.Time{}
	}
	at := d.last.Add(d.quiet)
	if limit := d.first.Add(d.max); limit.Before(at) {
		at = limit
	}
	if now.Before(at) {
		return 0, at
	}
	e := d.pending
	d.pending = 0
	return e, time.Time{}
}

// sleepJump is how much more wall time than monotonic time between two
// ticks means a sleep (design 6).
const sleepJump = 5 * time.Second

// slept reports a sleep between two ticks: wall − mono > 5 s.
func slept(wall, mono time.Duration) bool {
	return wall-mono > sleepJump
}
