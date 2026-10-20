// Package health decides whether a tunnel is alive (design 8): an active
// check (ping of the check address through the tunnel) and a passive one
// (handshake age and tx/rx growth). Health is a pure value; the pings are
// made by Pinger (ping_darwin.go).
package health

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/mrFokin/wgplex/internal/tunnel"
)

const (
	Interval         = 10 * time.Second  // design 8
	FailsToDead      = 3                 // consecutive ping failures
	HandshakeTimeout = 180 * time.Second // design 8 "~3 minutes"
	PingTimeout      = 3 * time.Second
	HTTPTimeout      = 5 * time.Second  // the whole HTTP check (design 8)
	PokeEvery        = 30 * time.Second // handshake attempts of a dead tunnel
	StrikesToDead    = 2                // passive: polls in a row sending without receiving
)

// State is the verdict of Health.
type State uint8

const (
	Unknown State = iota // no evidence yet; routable
	Alive
	Dead
)

// Checker is the active check of a tunnel: Pinger or HTTPChecker.
type Checker interface {
	Check(ctx context.Context) PingResult
	Close() error
}

// PingResult is the outcome of one active check (ping or HTTP) in a Sample.
type PingResult struct {
	Done bool          // a check was made (check set and checkable)
	OK   bool          // an echo reply or an HTTP response came in time
	RTT  time.Duration // OK only
	Err  string        // !OK: why, for Reason (HTTP check only); "" for ping
}

// Sample is one poll of a running tunnel. At is wall time (Round(0)).
type Sample struct {
	At        time.Time
	Handshake time.Time // the newest of its peers; zero: never
	Tx, Rx    uint64    // sums over its peers
	Ping      PingResult
	Check     netip.Addr // the pinged address, for Reason; may be zero
	URL       string     // the HTTP check URL, for Reason; "" for ping
}

// Health is the verdict on one tunnel (decision 1); a value, Observe and
// Reset return the next one.
//
// The active verdict comes from pings: OK makes it Alive and zeroes Fails,
// FailsToDead failures in a row make it Dead. With URL set the reason is
// "http <url>: N failures" plus " (<Err>)" when Err is not empty; otherwise
// "ping <check>: N failures". The passive verdict comes from
// the sample (decision 11): Alive when rx grew since the last poll or the
// handshake is at most HandshakeTimeout old; Dead when on StrikesToDead
// polls in a row tx grew and rx did not, and At − ref > HandshakeTimeout on
// the current poll, where ref = max(handshake, since); otherwise unchanged.
// One such poll is not enough: leaving idle, a poll may fall between a
// handshake initiation and its response. Only a poll where rx grew or tx did
// not zeroes the count; the handshake age does not affect it, only the
// verdict. The first poll after New or Reset only records
// tx/rx (the count starts at 0). State is Dead when any verdict is Dead,
// Alive when some verdict is Alive and none Dead, Unknown otherwise.
type Health struct {
	State  State
	Reason string        // Dead: why, for status
	Fails  int           // consecutive ping failures
	LastOK time.Time     // the last successful ping
	RTT    time.Duration // of the last successful ping

	since   time.Time // up or the last Reset: the start of the passive window
	base    bool      // tx, rx hold a previous poll
	strikes int       // polls in a row where tx grew and rx did not
	tx, rx  uint64    // sums of the previous poll
	active  State     // verdict of the pings
	passive State     // verdict of handshake and traffic
	poked   time.Time // the last handshake attempt of Poke

	activeWhy, passiveWhy string // the reason of a Dead verdict
}

// New returns the Health of a tunnel brought up at up: Unknown, routable.
func New(up time.Time) Health {
	return Health{since: up.Round(0)}
}

// Observe returns h after the poll s.
func (h Health) Observe(s Sample) Health {
	at := s.At.Round(0)

	if s.Ping.Done {
		if s.Ping.OK {
			h.Fails, h.LastOK, h.RTT = 0, at, s.Ping.RTT
			h.active, h.activeWhy = Alive, ""
		} else {
			h.Fails++
			if h.Fails >= FailsToDead {
				h.active = Dead
				switch {
				case s.URL != "":
					h.activeWhy = fmt.Sprintf("http %s: %d failures", s.URL, h.Fails)
					if s.Ping.Err != "" {
						h.activeWhy += " (" + s.Ping.Err + ")"
					}
				case s.Check.IsValid():
					h.activeWhy = fmt.Sprintf("ping %s: %d failures", s.Check, h.Fails)
				default:
					h.activeWhy = fmt.Sprintf("ping: %d failures", h.Fails)
				}
			}
		}
	}

	if h.base {
		hs := s.Handshake.Round(0)
		rxGrew, txGrew := s.Rx > h.rx, s.Tx > h.tx
		fresh := !hs.IsZero() && at.Sub(hs) <= HandshakeTimeout
		ref := h.since
		if hs.After(ref) {
			ref = hs
		}
		if txGrew && !rxGrew {
			h.strikes++
		} else {
			h.strikes = 0
		}
		switch {
		case rxGrew || fresh:
			h.passive, h.passiveWhy = Alive, ""
		case h.strikes >= StrikesToDead && at.Sub(ref) > HandshakeTimeout:
			h.passive = Dead
			h.passiveWhy = fmt.Sprintf("no handshake for %s while sending", at.Sub(ref).Truncate(time.Second))
		}
	}
	h.tx, h.rx, h.base = s.Tx, s.Rx, true

	return h.decide()
}

// decide sets State and Reason from the verdicts.
func (h Health) decide() Health {
	switch {
	case h.active == Dead && h.passive == Dead:
		h.State, h.Reason = Dead, h.activeWhy+"; "+h.passiveWhy
	case h.active == Dead:
		h.State, h.Reason = Dead, h.activeWhy
	case h.passive == Dead:
		h.State, h.Reason = Dead, h.passiveWhy
	case h.active == Alive || h.passive == Alive:
		h.State, h.Reason = Alive, ""
	default:
		h.State, h.Reason = Unknown, ""
	}
	return h
}

// Reset returns h after a network change or a wake at at: the passive
// window starts at at, the tx/rx base and the passive count are forgotten,
// Fails is 0; the verdicts stay (a dead tunnel stays dead until evidence of
// life).
func (h Health) Reset(at time.Time) Health {
	h.since = at.Round(0)
	h.base, h.tx, h.rx, h.strikes = false, 0, 0, 0
	h.Fails = 0
	return h
}

// Alive reports whether the tunnel is routable: State != Dead.
func (h Health) Alive() bool {
	return h.State != Dead
}

// Poke reports whether a dead tunnel is due a handshake attempt at now
// (PokeEvery since the last one) and returns h with the attempt recorded.
// It is always false for a tunnel not Dead.
func (h Health) Poke(now time.Time) (Health, bool) {
	if h.State != Dead {
		h.poked = time.Time{} // a tunnel dying again is poked at once
		return h, false
	}
	now = now.Round(0)
	if !h.poked.IsZero() && now.Sub(h.poked) < PokeEvery {
		return h, false
	}
	h.poked = now
	return h, true
}

// SampleOf builds a Sample from peer stats: newest handshake, sums of tx/rx.
func SampleOf(at time.Time, peers []tunnel.PeerStats, ping PingResult) Sample {
	s := Sample{At: at.Round(0), Ping: ping}
	for _, p := range peers {
		if p.LastHandshake.After(s.Handshake) {
			s.Handshake = p.LastHandshake
		}
		s.Tx += p.TxBytes
		s.Rx += p.RxBytes
	}
	return s
}
