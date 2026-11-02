package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Tests of Dynamics.Pairs follow design 8 (a pair per name–address, deadline
// TTL + 1 h extended by every answer, names compared case-insensitively
// without the trailing dot) (Pairs sorted by name, then
// address), not the implementation.

var pairsT0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func dynPairs(t *testing.T, d *Dynamics) (got []Pair) {
	t.Helper()
	noPanic(t, "Pairs", func() { got = d.Pairs() })
	return got
}

func fmtPairs(ps []Pair) string {
	s := ""
	for _, p := range ps {
		s += fmt.Sprintf("\n  %s %s %s", p.Name, p.Addr, p.Deadline.Format(time.RFC3339))
	}
	return s
}

func samePairs(t *testing.T, what string, got, want []Pair) {
	t.Helper()
	ok := len(got) == len(want)
	for i := 0; ok && i < len(got); i++ {
		ok = got[i].Name == want[i].Name && got[i].Addr == want[i].Addr && got[i].Deadline.Equal(want[i].Deadline)
	}
	if !ok {
		t.Errorf("%s: Pairs =%s\nwant%s", what, fmtPairs(got), fmtPairs(want))
	}
}

func TestPairsEmpty(t *testing.T) {
	var d Dynamics
	if got := dynPairs(t, &d); len(got) != 0 {
		t.Errorf("zero Dynamics: Pairs = %v, want empty", got)
	}
}

// Sorted by name, then address (IPv4 before IPv6 as netip orders
// them); names are normalized; the deadline is now + TTL + 1 h (design 8).
func TestPairsSortedNormalized(t *testing.T) {
	var d Dynamics
	ttl := 5 * time.Minute
	dynAdd(t, &d, "WWW.YouTube.com.", parseAddrs("192.0.2.20", "2001:db8::1", "192.0.2.3"), ttl, pairsT0)
	dynAdd(t, &d, "ifconfig.me", parseAddrs("34.160.111.145"), time.Minute, pairsT0)
	dynAdd(t, &d, "a.example.org", parseAddrs("198.51.100.9"), ttl, pairsT0.Add(time.Second))

	dl := pairsT0.Add(ttl + time.Hour)
	want := []Pair{
		{Name: "a.example.org", Addr: netip.MustParseAddr("198.51.100.9"), Deadline: dl.Add(time.Second)},
		{Name: "ifconfig.me", Addr: netip.MustParseAddr("34.160.111.145"), Deadline: pairsT0.Add(time.Minute + time.Hour)},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("192.0.2.3"), Deadline: dl},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("192.0.2.20"), Deadline: dl},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("2001:db8::1"), Deadline: dl},
	}
	samePairs(t, "after Add", dynPairs(t, &d), want)
}

// design 8: one pair per (name, address); an address shared by several names
// is a pair per name, each with its own deadline; a name written differently
// is the same pair.
func TestPairsSharedAddress(t *testing.T) {
	var d Dynamics
	a := parseAddrs("203.0.113.10")
	dynAdd(t, &d, "b.example", a, time.Minute, pairsT0)
	dynAdd(t, &d, "a.example", a, 10*time.Minute, pairsT0)
	dynAdd(t, &d, "B.Example.", a, time.Minute, pairsT0) // same pair as b.example

	want := []Pair{
		{Name: "a.example", Addr: a[0], Deadline: pairsT0.Add(10*time.Minute + time.Hour)},
		{Name: "b.example", Addr: a[0], Deadline: pairsT0.Add(time.Minute + time.Hour)},
	}
	samePairs(t, "shared address", dynPairs(t, &d), want)
}

// design 8: every answer extends the deadline; an earlier one does not
// shorten it (max of old and new).
func TestPairsDeadlineExtended(t *testing.T) {
	var d Dynamics
	a := parseAddrs("203.0.113.10")
	dynAdd(t, &d, "x.example", a, time.Minute, pairsT0)
	later := pairsT0.Add(30 * time.Minute)
	dynAdd(t, &d, "x.example", a, time.Minute, later)
	samePairs(t, "extended", dynPairs(t, &d), []Pair{
		{Name: "x.example", Addr: a[0], Deadline: later.Add(time.Minute + time.Hour)},
	})

	// An answer with a short TTL right after does not shorten the deadline.
	dynAdd(t, &d, "x.example", a, 0, later)
	samePairs(t, "not shortened", dynPairs(t, &d), []Pair{
		{Name: "x.example", Addr: a[0], Deadline: later.Add(time.Minute + time.Hour)},
	})
}

// Expire drops pairs with deadline <= now; the rest stay in Pairs.
func TestPairsAfterExpire(t *testing.T) {
	var d Dynamics
	dynAdd(t, &d, "short.example", parseAddrs("192.0.2.1"), time.Minute, pairsT0)
	dynAdd(t, &d, "long.example", parseAddrs("192.0.2.2"), time.Hour, pairsT0)

	dynExpire(t, &d, pairsT0.Add(time.Minute+time.Hour)) // exactly the deadline of short
	samePairs(t, "after Expire", dynPairs(t, &d), []Pair{
		{Name: "long.example", Addr: netip.MustParseAddr("192.0.2.2"), Deadline: pairsT0.Add(2 * time.Hour)},
	})

	dynExpire(t, &d, pairsT0.Add(2*time.Hour))
	if got := dynPairs(t, &d); len(got) != 0 {
		t.Errorf("after the last deadline: Pairs = %s, want empty", fmtPairs(got))
	}
}

// Pairs is a snapshot: changing the returned slice does not change Dynamics.
func TestPairsSnapshot(t *testing.T) {
	var d Dynamics
	dynAdd(t, &d, "x.example", parseAddrs("192.0.2.1"), time.Minute, pairsT0)
	got := dynPairs(t, &d)
	if len(got) != 1 {
		t.Fatalf("Pairs = %s, want one pair", fmtPairs(got))
	}
	got[0].Name = "changed"
	if again := dynPairs(t, &d); len(again) != 1 || again[0].Name != "x.example" {
		t.Errorf("Pairs after changing the returned slice = %s", fmtPairs(again))
	}
}
