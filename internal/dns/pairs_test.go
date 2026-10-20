package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Tests of Dynamics.Pairs follow design 7 (a pair per name–address, deadline
// TTL + 1 h extended by every answer, names compared case-insensitively
// without the trailing dot) and the M6 plan (Pairs sorted by name, then
// address), not the implementation.

var m6T0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func m6Pairs(t *testing.T, d *Dynamics) (got []Pair) {
	t.Helper()
	m5NoPanic(t, "Pairs", func() { got = d.Pairs() })
	return got
}

func m6FmtPairs(ps []Pair) string {
	s := ""
	for _, p := range ps {
		s += fmt.Sprintf("\n  %s %s %s", p.Name, p.Addr, p.Deadline.Format(time.RFC3339))
	}
	return s
}

func m6SamePairs(t *testing.T, what string, got, want []Pair) {
	t.Helper()
	ok := len(got) == len(want)
	for i := 0; ok && i < len(got); i++ {
		ok = got[i].Name == want[i].Name && got[i].Addr == want[i].Addr && got[i].Deadline.Equal(want[i].Deadline)
	}
	if !ok {
		t.Errorf("%s: Pairs =%s\nwant%s", what, m6FmtPairs(got), m6FmtPairs(want))
	}
}

func TestM6PairsEmpty(t *testing.T) {
	var d Dynamics
	if got := m6Pairs(t, &d); len(got) != 0 {
		t.Errorf("zero Dynamics: Pairs = %v, want empty", got)
	}
}

// M6 plan: sorted by name, then address (IPv4 before IPv6 as netip orders
// them); names are normalized; the deadline is now + TTL + 1 h (design 7).
func TestM6PairsSortedNormalized(t *testing.T) {
	var d Dynamics
	ttl := 5 * time.Minute
	m5Add(t, &d, "WWW.YouTube.com.", m5Addrs("192.0.2.20", "2001:db8::1", "192.0.2.3"), ttl, m6T0)
	m5Add(t, &d, "ifconfig.me", m5Addrs("34.160.111.145"), time.Minute, m6T0)
	m5Add(t, &d, "a.example.org", m5Addrs("198.51.100.9"), ttl, m6T0.Add(time.Second))

	dl := m6T0.Add(ttl + time.Hour)
	want := []Pair{
		{Name: "a.example.org", Addr: netip.MustParseAddr("198.51.100.9"), Deadline: dl.Add(time.Second)},
		{Name: "ifconfig.me", Addr: netip.MustParseAddr("34.160.111.145"), Deadline: m6T0.Add(time.Minute + time.Hour)},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("192.0.2.3"), Deadline: dl},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("192.0.2.20"), Deadline: dl},
		{Name: "www.youtube.com", Addr: netip.MustParseAddr("2001:db8::1"), Deadline: dl},
	}
	m6SamePairs(t, "after Add", m6Pairs(t, &d), want)
}

// design 7: one pair per (name, address); an address shared by several names
// is a pair per name, each with its own deadline; a name written differently
// is the same pair.
func TestM6PairsSharedAddress(t *testing.T) {
	var d Dynamics
	a := m5Addrs("203.0.113.10")
	m5Add(t, &d, "b.example", a, time.Minute, m6T0)
	m5Add(t, &d, "a.example", a, 10*time.Minute, m6T0)
	m5Add(t, &d, "B.Example.", a, time.Minute, m6T0) // same pair as b.example

	want := []Pair{
		{Name: "a.example", Addr: a[0], Deadline: m6T0.Add(10*time.Minute + time.Hour)},
		{Name: "b.example", Addr: a[0], Deadline: m6T0.Add(time.Minute + time.Hour)},
	}
	m6SamePairs(t, "shared address", m6Pairs(t, &d), want)
}

// design 7: every answer extends the deadline; an earlier one does not
// shorten it (max of old and new).
func TestM6PairsDeadlineExtended(t *testing.T) {
	var d Dynamics
	a := m5Addrs("203.0.113.10")
	m5Add(t, &d, "x.example", a, time.Minute, m6T0)
	later := m6T0.Add(30 * time.Minute)
	m5Add(t, &d, "x.example", a, time.Minute, later)
	m6SamePairs(t, "extended", m6Pairs(t, &d), []Pair{
		{Name: "x.example", Addr: a[0], Deadline: later.Add(time.Minute + time.Hour)},
	})

	// An answer with a short TTL right after does not shorten the deadline.
	m5Add(t, &d, "x.example", a, 0, later)
	m6SamePairs(t, "not shortened", m6Pairs(t, &d), []Pair{
		{Name: "x.example", Addr: a[0], Deadline: later.Add(time.Minute + time.Hour)},
	})
}

// Expire drops pairs with deadline <= now; the rest stay in Pairs.
func TestM6PairsAfterExpire(t *testing.T) {
	var d Dynamics
	m5Add(t, &d, "short.example", m5Addrs("192.0.2.1"), time.Minute, m6T0)
	m5Add(t, &d, "long.example", m5Addrs("192.0.2.2"), time.Hour, m6T0)

	m5Expire(t, &d, m6T0.Add(time.Minute+time.Hour)) // exactly the deadline of short
	m6SamePairs(t, "after Expire", m6Pairs(t, &d), []Pair{
		{Name: "long.example", Addr: netip.MustParseAddr("192.0.2.2"), Deadline: m6T0.Add(2 * time.Hour)},
	})

	m5Expire(t, &d, m6T0.Add(2*time.Hour))
	if got := m6Pairs(t, &d); len(got) != 0 {
		t.Errorf("after the last deadline: Pairs = %s, want empty", m6FmtPairs(got))
	}
}

// Pairs is a snapshot: changing the returned slice does not change Dynamics.
func TestM6PairsSnapshot(t *testing.T) {
	var d Dynamics
	m5Add(t, &d, "x.example", m5Addrs("192.0.2.1"), time.Minute, m6T0)
	got := m6Pairs(t, &d)
	if len(got) != 1 {
		t.Fatalf("Pairs = %s, want one pair", m6FmtPairs(got))
	}
	got[0].Name = "changed"
	if again := m6Pairs(t, &d); len(again) != 1 || again[0].Name != "x.example" {
		t.Errorf("Pairs after changing the returned slice = %s", m6FmtPairs(again))
	}
}
