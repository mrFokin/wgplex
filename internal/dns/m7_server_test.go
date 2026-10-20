package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow design 7 ("Домены из правил": SERVFAIL only when the route of
// an address of this answer did not go in) and the M7 plan (accumulated
// tasks 4, 5; decision 9; Server.Invalidate), not the implementation. The Server and
// the fake upstream are those of server_test.go (m5StartServer: rule
// ifconfig.me via de, icanhazip.com direct, example.com in fallback: block;
// system upstream 127.0.0.1).

// m7SetSyncErr makes the fake Sync of y return err (nil: success).
func m7SetSyncErr(y *m5Sync, err error) {
	if err == nil {
		y.err.Store(nil)
		return
	}
	y.err.Store(&err)
}

func m7Pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// m7SyncErr is a *router.SyncError with the failed prefixes.
func m7SyncErr(failed ...string) error {
	return &router.SyncError{Failed: m7Pfx(failed...), Err: errors.New("route add: file exists")}
}

// m7Call runs f; a panic of the code under test fails the test.
func m7Call(t *testing.T, what string, f func()) {
	t.Helper()
	ok := false
	m5NoPanic(t, what, func() { f(); ok = true })
	if !ok {
		t.FailNow()
	}
}

// Decision 9, accumulated task 4: a *router.SyncError gives SERVFAIL only
// when its failed prefixes hold the /32 (/128) of an address of this answer;
// any other error is SERVFAIL as before.
func TestM7ServerSyncErrorPrefixes(t *testing.T) {
	cases := []struct {
		name     string
		qname    string
		qtype    uint16
		answer   []string // A or AAAA of the upstream
		err      error
		servfail bool
	}{
		{"other /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			m7SyncErr("198.51.100.7/32"), false},
		{"other /32 and a /24 holding the address failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			m7SyncErr("198.51.100.7/32", "192.0.2.0/24"), false},
		{"empty Failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			m7SyncErr(), false},
		{"own /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			m7SyncErr("198.51.100.7/32", "192.0.2.1/32"), true},
		{"/32 of the second address failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1", "192.0.2.2"},
			m7SyncErr("192.0.2.2/32"), true},
		{"direct rule: own /32 failed", "icanhazip.com", dns.TypeA, []string{"192.0.2.3"},
			m7SyncErr("192.0.2.3/32"), true},
		{"direct rule: other /32 failed", "icanhazip.com", dns.TypeA, []string{"192.0.2.3"},
			m7SyncErr("192.0.2.4/32"), false},
		{"own /128 failed", "icanhazip.com", dns.TypeAAAA, []string{"2001:db8::1"},
			m7SyncErr("2001:db8::1/128"), true},
		{"other /128 failed", "icanhazip.com", dns.TypeAAAA, []string{"2001:db8::1"},
			m7SyncErr("2001:db8::2/128"), false},
		{"plain error", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			errors.New("dump: operation not permitted"), true},
		// The server finds the SyncError with errors.As (orchestrator decision).
		{"wrapped: own /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			fmt.Errorf("sync: %w", m7SyncErr("192.0.2.1/32")), true},
		{"wrapped: other /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			fmt.Errorf("sync: %w", m7SyncErr("198.51.100.7/32")), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m5StartUpstream(t, m5Answer(func(q dns.Question) []dns.RR {
				if q.Qtype != c.qtype {
					return nil
				}
				var rrs []dns.RR
				for _, a := range c.answer {
					if c.qtype == dns.TypeA {
						rrs = append(rrs, m5A(q.Name, a, 60))
					} else {
						rrs = append(rrs, m5AAAA(q.Name, a, 60))
					}
				}
				return rrs
			}))
			s, y := m5StartServer(t)
			m7SetSyncErr(y, c.err)
			resp := m5Exchange(t, s, "udp", c.qname, c.qtype, 0)
			if y.calls.Load() == 0 {
				t.Error("Sync not called for a new pair")
			}
			if c.servfail {
				m5Rcode(t, resp, dns.RcodeServerFailure)
				if got := m5AnswerAddrs(resp); len(got) != 0 {
					t.Errorf("SERVFAIL carries addresses %v", got)
				}
				return
			}
			m5Rcode(t, resp, dns.RcodeSuccess)
			if got := m5AnswerAddrs(resp); !slices.Equal(got, c.answer) {
				t.Errorf("answer = %v, want %v", got, c.answer)
			}
		})
	}
}

// M7 plan "internal/dns": after a SyncError that did not touch this answer
// the answer goes, but the sync is not counted as done: the next answer of
// the same pair calls Sync again; after a successful Sync it does not.
func TestM7ServerSyncErrorNotSynced(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)
	m7SetSyncErr(y, m7SyncErr("198.51.100.7/32"))

	steps := []struct {
		why   string
		err   error
		calls int32
	}{
		{"new pair, SyncError of another prefix", m7SyncErr("198.51.100.7/32"), 1},
		{"known pair, the last Sync failed: Sync again", m7SyncErr("198.51.100.7/32"), 2},
		{"known pair, Sync succeeds", nil, 3},
		{"known pair, synced: no Sync", nil, 3},
	}
	for _, st := range steps {
		m7SetSyncErr(y, st.err)
		resp := m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
		m5Rcode(t, resp, dns.RcodeSuccess)
		if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
			t.Errorf("%s: answer = %v, want [192.0.2.1]", st.why, got)
		}
		if n := y.calls.Load(); n != st.calls {
			t.Errorf("%s: Sync called %d times in all, want %d", st.why, n, st.calls)
		}
	}
}

// Accumulated task 5: a failed Sync of the daemon → Invalidate; the next
// answer with rule addresses (a known pair too) calls Sync itself; a name
// without a rule does not.
func TestM7ServerInvalidate(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)

	query := func(name string, want int32, why string) {
		t.Helper()
		resp := m5Exchange(t, s, "udp", name, dns.TypeA, 0)
		m5Rcode(t, resp, dns.RcodeSuccess)
		if n := y.calls.Load(); n != want {
			t.Errorf("%s: Sync called %d times in all, want %d", why, n, want)
		}
	}
	query("ifconfig.me", 1, "new pair")
	query("ifconfig.me", 1, "known pair")

	m7Call(t, "Invalidate", s.Invalidate)
	query("apple.test", 1, "after Invalidate, a name without a rule")
	query("ifconfig.me", 2, "after Invalidate, a known pair")
	query("ifconfig.me", 2, "known pair again")
	query("icanhazip.com", 3, "a new pair of the direct rule")

	m7Call(t, "Invalidate", s.Invalidate)
	query("icanhazip.com", 4, "after a second Invalidate, a known pair of the direct rule")
}
