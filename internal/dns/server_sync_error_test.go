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

// Tests follow design 8 ("Домены из правил": SERVFAIL only when the route of
// an address of this answer did not go in; Server.Invalidate),
// not the implementation. The Server and
// the fake upstream are those of server_test.go (startServer: rule
// ifconfig.me via de, icanhazip.com direct, example.com in fallback: block;
// system upstream 127.0.0.1).

// setSyncErr makes the fake Sync of y return err (nil: success).
func setSyncErr(y *fakeSync, err error) {
	if err == nil {
		y.err.Store(nil)
		return
	}
	y.err.Store(&err)
}

func pfxList(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// syncErr is a *router.SyncError with the failed prefixes.
func syncErr(failed ...string) error {
	return &router.SyncError{Failed: pfxList(failed...), Err: errors.New("route add: file exists")}
}

// callNoPanic runs f; a panic of the code under test fails the test.
func callNoPanic(t *testing.T, what string, f func()) {
	t.Helper()
	ok := false
	noPanic(t, what, func() { f(); ok = true })
	if !ok {
		t.FailNow()
	}
}

// A *router.SyncError gives SERVFAIL only
// when its failed prefixes hold the /32 (/128) of an address of this answer;
// any other error is SERVFAIL as before.
func TestServerSyncErrorPrefixes(t *testing.T) {
	cases := []struct {
		name     string
		qname    string
		qtype    uint16
		answer   []string // A or AAAA of the upstream
		err      error
		servfail bool
	}{
		{"other /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			syncErr("198.51.100.7/32"), false},
		{"other /32 and a /24 holding the address failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			syncErr("198.51.100.7/32", "192.0.2.0/24"), false},
		{"empty Failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			syncErr(), false},
		{"own /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			syncErr("198.51.100.7/32", "192.0.2.1/32"), true},
		{"/32 of the second address failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1", "192.0.2.2"},
			syncErr("192.0.2.2/32"), true},
		{"direct rule: own /32 failed", "icanhazip.com", dns.TypeA, []string{"192.0.2.3"},
			syncErr("192.0.2.3/32"), true},
		{"direct rule: other /32 failed", "icanhazip.com", dns.TypeA, []string{"192.0.2.3"},
			syncErr("192.0.2.4/32"), false},
		{"own /128 failed", "icanhazip.com", dns.TypeAAAA, []string{"2001:db8::1"},
			syncErr("2001:db8::1/128"), true},
		{"other /128 failed", "icanhazip.com", dns.TypeAAAA, []string{"2001:db8::1"},
			syncErr("2001:db8::2/128"), false},
		{"plain error", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			errors.New("dump: operation not permitted"), true},
		// The server finds the SyncError with errors.As (orchestrator decision).
		{"wrapped: own /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			fmt.Errorf("sync: %w", syncErr("192.0.2.1/32")), true},
		{"wrapped: other /32 failed", "ifconfig.me", dns.TypeA, []string{"192.0.2.1"},
			fmt.Errorf("sync: %w", syncErr("198.51.100.7/32")), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			startUpstream(t, answerFunc(func(q dns.Question) []dns.RR {
				if q.Qtype != c.qtype {
					return nil
				}
				var rrs []dns.RR
				for _, a := range c.answer {
					if c.qtype == dns.TypeA {
						rrs = append(rrs, aRR(q.Name, a, 60))
					} else {
						rrs = append(rrs, aaaaRR(q.Name, a, 60))
					}
				}
				return rrs
			}))
			s, y := startServer(t)
			setSyncErr(y, c.err)
			resp := exchangeMsg(t, s, "udp", c.qname, c.qtype, 0)
			if y.calls.Load() == 0 {
				t.Error("Sync not called for a new pair")
			}
			if c.servfail {
				wantRcode(t, resp, dns.RcodeServerFailure)
				if got := answerAddrs(resp); len(got) != 0 {
					t.Errorf("SERVFAIL carries addresses %v", got)
				}
				return
			}
			wantRcode(t, resp, dns.RcodeSuccess)
			if got := answerAddrs(resp); !slices.Equal(got, c.answer) {
				t.Errorf("answer = %v, want %v", got, c.answer)
			}
		})
	}
}

// After a SyncError that did not touch this answer
// the answer goes, but the sync is not counted as done: the next answer of
// the same pair calls Sync again; after a successful Sync it does not.
func TestServerSyncErrorNotSynced(t *testing.T) {
	startUpstream(t, addrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := startServer(t)
	setSyncErr(y, syncErr("198.51.100.7/32"))

	steps := []struct {
		why   string
		err   error
		calls int32
	}{
		{"new pair, SyncError of another prefix", syncErr("198.51.100.7/32"), 1},
		{"known pair, the last Sync failed: Sync again", syncErr("198.51.100.7/32"), 2},
		{"known pair, Sync succeeds", nil, 3},
		{"known pair, synced: no Sync", nil, 3},
	}
	for _, st := range steps {
		setSyncErr(y, st.err)
		resp := exchangeMsg(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
		wantRcode(t, resp, dns.RcodeSuccess)
		if got := answerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
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
func TestServerInvalidate(t *testing.T) {
	startUpstream(t, addrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := startServer(t)

	query := func(name string, want int32, why string) {
		t.Helper()
		resp := exchangeMsg(t, s, "udp", name, dns.TypeA, 0)
		wantRcode(t, resp, dns.RcodeSuccess)
		if n := y.calls.Load(); n != want {
			t.Errorf("%s: Sync called %d times in all, want %d", why, n, want)
		}
	}
	query("ifconfig.me", 1, "new pair")
	query("ifconfig.me", 1, "known pair")

	callNoPanic(t, "Invalidate", s.Invalidate)
	query("apple.test", 1, "after Invalidate, a name without a rule")
	query("ifconfig.me", 2, "after Invalidate, a known pair")
	query("ifconfig.me", 2, "known pair again")
	query("icanhazip.com", 3, "a new pair of the direct rule")

	callNoPanic(t, "Invalidate", s.Invalidate)
	query("icanhazip.com", 4, "after a second Invalidate, a known pair of the direct rule")
}
