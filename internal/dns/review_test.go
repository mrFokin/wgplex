package dns

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests from the Wirefork M5 review (plan "Ход работы", step 3, "Замечания test-dev")
// and decisions 5, 11, 12; they follow design 8 and the plan, not the code.
// The fake upstream, m5ServerCfg and the other m5 helpers are in the other
// *_test.go files of the package.

// --- helpers -----------------------------------------------------------------

// m5rStartServer starts a Server on 127.0.0.1:0 with the given state, system
// upstream and Sync.
func m5rStartServer(t *testing.T, cfg *config.Config, rules []router.RuleState, ifaces map[string]int,
	system []netip.Addr, syncFn func() error) *Server {
	t.Helper()
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Sync: syncFn}
	ok := false
	m5NoPanic(t, "Server setup", func() {
		s.SetState(cfg, rules, ifaces)
		s.SetSystem(system)
		if err := s.Start("127.0.0.1:0"); err != nil {
			t.Fatalf("Start: %v", err)
		}
		ok = true
	})
	if !ok {
		t.FailNow()
	}
	t.Cleanup(func() {
		if err := s.Shutdown(); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return s
}

func m5rLoopback() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }

// m5rResult is the outcome of a query sent from a goroutine.
type m5rResult struct {
	m   *dns.Msg
	err error
}

// m5rQuery sends one UDP A query for name to s in the background.
func m5rQuery(s *Server, name string) <-chan m5rResult {
	ch := make(chan m5rResult, 1)
	addr := s.Addr().String()
	go func() {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(name), dns.TypeA)
		c := &dns.Client{Net: "udp", Timeout: 10 * time.Second}
		m, _, err := c.Exchange(req, addr)
		ch <- m5rResult{m, err}
	}()
	return ch
}

// m5rWait waits for cond up to 5 s.
func m5rWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// m5rReply answers with rcode and no records.
func m5rReply(rcode int) func(r *dns.Msg, tcp bool) *dns.Msg {
	return func(r *dns.Msg, _ bool) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		return m
	}
}

// m5rSilent never answers.
func m5rSilent(*dns.Msg, bool) *dns.Msg { return nil }

// m5rSeq answers the n-th query (from 0) with hs[n]; the last handler serves
// every later query.
func m5rSeq(hs ...func(r *dns.Msg, tcp bool) *dns.Msg) func(r *dns.Msg, tcp bool) *dns.Msg {
	var n atomic.Int32
	return func(r *dns.Msg, tcp bool) *dns.Msg {
		i := int(n.Add(1)) - 1
		if i >= len(hs) {
			i = len(hs) - 1
		}
		return hs[i](r, tcp)
	}
}

// --- B1: no answer before the Sync that covers its pair -----------------------

// design 8 "Домены из правил" (the /32 before the answer), Wirefork M5 "Модель" query
// step 5, decision 5, review blocker B1: two concurrent queries for one new
// name of a rule (a retry of mDNSResponder). While Sync is blocked neither is
// answered; after it returns both get NOERROR with the address, or both
// SERVFAIL if it failed. More than one Sync call is fine.
func TestM5rServerSyncConcurrent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		rcode int
	}{
		{"Sync succeeds", nil, dns.RcodeSuccess},
		{"Sync fails", errors.New("route add: no buffer space"), dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
			var (
				calls   atomic.Int32
				entered = make(chan struct{}, 64)
				release = make(chan struct{})
				once    sync.Once
			)
			cfg, rules, ifaces := m5ServerCfg()
			s := m5rStartServer(t, cfg, rules, ifaces, m5rLoopback(), func() error {
				calls.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
				return tc.err
			})
			unblock := func() { once.Do(func() { close(release) }) }
			// Runs before Shutdown (cleanups are LIFO): in-flight queries end.
			t.Cleanup(unblock)

			r1 := m5rQuery(s, "ifconfig.me")
			select {
			case <-entered:
			case res := <-r1:
				t.Fatalf("first query answered without Sync: %v %v", res.m, res.err)
			case <-time.After(5 * time.Second):
				t.Fatal("Sync not called for a new pair")
			}
			r2 := m5rQuery(s, "ifconfig.me")
			// The second query has reached the server and the upstream.
			m5rWait(t, "the second upstream query", func() bool { return u.total() >= 2 })

			select {
			case res := <-r1:
				t.Fatalf("first query answered while Sync is blocked: %v %v", res.m, res.err)
			case res := <-r2:
				t.Fatalf("second query answered while Sync is blocked (B1): %v %v", res.m, res.err)
			case <-time.After(300 * time.Millisecond):
			}

			unblock()
			for i, ch := range []<-chan m5rResult{r1, r2} {
				var res m5rResult
				select {
				case res = <-ch:
				case <-time.After(m5ClientTimeout):
					t.Fatalf("query %d: no answer after Sync returned", i+1)
				}
				if res.err != nil {
					t.Fatalf("query %d: %v", i+1, res.err)
				}
				m5Rcode(t, res.m, tc.rcode)
				got := m5AnswerAddrs(res.m)
				if tc.rcode == dns.RcodeSuccess && !slices.Equal(got, []string{"192.0.2.1"}) {
					t.Errorf("query %d: answer = %v, want [192.0.2.1]", i+1, got)
				}
				if tc.rcode != dns.RcodeSuccess && len(got) != 0 {
					t.Errorf("query %d: SERVFAIL carries addresses %v", i+1, got)
				}
			}
			if calls.Load() == 0 {
				t.Error("Sync not called")
			}
		})
	}
}

// decision 5, review "повтор после неудачного Sync": the first Sync fails
// (SERVFAIL); the next query for the same name calls Sync again although the
// pair is already known, and gets NOERROR once it succeeds.
func TestM5rServerSyncRetry(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	var (
		calls atomic.Int32
		mu    sync.Mutex
		dyn   []router.Dynamic
		s     *Server
	)
	cfg, rules, ifaces := m5ServerCfg()
	s = m5rStartServer(t, cfg, rules, ifaces, m5rLoopback(), func() error {
		d := s.Dynamic()
		mu.Lock()
		dyn = d
		mu.Unlock()
		if calls.Add(1) == 1 {
			return errors.New("route add: file exists")
		}
		return nil
	})

	resp := m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeServerFailure)
	if n := calls.Load(); n != 1 {
		t.Fatalf("after the first query Sync called %d times, want 1", n)
	}

	resp = m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
	if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("answer = %v, want [192.0.2.1]", got)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("Sync called %d times in all, want 2: the retry must sync again", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := m5Dyn("192.0.2.1", m5SRTun); !slices.Contains(dyn, want) {
		t.Errorf("Dynamic at the second Sync = %v, want it to hold %v", dyn, want)
	}
}

// --- a rule tunnel without utun ----------------------------------------------

// design 8 "Домены из правил" (the query goes through the tunnel; an unbound
// socket would go directly), Wirefork M5 step 2 item 3: the rule's tunnel has no entry
// in ifaces → SERVFAIL, the upstream is not asked, no Sync. A dns_domains
// name of that tunnel goes to the system (decision 7) and is answered.
func TestM5rServerRuleTunnelWithoutUtun(t *testing.T) {
	u := m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	var calls atomic.Int32
	cfg, rules, _ := m5ServerCfg()
	s := m5rStartServer(t, cfg, rules, map[string]int{}, m5rLoopback(), func() error {
		calls.Add(1)
		return nil
	})

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
		resp := m5Exchange(t, s, "udp", "ifconfig.me", qtype, 0)
		m5Rcode(t, resp, dns.RcodeServerFailure)
		if len(resp.Answer) != 0 {
			t.Errorf("%s: SERVFAIL carries %v", dns.TypeToString[qtype], resp.Answer)
		}
	}
	if n := u.total(); n != 0 {
		t.Errorf("upstream asked %d times for a rule tunnel without utun", n)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("Sync called %d times", n)
	}

	resp := m5Exchange(t, s, "udp", "vault.corp.example", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
	if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("dns_domains name without utun: answer = %v, want [192.0.2.1] from the system", got)
	}
}

// --- the next server ---------------------------------------------------------

// m5rTwoServers is m5ServerCfg with the tunnel de's DNS and the system
// upstream both set to servers (built directly: config.Load would drop
// duplicates).
func m5rTwoServers(t *testing.T, servers ...string) *Server {
	t.Helper()
	cfg, rules, ifaces := m5ServerCfg()
	cfg.Tunnels[0].WG.DNS = m5Addrs(servers...)
	return m5rStartServer(t, cfg, rules, ifaces, m5Addrs(servers...), func() error { return nil })
}

// design 8 (2 s per server, the next one on no answer), decision 10: the
// first server does not answer, the second does. Both through a rule tunnel
// and the system upstream.
func TestM5rServerNextOnSilence(t *testing.T) {
	for _, tc := range []struct {
		why     string
		servers []string
		handle  func() func(r *dns.Msg, tcp bool) *dns.Msg // a fresh handler per subtest
		asked   int32                                      // queries the fake must get
	}{
		// The fake is asked twice: the first time it keeps silent.
		{"first silent", []string{"127.0.0.1", "127.0.0.1"},
			func() func(*dns.Msg, bool) *dns.Msg {
				return m5rSeq(m5rSilent, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
			}, 2},
		// Nothing listens on 127.0.0.2 (no alias on lo0: a send error, a
		// refusal or a timeout — any of them is "no answer").
		{"first is 127.0.0.2", []string{"127.0.0.2", "127.0.0.1"},
			func() func(*dns.Msg, bool) *dns.Msg { return m5AddrAnswer("192.0.2.1", "2001:db8::1") }, 1},
	} {
		for _, name := range []string{"ifconfig.me", "apple.test"} {
			t.Run(tc.why+" "+name, func(t *testing.T) {
				u := m5StartUpstream(t, tc.handle())
				s := m5rTwoServers(t, tc.servers...)
				start := time.Now()
				resp := m5Exchange(t, s, "udp", name, dns.TypeA, 0)
				el := time.Since(start)
				m5Rcode(t, resp, dns.RcodeSuccess)
				if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
					t.Errorf("answer = %v, want [192.0.2.1] from the second server", got)
				}
				if n := u.total(); n != tc.asked {
					t.Errorf("fake asked %d times, want %d", n, tc.asked)
				}
				if el > upstreamTimeout+time.Second {
					t.Errorf("answer after %v, want within one upstream timeout %v", el, upstreamTimeout)
				}
			})
		}
	}
}

// design 8, decision 12: SERVFAIL or REFUSED from a server → the next one; if
// there is no better answer, the client gets the last such answer. Other
// answers (NXDOMAIN) are final. One fake answers by query count; the tunnel
// and the system have it twice.
func TestM5rServerNextOnServfail(t *testing.T) {
	addr := m5AddrAnswer("192.0.2.1", "2001:db8::1")
	for _, tc := range []struct {
		why   string
		hs    []func(r *dns.Msg, tcp bool) *dns.Msg
		rcode int
		addrs []string
		asked int32
	}{
		{"REFUSED, then an answer", []func(*dns.Msg, bool) *dns.Msg{m5rReply(dns.RcodeRefused), addr},
			dns.RcodeSuccess, []string{"192.0.2.1"}, 2},
		{"SERVFAIL, then an answer", []func(*dns.Msg, bool) *dns.Msg{m5rReply(dns.RcodeServerFailure), addr},
			dns.RcodeSuccess, []string{"192.0.2.1"}, 2},
		{"SERVFAIL, then REFUSED: the last", []func(*dns.Msg, bool) *dns.Msg{
			m5rReply(dns.RcodeServerFailure), m5rReply(dns.RcodeRefused)}, dns.RcodeRefused, nil, 2},
		{"REFUSED, then SERVFAIL: the last", []func(*dns.Msg, bool) *dns.Msg{
			m5rReply(dns.RcodeRefused), m5rReply(dns.RcodeServerFailure)}, dns.RcodeServerFailure, nil, 2},
		{"REFUSED, then silence: the REFUSED", []func(*dns.Msg, bool) *dns.Msg{
			m5rReply(dns.RcodeRefused), m5rSilent}, dns.RcodeRefused, nil, 2},
		{"NXDOMAIN is final", []func(*dns.Msg, bool) *dns.Msg{m5rReply(dns.RcodeNameError), addr},
			dns.RcodeNameError, nil, 1},
	} {
		for _, name := range []string{"ifconfig.me", "apple.test"} {
			t.Run(tc.why+" "+name, func(t *testing.T) {
				u := m5StartUpstream(t, m5rSeq(tc.hs...))
				s := m5rTwoServers(t, "127.0.0.1", "127.0.0.1")
				resp := m5Exchange(t, s, "udp", name, dns.TypeA, 0)
				m5Rcode(t, resp, tc.rcode)
				if got := m5AnswerAddrs(resp); !slices.Equal(got, tc.addrs) {
					t.Errorf("answer = %v, want %v", got, tc.addrs)
				}
				if n := u.total(); n != tc.asked {
					t.Errorf("fake asked %d times, want %d", n, tc.asked)
				}
			})
		}
	}
}

// --- HTTPS end to end --------------------------------------------------------

// design 8, decision 8: for rule domains (tunnel or direct) HTTPS loses
// ipv4hint and ipv6hint and keeps alpn; for a name without a rule the record
// passes as is.
func TestM5rServerHTTPSHints(t *testing.T) {
	m5StartUpstream(t, m5Answer(func(q dns.Question) []dns.RR {
		if q.Qtype == dns.TypeHTTPS {
			return []dns.RR{m5HTTPS(q.Name)}
		}
		return nil
	}))
	cfg, rules, ifaces := m5ServerCfg()
	s := m5rStartServer(t, cfg, rules, ifaces, m5rLoopback(), func() error { return nil })
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"ifconfig.me", []string{"alpn"}},
		{"www.ifconfig.me", []string{"alpn"}},
		{"icanhazip.com", []string{"alpn"}},
		{"apple.test", []string{"alpn", "ipv4hint", "ipv6hint"}},
		{"vault.corp.example", []string{"alpn", "ipv4hint", "ipv6hint"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				resp := m5Exchange(t, s, network, tc.name, dns.TypeHTTPS, 0)
				m5Rcode(t, resp, dns.RcodeSuccess)
				if len(resp.Answer) != 1 {
					t.Fatalf("%s: answer = %v, want one HTTPS record", network, resp.Answer)
				}
				got := m5SVCBKeys(resp.Answer[0])
				slices.Sort(got)
				if !slices.Equal(got, tc.want) {
					t.Errorf("%s: HTTPS keys = %v, want %v", network, got, tc.want)
				}
			}
		})
	}
}

// --- NODATA with EDNS0 -------------------------------------------------------

// design 7.3, Wirefork M5 step 2 item 5: the NODATA of block has an OPT when the client
// sent EDNS0, over TCP too (RFC 6891: and none without it).
func TestM5rServerNoDataEDNS0(t *testing.T) {
	u := m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	cfg, rules, ifaces := m5ServerCfg()
	s := m5rStartServer(t, cfg, rules, ifaces, m5rLoopback(), func() error { return nil })
	for _, tc := range []struct {
		network string
		edns    uint16
	}{
		{"tcp", 4096},
		{"udp", 1232},
		{"tcp", 0},
		{"udp", 0},
	} {
		resp := m5Exchange(t, s, tc.network, "www.example.com", dns.TypeA, tc.edns)
		m5Rcode(t, resp, dns.RcodeSuccess)
		if len(resp.Answer) != 0 {
			t.Errorf("%s EDNS0 %d: answer = %v, want empty", tc.network, tc.edns, resp.Answer)
		}
		if !slices.ContainsFunc(resp.Ns, func(rr dns.RR) bool { _, ok := rr.(*dns.SOA); return ok }) {
			t.Errorf("%s EDNS0 %d: authority = %v, want a SOA", tc.network, tc.edns, resp.Ns)
		}
		opt := resp.IsEdns0()
		if tc.edns > 0 && opt == nil {
			t.Errorf("%s EDNS0 %d: no OPT in the reply", tc.network, tc.edns)
		}
		if tc.edns == 0 && opt != nil {
			t.Errorf("%s without EDNS0: OPT in the reply", tc.network)
		}
	}
	if n := u.total(); n != 0 {
		t.Errorf("upstream asked %d times for a blocked name", n)
	}
}

// --- parseScutil: empty values -----------------------------------------------

// Wirefork M5 review, go-dev remark 6: an empty array element ("0 : ") is kept as "",
// in its place; an empty scalar ("Key : ") is [""]. Capture checks
// SupplementalMatchDomains = [""] by this.
func TestM5rParseScutilEmpty(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want map[string][]string
	}{
		{"the capture key", `<dictionary> {
  ServerAddresses : <array> {
    0 : 127.0.0.1
  }
  SupplementalMatchDomains : <array> {
    0 :
  }
}
`, map[string][]string{
			"ServerAddresses":          {"127.0.0.1"},
			"SupplementalMatchDomains": {""},
		}},
		{"empty element in the middle", `<dictionary> {
  SearchDomains : <array> {
    0 : a.example
    1 :
    2 : b.example
  }
}
`, map[string][]string{"SearchDomains": {"a.example", "", "b.example"}}},
		{"empty scalar", `<dictionary> {
  DomainName :
  Router : 192.168.20.1
}
`, map[string][]string{"DomainName": {""}, "Router": {"192.168.20.1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m5Parse(t, c.out)
			m5SameMap(t, got, c.want)
			if len(got) != len(c.want) {
				t.Errorf("parsed %d keys %q, want %d", len(got), got, len(c.want))
			}
		})
	}
}

// --- systemServers: loopback -------------------------------------------------

// Wirefork M5 review, go-dev remark 3: a loopback system server (127.0.0.1 is our own
// resolver once captured; 127.0.0.53, ::1) would loop, so it is dropped.
// Tested on systemServers: Server.SetSystem cannot filter it, the server
// tests use 127.0.0.1 as the system upstream.
func TestM5rSystemServersLoopback(t *testing.T) {
	cases := []struct {
		why          string
		setup, state map[string][]string
		want         []string
	}{
		{"State: loopback dropped",
			nil, map[string][]string{"ServerAddresses": {"127.0.0.1", "192.168.20.1", "127.0.0.53", "::1", "2001:db8::53"}},
			[]string{"192.168.20.1", "2001:db8::53"}},
		{"Setup: loopback dropped",
			map[string][]string{"ServerAddresses": {"::1", "9.9.9.9", "127.0.0.1"}}, nil,
			[]string{"9.9.9.9"}},
		{"only loopback", nil, map[string][]string{"ServerAddresses": {"127.0.0.1", "127.0.0.53", "::1"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			var got []string
			m5NoPanic(t, "systemServers", func() {
				for _, a := range systemServers(c.setup, c.state) {
					got = append(got, a.String())
				}
			})
			if !slices.Equal(got, c.want) {
				t.Errorf("systemServers = %v, want %v", got, c.want)
			}
		})
	}
}
