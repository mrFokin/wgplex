package dns

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow design 6.3 (NODATA for block), 7 (upstreams, the /32 before
// the answer, SERVFAIL, the IPv6 filter, 2 s per server) and the M5 plan
// ("Модель" query steps 1–6, decisions 5, 8, 10), not the implementation.
//
// No root and no network: the Server listens on 127.0.0.1:0; the upstream is
// a fake miekg dns.Server on 127.0.0.1 (UDP and TCP on one port), reached
// through upstreamPort. The tunnel de has DNS = 127.0.0.1 and utun index 0
// (an unbound socket); the system upstream is 127.0.0.1 too, so which
// upstream answered is not visible here — Choose tests cover that.

// m5ClientTimeout is well above upstreamTimeout (2 s).
const m5ClientTimeout = 6 * time.Second

// --- fake upstream -----------------------------------------------------------

// m5Upstream is a fake upstream server. handle returns the reply to r (nil:
// no reply); over UDP the reply is truncated to the request's size (512
// without EDNS0), as real servers do.
type m5Upstream struct {
	udp, tcp atomic.Int32 // queries received by transport
	mu       sync.Mutex
	names    []string // queried names, lower case
	handle   func(r *dns.Msg, tcp bool) *dns.Msg
}

func (u *m5Upstream) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	tcp := w.LocalAddr().Network() == "tcp"
	if tcp {
		u.tcp.Add(1)
	} else {
		u.udp.Add(1)
	}
	if len(r.Question) > 0 {
		u.mu.Lock()
		u.names = append(u.names, strings.ToLower(r.Question[0].Name))
		u.mu.Unlock()
	}
	resp := u.handle(r, tcp)
	if resp == nil {
		return
	}
	if !tcp {
		size := dns.MinMsgSize
		if opt := r.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

func (u *m5Upstream) total() int32 { return u.udp.Load() + u.tcp.Load() }

// m5StartUpstream starts u on 127.0.0.1, UDP and TCP on one port, and points
// upstreamPort at it for the test.
func m5StartUpstream(t *testing.T, handle func(r *dns.Msg, tcp bool) *dns.Msg) *m5Upstream {
	t.Helper()
	u := &m5Upstream{handle: handle}
	var (
		pc net.PacketConn
		ln net.Listener
	)
	for i := 0; i < 20 && ln == nil; i++ {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", p.LocalAddr().String())
		if err != nil {
			p.Close()
			continue
		}
		pc, ln = p, l
	}
	if ln == nil {
		t.Fatal("no free port for UDP and TCP")
	}
	start := func(srv *dns.Server) {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("fake upstream did not start")
		}
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	start(&dns.Server{PacketConn: pc, Handler: u})
	start(&dns.Server{Listener: ln, Handler: u})

	old := upstreamPort
	upstreamPort = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(func() { upstreamPort = old })
	return u
}

// m5Answer replies with the records made by rrs for the question (NXDOMAIN
// never: an empty answer is NOERROR).
func m5Answer(rrs func(q dns.Question) []dns.RR) func(r *dns.Msg, tcp bool) *dns.Msg {
	return func(r *dns.Msg, _ bool) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = rrs(r.Question[0])
		}
		return m
	}
}

// m5AddrAnswer answers A and AAAA queries with a and aaaa (TTL 60) for any
// name; other types get an empty answer.
func m5AddrAnswer(a, aaaa string) func(r *dns.Msg, tcp bool) *dns.Msg {
	return m5Answer(func(q dns.Question) []dns.RR {
		switch q.Qtype {
		case dns.TypeA:
			return []dns.RR{m5A(q.Name, a, 60)}
		case dns.TypeAAAA:
			return []dns.RR{m5AAAA(q.Name, aaaa, 60)}
		}
		return nil
	})
}

// --- the server under test ---------------------------------------------------

// Rule indexes of m5ServerCfg.
const (
	m5SRTun    = 0 // ifconfig.me via de (no IPv6 Address)
	m5SRDirect = 1 // icanhazip.com, empty via
	m5SRBlock  = 2 // example.com, fallback: block, in fallback
)

func m5ServerCfg() (*config.Config, []router.RuleState, map[string]int) {
	cfg := &config.Config{
		IPv6Filter: true,
		Tunnels: []config.Tunnel{
			m5Tunnel("de", []string{"10.0.0.2/32"}, []string{"127.0.0.1"}, "corp.example"),
		},
		Services: map[string]config.Service{
			"tun":    {Domains: m5Domains("ifconfig.me")},
			"direct": {Domains: m5Domains("icanhazip.com")},
			"block":  {Domains: m5Domains("example.com")},
		},
		Rules: []config.Rule{
			m5SRTun:    {Services: []string{"tun"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
			m5SRDirect: {Services: []string{"direct"}, Fallback: config.FallbackDefault},
			m5SRBlock:  {Services: []string{"block"}, Via: []string{"home"}, Fallback: config.FallbackBlock},
		},
	}
	rules := []router.RuleState{
		m5SRTun:    {Tunnel: "de"},
		m5SRDirect: {},
		m5SRBlock:  {Fallback: true},
	}
	return cfg, rules, map[string]int{"de": 0}
}

// m5Sync records the calls of Server.Sync and what Dynamic held at each.
type m5Sync struct {
	calls atomic.Int32
	err   atomic.Pointer[error]
	mu    sync.Mutex
	dyn   [][]router.Dynamic
}

func (y *m5Sync) last() []router.Dynamic {
	y.mu.Lock()
	defer y.mu.Unlock()
	if len(y.dyn) == 0 {
		return nil
	}
	return y.dyn[len(y.dyn)-1]
}

// m5StartServer starts a Server with m5ServerCfg on 127.0.0.1:0, system
// upstream 127.0.0.1, and a Sync recorded in the returned m5Sync.
func m5StartServer(t *testing.T) (*Server, *m5Sync) {
	t.Helper()
	y := &m5Sync{}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.Sync = func() error {
		y.calls.Add(1)
		// Sync is called without Server's lock held: Dynamic must not
		// deadlock, and it already holds the new addresses (Build with
		// Dynamic() before the answer).
		d := s.Dynamic()
		y.mu.Lock()
		y.dyn = append(y.dyn, d)
		y.mu.Unlock()
		if e := y.err.Load(); e != nil {
			return *e
		}
		return nil
	}
	cfg, rules, ifaces := m5ServerCfg()
	ok := false
	m5NoPanic(t, "Server setup", func() {
		s.SetState(cfg, rules, ifaces)
		s.SetSystem([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
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
	return s, y
}

// m5Exchange sends one query to s; edns > 0 adds an EDNS0 OPT with that size.
func m5Exchange(t *testing.T, s *Server, network, name string, qtype, edns uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Net: network, Timeout: m5ClientTimeout}
	if edns > 0 {
		req.SetEdns0(edns, false)
		c.UDPSize = edns
	}
	resp, _, err := c.Exchange(req, s.Addr().String())
	if err != nil {
		t.Fatalf("%s %s %s: %v", network, name, dns.TypeToString[qtype], err)
	}
	if resp.Id != req.Id {
		t.Errorf("id = %d, want %d", resp.Id, req.Id)
	}
	if !slices.Equal(resp.Question, req.Question) {
		t.Errorf("question = %v, want %v", resp.Question, req.Question)
	}
	return resp
}

func m5Rcode(t *testing.T, m *dns.Msg, want int) {
	t.Helper()
	if m.Rcode != want {
		t.Errorf("rcode = %s, want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[want])
	}
}

// m5AnswerAddrs lists the A/AAAA addresses of the answer.
func m5AnswerAddrs(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.A:
			out = append(out, r.A.String())
		case *dns.AAAA:
			out = append(out, r.AAAA.String())
		}
	}
	return out
}

// --- tests -------------------------------------------------------------------

// Start, Addr: one port for UDP and TCP on 127.0.0.1 (design 7: loopback only).
func TestM5ServerAddr(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, _ := m5StartServer(t)
	a := s.Addr()
	if a.Addr() != netip.MustParseAddr("127.0.0.1") || a.Port() == 0 {
		t.Errorf("Addr = %v, want 127.0.0.1 with a port", a)
	}
}

// Start: a bind error (EADDRINUSE) is returned at once (M5 fact 13).
func TestM5ServerAddrInUse(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, _ := m5StartServer(t)
	s2 := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Sync: func() error { return nil }}
	cfg, rules, ifaces := m5ServerCfg()
	var err error
	m5NoPanic(t, "second Start", func() {
		s2.SetState(cfg, rules, ifaces)
		err = s2.Start(s.Addr().String())
	})
	if err == nil {
		_ = s2.Shutdown()
		t.Fatal("Start on a busy address succeeded")
	}
}

// design 7 steps 5, 6: UDP and TCP queries for a name without a rule go to
// an upstream and come back; no dynamic addresses, no Sync. The same for a
// dns_domains name (split DNS, no dynamic routes).
func TestM5ServerUDPAndTCP(t *testing.T) {
	u := m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)
	for _, network := range []string{"udp", "tcp"} {
		for _, name := range []string{"apple.test", "vault.corp.example"} {
			t.Run(network+" "+name, func(t *testing.T) {
				resp := m5Exchange(t, s, network, name, dns.TypeA, 0)
				m5Rcode(t, resp, dns.RcodeSuccess)
				if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
					t.Errorf("answer = %v, want [192.0.2.1]", got)
				}
			})
		}
	}
	if u.total() == 0 {
		t.Error("upstream was not asked")
	}
	if n := y.calls.Load(); n != 0 {
		t.Errorf("Sync called %d times for names without a rule", n)
	}
	if d := s.Dynamic(); len(d) != 0 {
		t.Errorf("Dynamic = %v, want none for names without a rule", d)
	}
}

// M5 "Модель" query step 3: TC from the upstream over UDP → the same query
// again over TCP.
func TestM5ServerUpstreamTCRetry(t *testing.T) {
	u := m5StartUpstream(t, func(r *dns.Msg, tcp bool) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(r)
		if !tcp {
			m.Truncated = true
			return m
		}
		m.Answer = []dns.RR{m5A(r.Question[0].Name, "192.0.2.77", 60)}
		return m
	})
	s, _ := m5StartServer(t)
	resp := m5Exchange(t, s, "udp", "tc.test", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
	if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.77"}) {
		t.Errorf("answer = %v, want [192.0.2.77] from the TCP retry", got)
	}
	if resp.Truncated {
		t.Error("TC passed on to the client")
	}
	if u.tcp.Load() == 0 {
		t.Error("no TCP query to the upstream after TC")
	}
}

// M5 "Модель" query step 6: the reply is truncated to the client's UDP size
// (512 without EDNS0, the OPT size with it); TCP gets everything.
func TestM5ServerTruncateToClient(t *testing.T) {
	const n = 25
	txt := strings.Repeat("x", 100)
	m5StartUpstream(t, m5Answer(func(q dns.Question) []dns.RR {
		var rrs []dns.RR
		for i := 0; i < n; i++ {
			rrs = append(rrs, &dns.TXT{Hdr: m5Hdr(q.Name, dns.TypeTXT, 60), Txt: []string{txt}})
		}
		return rrs
	}))
	s, _ := m5StartServer(t)

	t.Run("UDP without EDNS0: TC within 512 bytes", func(t *testing.T) {
		resp := m5Exchange(t, s, "udp", "big.test", dns.TypeTXT, 0)
		if !resp.Truncated {
			t.Error("TC not set")
		}
		if b, err := resp.Pack(); err == nil && len(b) > dns.MinMsgSize {
			t.Errorf("reply is %d bytes, over 512", len(b))
		}
		if len(resp.Answer) >= n {
			t.Errorf("answer has %d records, want fewer than %d", len(resp.Answer), n)
		}
	})
	t.Run("UDP with EDNS0 4096: all records", func(t *testing.T) {
		resp := m5Exchange(t, s, "udp", "big.test", dns.TypeTXT, 4096)
		if resp.Truncated || len(resp.Answer) != n {
			t.Errorf("TC %v, %d records; want no TC, %d", resp.Truncated, len(resp.Answer), n)
		}
	})
	t.Run("TCP: all records", func(t *testing.T) {
		resp := m5Exchange(t, s, "tcp", "big.test", dns.TypeTXT, 0)
		if resp.Truncated || len(resp.Answer) != n {
			t.Errorf("TC %v, %d records; want no TC, %d", resp.Truncated, len(resp.Answer), n)
		}
	})
}

// design 6.3, 7 step 2, decision 8: a rule in fallback: block → NODATA for
// any type, the upstream is not asked, no Sync, no dynamic addresses.
func TestM5ServerBlock(t *testing.T) {
	u := m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"example.com", dns.TypeA},
		{"example.com", dns.TypeAAAA},
		{"example.com", dns.TypeHTTPS},
		{"www.example.com", dns.TypeMX},
		{"WWW.Example.COM.", dns.TypeTXT},
	} {
		t.Run(q.name+" "+dns.TypeToString[q.qtype], func(t *testing.T) {
			resp := m5Exchange(t, s, "udp", q.name, q.qtype, 0)
			m5Rcode(t, resp, dns.RcodeSuccess)
			if len(resp.Answer) != 0 {
				t.Errorf("answer = %v, want empty", resp.Answer)
			}
			if !slices.ContainsFunc(resp.Ns, func(rr dns.RR) bool { _, ok := rr.(*dns.SOA); return ok }) {
				t.Errorf("authority = %v, want a SOA", resp.Ns)
			}
		})
	}
	resp := m5Exchange(t, s, "tcp", "example.com", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
	if len(resp.Answer) != 0 {
		t.Errorf("TCP: answer = %v, want empty", resp.Answer)
	}
	if n := u.total(); n != 0 {
		t.Errorf("upstream asked %d times for a blocked name", n)
	}
	if n := y.calls.Load(); n != 0 {
		t.Errorf("Sync called %d times for a blocked name", n)
	}
	if d := s.Dynamic(); len(d) != 0 {
		t.Errorf("Dynamic = %v, want none", d)
	}
}

// design 7 "IPv6", M5 "Модель" query step 4: AAAA dropped for a rule domain
// whose tunnel has no IPv6; kept for a direct rule and a name without a rule.
func TestM5ServerDropAAAA(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)

	resp := m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeAAAA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
	if got := m5AnswerAddrs(resp); len(got) != 0 {
		t.Errorf("ifconfig.me AAAA: answer = %v, want empty", got)
	}
	// No address left in the answer: nothing for Dynamics, no Sync.
	if n := y.calls.Load(); n != 0 {
		t.Errorf("Sync called %d times for a filtered answer", n)
	}

	resp = m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
	if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("ifconfig.me A: answer = %v, want [192.0.2.1]", got)
	}

	for _, name := range []string{"icanhazip.com", "apple.test"} {
		resp := m5Exchange(t, s, "udp", name, dns.TypeAAAA, 0)
		if got := m5AnswerAddrs(resp); !slices.Equal(got, []string{"2001:db8::1"}) {
			t.Errorf("%s AAAA: answer = %v, want [2001:db8::1]", name, got)
		}
	}
}

// design 7 "Домены из правил", M5 "Модель" query step 5: for a rule domain
// (on a tunnel or direct) Sync is called before the answer only when a new
// (name, address) pair appears, with the new address already in Dynamic.
func TestM5ServerSync(t *testing.T) {
	var (
		mu    sync.Mutex
		addrs = map[string]string{
			"ifconfig.me.":     "192.0.2.1",
			"www.ifconfig.me.": "192.0.2.1",
			"icanhazip.com.":   "192.0.2.3",
			"apple.test.":      "192.0.2.9",
		}
	)
	m5StartUpstream(t, m5Answer(func(q dns.Question) []dns.RR {
		mu.Lock()
		defer mu.Unlock()
		if a, ok := addrs[strings.ToLower(q.Name)]; ok && q.Qtype == dns.TypeA {
			return []dns.RR{m5A(q.Name, a, 60)}
		}
		return nil
	}))
	s, y := m5StartServer(t)

	steps := []struct {
		why   string
		name  string
		calls int32
		has   router.Dynamic // must be in Dynamic at the last Sync
	}{
		{"new pair on a tunnel rule", "ifconfig.me", 1, m5Dyn("192.0.2.1", m5SRTun)},
		{"the same pair again: no Sync", "ifconfig.me", 1, router.Dynamic{}},
		{"the same pair, other case: no Sync", "IfConfig.ME.", 1, router.Dynamic{}},
		{"known address, new name: a new pair", "www.ifconfig.me", 2, m5Dyn("192.0.2.1", m5SRTun)},
		{"direct rule: dynamic addresses too", "icanhazip.com", 3, m5Dyn("192.0.2.3", m5SRDirect)},
		{"no rule: no Sync", "apple.test", 3, router.Dynamic{}},
	}
	for _, st := range steps {
		resp := m5Exchange(t, s, "udp", st.name, dns.TypeA, 0)
		m5Rcode(t, resp, dns.RcodeSuccess)
		if len(m5AnswerAddrs(resp)) != 1 {
			t.Errorf("%s: answer = %v, want one address", st.why, resp.Answer)
		}
		// Sync runs before the reply: its count is final once the reply is in.
		if n := y.calls.Load(); n != st.calls {
			t.Errorf("%s: Sync called %d times in all, want %d", st.why, n, st.calls)
		}
		if st.has.Addr.IsValid() && !slices.Contains(y.last(), st.has) {
			t.Errorf("%s: Dynamic at Sync = %v, want it to hold %v", st.why, y.last(), st.has)
		}
	}

	// Dynamic and Expire (decision 4: deadline TTL + 1 h).
	want := []router.Dynamic{m5Dyn("192.0.2.1", m5SRTun), m5Dyn("192.0.2.3", m5SRDirect)}
	if got := s.Dynamic(); !slices.Equal(got, want) {
		t.Errorf("Dynamic = %v, want %v", got, want)
	}
	if s.Expire(time.Now()) {
		t.Error("Expire now removed something")
	}
	if s.Expire(time.Now().Add(59 * time.Minute)) {
		t.Error("Expire before TTL + 1 h removed something")
	}
	if !s.Expire(time.Now().Add(2 * time.Hour)) {
		t.Error("Expire after TTL + 1 h removed nothing")
	}
	if got := s.Dynamic(); len(got) != 0 {
		t.Errorf("Dynamic after Expire = %v, want none", got)
	}
	if s.Expire(time.Now().Add(3 * time.Hour)) {
		t.Error("second Expire removed something")
	}
	// After expiry the same answer is a new pair again.
	m5Exchange(t, s, "udp", "ifconfig.me", dns.TypeA, 0)
	if n := y.calls.Load(); n != 4 {
		t.Errorf("Sync after expiry: %d calls in all, want 4", n)
	}
}

// design 7, decision 5: an error of Sync → SERVFAIL (an answer without the
// route would send the connection directly).
func TestM5ServerSyncError(t *testing.T) {
	m5StartUpstream(t, m5AddrAnswer("192.0.2.1", "2001:db8::1"))
	s, y := m5StartServer(t)
	e := errors.New("route add: file exists")
	y.err.Store(&e)

	for _, name := range []string{"ifconfig.me", "icanhazip.com"} {
		resp := m5Exchange(t, s, "udp", name, dns.TypeA, 0)
		m5Rcode(t, resp, dns.RcodeServerFailure)
		if got := m5AnswerAddrs(resp); len(got) != 0 {
			t.Errorf("%s: SERVFAIL carries addresses %v", name, got)
		}
	}
	if y.calls.Load() == 0 {
		t.Error("Sync not called")
	}
	// A name without a rule needs no Sync and is answered.
	resp := m5Exchange(t, s, "udp", "apple.test", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeSuccess)
}

// design 7, decision 10: no answer from any server (2 s each) → SERVFAIL.
func TestM5ServerUpstreamSilent(t *testing.T) {
	u := m5StartUpstream(t, func(*dns.Msg, bool) *dns.Msg { return nil })
	s, y := m5StartServer(t)
	start := time.Now()
	resp := m5Exchange(t, s, "udp", "apple.test", dns.TypeA, 0)
	m5Rcode(t, resp, dns.RcodeServerFailure)
	if el := time.Since(start); el < upstreamTimeout/2 {
		t.Errorf("SERVFAIL after %v, before the upstream timeout %v", el, upstreamTimeout)
	}
	if u.total() == 0 {
		t.Error("upstream was not asked")
	}
	if n := y.calls.Load(); n != 0 {
		t.Errorf("Sync called %d times", n)
	}
}
