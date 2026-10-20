package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

const (
	maxInflight     = 256             // concurrent upstream queries; over it: SERVFAIL (M5 decision 10)
	upstreamTimeout = 2 * time.Second // per upstream server (M5 decision 10)
)

// upstreamPort is the port of upstream servers; tests point it at a fake
// upstream on 127.0.0.1.
var upstreamPort uint16 = 53

// Server is the resolver on 127.0.0.1:53 (design 7). Safe for concurrent
// use; Sync is called without Server's lock held.
//
// A query: Choose; Block → NoData; else the servers of the upstream in turn
// (upstreamTimeout each, UDP, TCP again on TC; the socket of a tunnel
// upstream bound to its utun). A server that does not answer, or answers
// SERVFAIL or REFUSED, passes the query to the next one; if none gives a
// better answer, the last SERVFAIL/REFUSED goes to the client, and with no
// answer at all the client gets SERVFAIL. Then Filter; for a rule domain the
// addresses go to Dynamics before the reply (see below). The reply is
// truncated to the client's UDP size (512 without EDNS0).
//
// Every Dynamics.Add that records a new pair starts a new generation. An
// answer with rule addresses goes out only once a successful Sync has begun
// at or after the generation of its own Add; otherwise Sync is called first.
// A *router.SyncError whose Failed has no host prefix (/32, /128) of this
// answer's addresses lets the answer go out without covering its generation
// (M7 accumulated task 4); any other error → SERVFAIL. So a concurrent answer for the same pair (a retry
// of mDNSResponder) waits for a Sync of its own instead of going out before
// the route is set, and after a failed Sync the next such answer calls Sync
// again.
//
// A rule's tunnel missing from ifaces gives SERVFAIL: an unbound socket would
// send the query directly.
type Server struct {
	Log  *slog.Logger
	Sync func() error // Build with Dynamic() and router.Sync; before an answer with new addresses

	mu        sync.Mutex
	cfg       *config.Config
	rules     []router.RuleState
	ifaces    map[string]int // tunnel → utun index
	system    []netip.Addr   // system upstream servers
	dyn       Dynamics
	evictWarn time.Time // last eviction warning, at most one a minute
	gen       uint64    // bumped by every Add that records a new pair
	syncedGen uint64    // the latest gen covered by a successful Sync

	sem      chan struct{} // maxInflight slots for upstream queries
	udp, tcp *dns.Server
	addr     netip.AddrPort
	errc     chan error // serving errors after Start, see Err
}

// Invalidate makes the next answer with rule addresses call Sync (a Sync
// of the daemon failed).
func (s *Server) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncedGen = 0 // every pair has gen ≥ 1
}

// SetState sets the config, rule decisions and utun indexes (tunnel →
// interface index) used for new queries.
func (s *Server) SetState(cfg *config.Config, rules []router.RuleState, ifaces map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.rules, s.ifaces = cfg, slices.Clone(rules), maps.Clone(ifaces)
}

// SetSystem sets the system upstream servers.
func (s *Server) SetSystem(servers []netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.system = slices.Clone(servers)
}

// Dynamic returns Dynamics.List under the current state, for router.Build.
// Before SetState: nil.
func (s *Server) Dynamic() []router.Dynamic {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return nil
	}
	return s.dyn.List(s.cfg, s.rules)
}

// Pairs returns Dynamics.Pairs under the lock.
func (s *Server) Pairs() []Pair {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dyn.Pairs()
}

// Expire drops expired dynamic addresses; true: the table must be synced.
func (s *Server) Expire(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dyn.Expire(now)
}

// Start binds UDP and TCP on addr ("127.0.0.1:53"; "127.0.0.1:0" in tests,
// one port for both) and serves in the background. It returns after both are
// bound: a bind error (EADDRINUSE) is returned at once.
func (s *Server) Start(addr string) error {
	pc, ln, err := listen(addr)
	if err != nil {
		return err
	}
	s.addr = pc.LocalAddr().(*net.UDPAddr).AddrPort()
	s.sem = make(chan struct{}, maxInflight)
	s.errc = make(chan error, 2)
	h := dns.HandlerFunc(s.serve)
	var started sync.WaitGroup
	started.Add(2)
	s.udp = &dns.Server{PacketConn: pc, Handler: h, UDPSize: dns.DefaultMsgSize, NotifyStartedFunc: started.Done}
	s.tcp = &dns.Server{Listener: ln, Handler: h, NotifyStartedFunc: started.Done}
	for i, srv := range []*dns.Server{s.udp, s.tcp} {
		go func() {
			// nil after Shutdown; an error means serving has stopped.
			if err := srv.ActivateAndServe(); err != nil {
				s.errc <- fmt.Errorf("dns %s: %w", [...]string{"udp", "tcp"}[i], err)
			}
		}()
	}
	started.Wait() // Shutdown fails on a server not started yet
	return nil
}

// listen binds UDP and then TCP on addr; with port 0, TCP takes the port UDP
// got, and a few ports are tried if that one is taken for TCP.
func listen(addr string) (net.PacketConn, net.Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dns listen: %w", err)
	}
	for try := 0; ; try++ {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("dns listen: %w", err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", net.JoinHostPort(ap.Addr().String(), strconv.Itoa(port)))
		if err == nil {
			return pc, ln, nil
		}
		pc.Close()
		if ap.Port() != 0 || try == 9 {
			return nil, nil, fmt.Errorf("dns listen: %w", err)
		}
	}
}

// Err returns the channel that receives an error when serving UDP or TCP
// stops after Start other than by Shutdown (at most one per listener). The
// resolver no longer answers then: the caller stops. Before Start: nil (a
// receive blocks forever).
func (s *Server) Err() <-chan error {
	return s.errc
}

// Addr returns the bound address (for tests with port 0).
func (s *Server) Addr() netip.AddrPort {
	return s.addr
}

// Shutdown stops both listeners and waits for in-flight queries. Without
// Start: nil.
func (s *Server) Shutdown() error {
	var errs []error
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		if srv != nil {
			if err := srv.Shutdown(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// log returns s.Log or a logger that drops everything.
func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// serve answers one query and logs it at debug level.
func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	reply, c, added, err := s.resolve(req)
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		reply.Truncate(size)
	}
	if werr := w.WriteMsg(reply); werr != nil {
		err = errors.Join(err, fmt.Errorf("write reply: %w", werr))
	}

	log := s.log()
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	upstream := "system"
	switch {
	case c.Block:
		upstream = "block" // NODATA, no upstream asked
	case c.Tunnel != "":
		upstream = c.Tunnel
	}
	var name, typ string
	if len(req.Question) > 0 {
		name, typ = req.Question[0].Name, dns.TypeToString[req.Question[0].Qtype]
	}
	attrs := []any{"name", name, "type", typ, "upstream", upstream, "rule", c.Rule, "rcode", dns.RcodeToString[reply.Rcode]}
	if len(added) > 0 {
		attrs = append(attrs, "added", added)
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	log.Debug("dns query", attrs...)
}

// resolve answers req (see Server). It returns the reply, the choice for
// the queried name, the addresses recorded as new and the reason of a
// SERVFAIL.
func (s *Server) resolve(req *dns.Msg) (*dns.Msg, Choice, []netip.Addr, error) {
	c := Choice{Rule: -1}
	if len(req.Question) == 0 {
		return new(dns.Msg).SetRcode(req, dns.RcodeFormatError), c, nil, errors.New("no question")
	}
	name := req.Question[0].Name

	s.mu.Lock()
	cfg, rules, ifaces, system := s.cfg, s.rules, s.ifaces, s.system
	s.mu.Unlock()
	if cfg != nil {
		c = Choose(cfg, rules, ifaces, name)
	}
	if c.Block {
		return NoData(req), c, nil, nil
	}

	servers, index := system, 0
	if c.Tunnel != "" {
		idx, ok := ifaces[c.Tunnel]
		t := findTunnel(cfg, c.Tunnel)
		if !ok || t == nil {
			return servfail(req), c, nil, fmt.Errorf("tunnel %s has no utun", c.Tunnel)
		}
		servers, index = Servers(t), idx
	}

	select {
	case s.sem <- struct{}{}:
	default:
		return servfail(req), c, nil, errors.New("too many upstream queries")
	}
	r, err := exchange(req, servers, index)
	<-s.sem
	if err != nil {
		return servfail(req), c, nil, err
	}

	Filter(r, c)
	if c.Rule < 0 {
		return r, c, nil, nil
	}
	addrs, ttl := Addrs(r)
	if len(addrs) == 0 {
		return r, c, nil, nil
	}
	now := time.Now()
	s.mu.Lock()
	added, evicted := s.dyn.Add(name, addrs, ttl, now)
	if added {
		s.gen++
	}
	my := s.gen // the generation that covers this answer's pairs
	need := s.syncedGen < my
	warn := evicted > 0 && now.Sub(s.evictWarn) >= time.Minute
	if warn {
		s.evictWarn = now
	}
	s.mu.Unlock()
	if warn {
		s.log().Warn("dns: dynamic address limit reached, the earliest evicted", "limit", dynamicLimit, "evicted", evicted)
	}
	if !need || s.Sync == nil {
		return r, c, nil, nil
	}
	// Without s.mu: Sync calls Dynamic. A successful Sync covers every
	// generation recorded before it started.
	s.mu.Lock()
	g := s.gen
	s.mu.Unlock()
	if err := s.Sync(); err != nil {
		var se *router.SyncError
		if !errors.As(err, &se) || failedAny(se.Failed, addrs) {
			return servfail(req), c, nil, fmt.Errorf("sync routes: %w", err)
		}
		// Only routes of other prefixes failed (the caller of Sync logs
		// them): the answer goes out, but its generation is not covered, so
		// the next answer syncs again.
		if !added {
			addrs = nil
		}
		return r, c, addrs, nil
	}
	s.mu.Lock()
	s.syncedGen = max(s.syncedGen, g)
	s.mu.Unlock()
	if !added {
		addrs = nil
	}
	return r, c, addrs, nil
}

// failedAny reports whether failed holds the host prefix (/32, /128) of
// one of addrs.
func failedAny(failed []netip.Prefix, addrs []netip.Addr) bool {
	for _, p := range failed {
		if !p.IsSingleIP() {
			continue
		}
		for _, a := range addrs {
			if p.Addr().Unmap() == a.Unmap() {
				return true
			}
		}
	}
	return false
}

// exchange sends req to servers in turn (upstreamPort, a socket bound to
// index, 0: unbound) and returns the first answer other than SERVFAIL or
// REFUSED; if every answer was one of those, the last of them; with req's id.
// No answer at all is an error.
func exchange(req *dns.Msg, servers []netip.Addr, index int) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no upstream servers")
	}
	q := req.Copy()
	q.Id = dns.Id()
	d := boundDialer(index)
	var (
		errs []error
		last *dns.Msg // the last SERVFAIL/REFUSED answer
	)
	for _, srv := range servers {
		addr := net.JoinHostPort(srv.String(), strconv.Itoa(int(upstreamPort)))
		r, err := exchangeOne(q, addr, d)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		r.Id = req.Id
		r.Compress = true
		if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
			last = r
			continue
		}
		return r, nil
	}
	if last != nil {
		return last, nil
	}
	return nil, errors.Join(errs...)
}

// exchangeOne asks one server within upstreamTimeout: UDP, then TCP when the
// UDP answer is truncated.
func exchangeOne(q *dns.Msg, addr string, d *net.Dialer) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()
	// UDPSize (without EDNS0 in q): read whatever the server sends; the
	// reply is truncated for the client later.
	c := &dns.Client{Net: "udp", Dialer: d, Timeout: upstreamTimeout, UDPSize: dns.MaxMsgSize}
	r, _, err := c.ExchangeContext(ctx, q, addr)
	if err != nil {
		return nil, err
	}
	if !r.Truncated {
		return r, nil
	}
	c.Net = "tcp"
	r, _, err = c.ExchangeContext(ctx, q, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp after truncated udp: %w", err)
	}
	return r, nil
}

// servfail returns the SERVFAIL reply to req.
func servfail(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	m.RecursionAvailable = true
	return m
}
