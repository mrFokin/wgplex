package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/router"
)

// HTTPChecker gets url through the interface index (design 8): sockets bound
// by IP_BOUND_IF/IPV6_BOUND_IF, a scoped host route to the address
// (router.AddScoped) put before a request unless one to the address is
// already in place (AddScoped replaces the route), no redirects, no
// keep-alive, no proxy from the environment; the certificate is verified for the URL host. A host name
// is resolved on every check through the tunnel DNS (dns.TunnelResolver).
// Check is not safe for concurrent use with itself; Close may be called
// during a Check.
type HTTPChecker struct {
	client  *http.Client
	url     string
	index   int
	servers []netip.Addr
	ipv6    bool

	// dialed is the address the current Check connects to; routed is the
	// set of addresses with a scoped route in place: one is added by a
	// successful Check and removed by a failed one, so a name resolving to
	// several addresses in turn does not replace its routes on every check.
	// The routes live as long as the utun. Under mu: a dial of a canceled
	// request may end after its Check.
	mu     sync.Mutex
	dialed netip.Addr
	routed map[netip.Addr]bool

	closed context.Context // done after Close: a Check in progress gives up
	close  context.CancelFunc
}

// NewHTTPChecker returns a checker of url through index; servers resolve a
// host name (dns.Servers of the tunnel), ipv6 picks the family.
func NewHTTPChecker(index int, url string, servers []netip.Addr, ipv6 bool) (*HTTPChecker, error) {
	if index <= 0 {
		return nil, fmt.Errorf("http %s: bad interface index %d", url, index)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("http %s: %w", url, err)
	}
	if req.URL.Hostname() == "" {
		return nil, fmt.Errorf("http %s: no host", url)
	}
	c := &HTTPChecker{url: url, index: index, servers: servers, ipv6: ipv6, routed: map[netip.Addr]bool{}}
	c.closed, c.close = context.WithCancel(context.Background())
	c.client = &http.Client{
		Transport: &http.Transport{
			Proxy:             nil, // no proxy from the environment
			DialContext:       c.dial,
			DisableKeepAlives: true, // every check is a new connection
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is a response too
		},
	}
	return c, nil
}

// Check makes one GET of the URL within HTTPTimeout (or ctx, whichever ends
// first). Any HTTP response is OK; RTT is the time to its headers, the body
// is not read. A failure (resolve, route, connect, TLS, timeout) has Err set.
func (c *HTTPChecker) Check(ctx context.Context) PingResult {
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	stop := context.AfterFunc(c.closed, cancel)
	defer stop()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil { // cannot happen: checked by NewHTTPChecker
		return PingResult{Done: true, Err: err.Error()}
	}
	c.mu.Lock()
	c.dialed = netip.Addr{}
	c.mu.Unlock()
	start := time.Now()
	resp, err := c.client.Do(req)
	rtt := time.Since(start)
	if err != nil {
		c.mu.Lock()
		delete(c.routed, c.dialed) // the next check to it puts the route again
		c.mu.Unlock()
		return PingResult{Done: true, Err: httpErr(ctx, err)}
	}
	resp.Body.Close()
	c.mu.Lock()
	if c.dialed.IsValid() {
		c.routed[c.dialed] = true
	}
	c.mu.Unlock()
	return PingResult{Done: true, OK: true, RTT: rtt}
}

// Close closes idle connections; it is idempotent.
func (c *HTTPChecker) Close() error {
	c.close()
	c.client.CloseIdleConnections()
	return nil
}

// dial connects to addr (host:port of the URL) through the utun: a host
// name is resolved through the tunnel DNS, a scoped route to the address is
// put in place unless the address is in routed, the socket is bound to the
// utun.
func (c *HTTPChecker) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		network := "ip4"
		if c.ipv6 {
			network = "ip6"
		}
		addrs, err := dns.TunnelResolver(c.servers, c.index).LookupNetIP(ctx, network, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", host)
		}
		a = addrs[0]
	}
	a = a.Unmap()
	c.mu.Lock()
	routed := c.routed[a]
	c.mu.Unlock()
	if !routed {
		if err := router.AddScoped(a, c.index); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	c.dialed = a
	c.mu.Unlock()
	network := "tcp4"
	if a.Is6() {
		network = "tcp6"
	}
	d := net.Dialer{Control: c.bind}
	return d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
}

// bind binds the socket to the utun (IP_BOUND_IF or IPV6_BOUND_IF by the
// address family).
func (c *HTTPChecker) bind(network, _ string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		if network == "tcp6" {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, c.index)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, c.index)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// httpErr is the text of a failed GET for Reason: without the method and
// the URL (Reason names it), a timeout as "timeout after 5s" (HTTPTimeout).
func httpErr(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("timeout after %s", HTTPTimeout)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}
