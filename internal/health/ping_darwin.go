package health

import (
	"context"
	"crypto/rand"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// lastID is the ICMP id of the last Pinger; it starts at a random value so
// that a restarted daemon does not take the replies meant for the old one.
var lastID atomic.Uint32

func init() {
	lastID.Store(mrand.Uint32())
}

// Pinger pings dst through the interface index (IP_BOUND_IF/IPV6_BOUND_IF,
// IP_STRIPHDR, connect); the scoped route to dst is the caller's. It is
// closed together with its tunnel. Check is not safe for concurrent use with
// itself; Close may be called during a Check.
//
// Every ICMP socket of the process gets every ICMP reply that connect does
// not filter out (Wirefork M7 fact 6), so a reply is matched by id, seq and a random
// nonce in its data.
type Pinger struct {
	conn net.Conn   // SOCK_DGRAM ICMP socket, connected to dst
	dst  netip.Addr // the check address
	id   uint16     // unique per Pinger
	seq  uint16     // of the last request
}

// NewPinger opens a Pinger to dst through the interface index; its id is
// unique per Pinger.
func NewPinger(index int, dst netip.Addr) (*Pinger, error) {
	dst = dst.Unmap()
	v6 := dst.Is6()
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if v6 {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, proto)
	if err != nil {
		return nil, fmt.Errorf("ping %s: socket: %w", dst, err)
	}
	fail := func(what string, err error) (*Pinger, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("ping %s: %s: %w", dst, what, err)
	}
	var sa unix.Sockaddr
	if v6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index); err != nil {
			return fail("IPV6_BOUND_IF", err)
		}
		sa = &unix.SockaddrInet6{Addr: dst.As16()}
	} else {
		// Replies come without the IP header, like ICMPv6 ones.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_STRIPHDR, 1); err != nil {
			return fail("IP_STRIPHDR", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index); err != nil {
			return fail("IP_BOUND_IF", err)
		}
		sa = &unix.SockaddrInet4{Addr: dst.As4()}
	}
	if err := unix.Connect(fd, sa); err != nil {
		return fail("connect", err)
	}
	f := os.NewFile(uintptr(fd), "icmp")
	pc, err := net.FilePacketConn(f) // a dup of fd, in the runtime poller
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("ping %s: %w", dst, err)
	}
	conn, ok := pc.(net.Conn)
	if !ok { // cannot happen: FilePacketConn returns a *UDPConn for SOCK_DGRAM
		pc.Close()
		return nil, fmt.Errorf("ping %s: unexpected connection type %T", dst, pc)
	}
	return &Pinger{conn: conn, dst: dst, id: uint16(lastID.Add(1))}, nil
}

// Check sends one echo request and waits for its reply until ctx is done
// (PingTimeout without a deadline in ctx).
func (p *Pinger) Check(ctx context.Context) PingResult {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, PingTimeout)
		defer cancel()
	}
	deadline, _ := ctx.Deadline()
	if err := p.conn.SetReadDeadline(deadline); err != nil {
		return PingResult{Done: true}
	}
	// Cancelling ctx before the deadline ends the read at once.
	stop := context.AfterFunc(ctx, func() { p.conn.SetReadDeadline(time.Now()) })
	defer stop()

	p.seq++
	nonce := make([]byte, 8)
	rand.Read(nonce)
	v6 := p.dst.Is6()
	start := time.Now()
	if _, err := p.conn.Write(echoRequest(v6, p.id, p.seq, nonce)); err != nil {
		return PingResult{Done: true}
	}
	buf := make([]byte, 1500)
	for {
		n, err := p.conn.Read(buf)
		if err != nil { // the deadline, ctx, Close or an ICMP error
			return PingResult{Done: true}
		}
		if isReply(v6, buf[:n], p.id, p.seq, nonce) {
			return PingResult{Done: true, OK: true, RTT: time.Since(start)}
		}
	}
}

// Close closes the socket.
func (p *Pinger) Close() error {
	return p.conn.Close()
}
