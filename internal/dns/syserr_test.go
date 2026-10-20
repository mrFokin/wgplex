package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

const resolvConfServer = "127.0.0.1:53"

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// M9 plan decision 12: a *net.DNSError gets Server replaced by the servers
// the lookup actually went to (comma-separated, addresses only); every other
// field stays the same.
func TestSystemErrorDNSError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		orig    net.DNSError
		servers []netip.Addr
		want    string // Server in the result
	}{
		{
			name:    "one server, not found",
			orig:    net.DNSError{Err: "no such host", Name: "vpn.example", Server: resolvConfServer, IsNotFound: true},
			servers: addrs("192.168.20.1"),
			want:    "192.168.20.1",
		},
		{
			name:    "two servers, timeout",
			orig:    net.DNSError{Err: "i/o timeout", Name: "vpn.example", Server: resolvConfServer, IsTimeout: true, IsTemporary: true},
			servers: addrs("192.168.20.1", "1.1.1.1"),
			want:    "192.168.20.1,1.1.1.1",
		},
		{
			name:    "ipv6 server without brackets or port",
			orig:    net.DNSError{Err: "no such host", Name: "vpn.example", Server: resolvConfServer, IsNotFound: true},
			servers: addrs("2001:db8::53", "192.168.20.1"),
			want:    "2001:db8::53,192.168.20.1",
		},
		{
			name:    "empty Server in original",
			orig:    net.DNSError{Err: "server misbehaving", Name: "vpn.example", IsTemporary: true},
			servers: addrs("10.0.0.1"),
			want:    "10.0.0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := tc.orig
			saved := orig

			got := SystemError(&orig, tc.servers)

			var de *net.DNSError
			if !errors.As(got, &de) {
				t.Fatalf("SystemError = %T %v, want *net.DNSError", got, got)
			}
			want := saved
			want.Server = tc.want
			if *de != want {
				t.Errorf("result = %+v, want %+v", *de, want)
			}
			msg := got.Error()
			if !strings.Contains(msg, tc.want) {
				t.Errorf("message %q does not name servers %q", msg, tc.want)
			}
			if strings.Contains(msg, resolvConfServer) {
				t.Errorf("message %q still names %s", msg, resolvConfServer)
			}
			if de == &orig {
				t.Error("result is the original *net.DNSError, want a copy")
			}
			if orig != saved {
				t.Errorf("original modified: %+v, was %+v", orig, saved)
			}
		})
	}
}

// M9 plan decision 12: a wrapped *net.DNSError keeps its wrapping; errors.As
// on the result finds the copy with the new Server.
func TestSystemErrorWrapped(t *testing.T) {
	servers := addrs("192.168.20.1", "1.1.1.1")
	const wantServer = "192.168.20.1,1.1.1.1"

	for _, tc := range []struct {
		name string
		wrap func(error) error
	}{
		{"one level", func(e error) error { return fmt.Errorf("resolve: %w", e) }},
		{"two levels", func(e error) error {
			return fmt.Errorf("resolve endpoints: %w", fmt.Errorf("tunnel home: %w", e))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dnsErr := &net.DNSError{Err: "no such host", Name: "vpn.example", Server: resolvConfServer, IsNotFound: true}
			saved := *dnsErr
			orig := tc.wrap(dnsErr)
			origMsg := orig.Error()

			got := SystemError(orig, servers)

			var de *net.DNSError
			if !errors.As(got, &de) {
				t.Fatalf("errors.As(%v) found no *net.DNSError", got)
			}
			want := saved
			want.Server = wantServer
			if *de != want {
				t.Errorf("unwrapped = %+v, want %+v", *de, want)
			}
			// Same wrapping, only the DNS part of the message changes.
			wantMsg := strings.Replace(origMsg, saved.Error(), want.Error(), 1)
			if got.Error() != wantMsg {
				t.Errorf("message = %q, want %q", got.Error(), wantMsg)
			}
			if strings.Contains(got.Error(), resolvConfServer) {
				t.Errorf("message %q still names %s", got.Error(), resolvConfServer)
			}
			if *dnsErr != saved {
				t.Errorf("original DNSError modified: %+v", *dnsErr)
			}
			if orig.Error() != origMsg {
				t.Errorf("original error message changed: %q", orig.Error())
			}
		})
	}
}

// M9 plan decision 12: non-DNS errors, nil and an empty server list give err
// unchanged.
func TestSystemErrorUnchanged(t *testing.T) {
	plain := errors.New("connection refused")
	wrappedPlain := fmt.Errorf("resolve: %w", plain)
	dnsErr := &net.DNSError{Err: "no such host", Name: "vpn.example", Server: resolvConfServer, IsNotFound: true}
	wrappedDNS := fmt.Errorf("resolve: %w", dnsErr)

	for _, tc := range []struct {
		name    string
		err     error
		servers []netip.Addr
	}{
		{"nil error", nil, addrs("192.168.20.1")},
		{"nil error, nil servers", nil, nil},
		{"non-DNS error", plain, addrs("192.168.20.1")},
		{"wrapped non-DNS error", wrappedPlain, addrs("192.168.20.1")},
		{"DNS error, nil servers", dnsErr, nil},
		{"DNS error, empty servers", dnsErr, []netip.Addr{}},
		{"wrapped DNS error, empty servers", wrappedDNS, []netip.Addr{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SystemError(tc.err, tc.servers)
			if got != tc.err {
				t.Errorf("SystemError = %v, want the same error %v", got, tc.err)
			}
		})
	}
	if dnsErr.Server != resolvConfServer {
		t.Errorf("original DNSError modified: Server = %q", dnsErr.Server)
	}
}
