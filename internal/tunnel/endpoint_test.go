package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// fakeResolver answers from a fixed table and records the hosts it was asked
// about. It honours the network argument ("ip", "ip4", "ip6") the way
// *net.Resolver does, so the code under test may query either way.
type fakeResolver struct {
	addrs map[string][]netip.Addr
	err   error
	calls []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, host)
	if r.err != nil {
		return nil, r.err
	}
	var out []netip.Addr
	for _, a := range r.addrs[host] {
		switch network {
		case "ip4":
			if a.Unmap().Is4() {
				out = append(out, a)
			}
		case "ip6":
			if !a.Unmap().Is4() {
				out = append(out, a)
			}
		default:
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// testKey returns a fresh random key, clamped like a Curve25519 private key
// so wireguard-go stores it unchanged.
func testKey(t *testing.T) config.Key {
	t.Helper()
	var k config.Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k
}

// keyForms returns the textual forms a key could leak in.
func keyForms(k config.Key) []string {
	return []string{
		hex.EncodeToString(k[:]),
		strings.ToUpper(hex.EncodeToString(k[:])),
		base64.StdEncoding.EncodeToString(k[:]),
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// design 5: the endpoint domain is resolved when the tunnel starts — first
// IPv4, else first IPv6; an IP literal is used as is; no Endpoint, no address.
func TestResolveEndpoints(t *testing.T) {
	table := map[string][]netip.Addr{
		"v4.example.com":     addrs("198.51.100.1", "198.51.100.2"),
		"mixed.example.com":  addrs("2001:db8::10", "198.51.100.20", "198.51.100.21", "2001:db8::11"),
		"v6.example.com":     addrs("2001:db8::30", "2001:db8::31"),
		"mapped.example.com": addrs("::ffff:198.51.100.40"),
	}
	tests := []struct {
		name      string
		endpoint  string
		want      string // "" — zero AddrPort
		wantCalls int    // resolver calls expected (-1: don't care, >0)
	}{
		{"IPv4 literal is used as is", "203.0.113.5:51820", "203.0.113.5:51820", 0},
		{"IPv6 literal is used as is", "[2001:db8::5]:51820", "[2001:db8::5]:51820", 0},
		{"IPv4-mapped literal is unmapped", "[::ffff:203.0.113.6]:51820", "203.0.113.6:51820", 0},
		{"no Endpoint gives zero AddrPort", "", "", 0},
		{"domain with IPv4 only: first IPv4", "v4.example.com:51820", "198.51.100.1:51820", -1},
		{"domain with IPv4 and IPv6: first IPv4 wins", "mixed.example.com:443", "198.51.100.20:443", -1},
		{"domain with IPv6 only: first IPv6", "v6.example.com:51821", "[2001:db8::30]:51821", -1},
		{"resolved IPv4-mapped address is unmapped", "mapped.example.com:51820", "198.51.100.40:51820", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeResolver{addrs: table}
			peers := []config.Peer{{PublicKey: testKey(t), Endpoint: tt.endpoint}}
			got, err := ResolveEndpoints(context.Background(), r, peers)
			if err != nil {
				t.Fatalf("ResolveEndpoints(%q): %v", tt.endpoint, err)
			}
			if len(got) != 1 {
				t.Fatalf("len = %d, want 1", len(got))
			}
			var want netip.AddrPort
			if tt.want != "" {
				want = netip.MustParseAddrPort(tt.want)
			}
			if got[0] != want {
				t.Errorf("endpoint %q → %v, want %v", tt.endpoint, got[0], want)
			}
			switch {
			case tt.wantCalls == 0 && len(r.calls) != 0:
				t.Errorf("resolver called for %q: %v", tt.endpoint, r.calls)
			case tt.wantCalls < 0 && len(r.calls) == 0:
				t.Errorf("resolver not called for %q", tt.endpoint)
			}
			for _, h := range r.calls {
				if strings.Contains(h, ":") {
					t.Errorf("resolver asked for %q: host must not carry the port", h)
				}
			}
		})
	}
}

// Index of the result is the peer index, including peers without Endpoint.
func TestResolveEndpointsPeerOrder(t *testing.T) {
	r := &fakeResolver{addrs: map[string][]netip.Addr{
		"vpn.example.com": addrs("198.51.100.7"),
	}}
	peers := []config.Peer{
		{PublicKey: testKey(t), Endpoint: "vpn.example.com:1000"},
		{PublicKey: testKey(t)},
		{PublicKey: testKey(t), Endpoint: "203.0.113.9:2000"},
	}
	got, err := ResolveEndpoints(context.Background(), r, peers)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:1000"),
		{},
		netip.MustParseAddrPort("203.0.113.9:2000"),
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("peer %d: %v, want %v", i, got[i], want[i])
		}
	}
}

func TestResolveEndpointsNoPeers(t *testing.T) {
	got, err := ResolveEndpoints(context.Background(), &fakeResolver{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// Errors: zones are rejected, resolver failures surface; error texts carry
// no keys (design 9.4).
func TestResolveEndpointsErrors(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		r        *fakeResolver
	}{
		{"zone in IPv6 literal", "[fe80::1%en0]:51820", &fakeResolver{}},
		{"resolved address with zone", "zoned.example.com:51820", &fakeResolver{addrs: map[string][]netip.Addr{
			"zoned.example.com": {netip.MustParseAddr("fe80::1%en0")},
		}}},
		{"resolver error", "vpn.example.com:51820", &fakeResolver{err: errors.New("lookup failed")}},
		{"unknown host", "nowhere.example.com:51820", &fakeResolver{addrs: map[string][]netip.Addr{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, psk := testKey(t), testKey(t)
			peers := []config.Peer{
				{PublicKey: testKey(t), Endpoint: "203.0.113.1:51820"},
				{PublicKey: k, PresharedKey: psk, Endpoint: tt.endpoint},
			}
			_, err := ResolveEndpoints(context.Background(), tt.r, peers)
			if err == nil {
				t.Fatalf("ResolveEndpoints(%q): want error", tt.endpoint)
			}
			for _, f := range append(keyForms(k), keyForms(psk)...) {
				if strings.Contains(err.Error(), f) {
					t.Errorf("error %q contains a key", err)
				}
			}
		})
	}
}
