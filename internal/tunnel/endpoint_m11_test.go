package tunnel

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 6 (DDNS: endpoints with a host name are resolved
// again) and the Wirefork M11 plan ("Модель → DDNS и повтор", "Сигнатуры →
// internal/tunnel"), not the implementation. Keys are generated per test.

// design 6: HasHostnames — some peer endpoint is a host name, not an IP
// literal; a peer without Endpoint does not count.
func TestM11HasHostnames(t *testing.T) {
	peer := func(ep string) config.Peer { return config.Peer{PublicKey: testKey(t), Endpoint: ep} }
	cases := []struct {
		name  string
		peers []config.Peer
		want  bool
	}{
		{"no peers", nil, false},
		{"no endpoint", []config.Peer{peer("")}, false},
		{"IPv4 literal", []config.Peer{peer("203.0.113.1:51820")}, false},
		{"IPv6 literal", []config.Peer{peer("[2001:db8::1]:51820")}, false},
		{"literals and no endpoint", []config.Peer{peer("203.0.113.1:51820"), peer(""), peer("[2001:db8::5]:51821")}, false},
		{"host name", []config.Peer{peer("vpn.example.com:51820")}, true},
		{"single label", []config.Peer{peer("localhost:51820")}, true},
		{"name after literals", []config.Peer{peer("203.0.113.1:51820"), peer(""), peer("de.example.net:51820")}, true},
		{"name first", []config.Peer{peer("nl.example.net:51820"), peer("203.0.113.1:51820")}, true},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("HasHostnames panicked: %v", r)
				}
			}()
			if got := HasHostnames(c.peers); got != c.want {
				t.Errorf("%s: HasHostnames = %v, want %v", c.name, got, c.want)
			}
		}()
	}
}

func m11EndpointUAPI(t *testing.T, pub config.Key, ep netip.AddrPort) string {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("endpointUAPI panicked: %v", r)
		}
	}()
	return endpointUAPI(pub, ep)
}

// Wirefork M11 plan: endpointUAPI is public_key (lowercase hex), update_only=true,
// endpoint — in this order; IPv6 in brackets.
func TestM11EndpointUAPI(t *testing.T) {
	pub := testKey(t)
	cases := []struct {
		ep   string
		want string
	}{
		{"203.0.113.9:51820", "203.0.113.9:51820"},
		{"[2001:db8::9]:51821", "[2001:db8::9]:51821"},
		{"198.51.100.200:443", "198.51.100.200:443"},
	}
	for _, c := range cases {
		got := m11EndpointUAPI(t, pub, netip.MustParseAddrPort(c.ep))
		lines := uapiLines(t, got)
		want := []string{
			"public_key=" + hexKey(pub),
			"update_only=true",
			"endpoint=" + c.want,
		}
		if !slices.Equal(lines, want) {
			t.Errorf("%s: lines\n%q\nwant\n%q", c.ep, lines, want)
		}
		if strings.ToLower(got) != got {
			t.Errorf("%s: UAPI text has upper case: %q", c.ep, got)
		}
	}
}

// The text of endpointUAPI is accepted by a real wireguard-go device (no
// root): it changes the endpoint of that peer only, keeps its allowed IPs
// and the other peers, and never creates a peer.
func TestM11EndpointUAPIAcceptedByDevice(t *testing.T) {
	priv, pub1, pub2 := testKey(t), testKey(t), testKey(t)
	wg := config.WGConfig{
		PrivateKey: priv,
		Peers: []config.Peer{
			{PublicKey: pub1, Endpoint: "203.0.113.5:51820", AllowedIPs: prefixList("10.0.0.0/24"), PersistentKeepalive: 25},
			{PublicKey: pub2, Endpoint: "vpn.example.com:51821", AllowedIPs: prefixList("192.168.10.0/24", "fd00::/64")},
		},
	}
	c := buildUAPI(&wg, []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.5:51820"),
		netip.MustParseAddrPort("198.51.100.7:51821"),
	})
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0],
		device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSetOperation(c.reader()); err != nil {
		t.Fatalf("IpcSetOperation(buildUAPI): %v", err)
	}

	// bindtest keeps only the endpoint port, so the new endpoint has a new port.
	text := m11EndpointUAPI(t, pub2, netip.MustParseAddrPort("198.51.100.8:51999"))
	if err := dev.IpcSetOperation(strings.NewReader(text)); err != nil {
		t.Fatalf("IpcSetOperation(endpointUAPI): %v", err)
	}
	// An unknown key: update_only does not create a peer.
	if err := dev.IpcSetOperation(strings.NewReader(m11EndpointUAPI(t, testKey(t), netip.MustParseAddrPort("198.51.100.9:52000")))); err != nil {
		t.Fatalf("IpcSetOperation(endpointUAPI, unknown key): %v", err)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	_, peers := parseIpcGet(t, got)
	if len(peers) != 2 {
		t.Fatalf("device has %d peers, want 2", len(peers))
	}
	p1, p2 := peers[hexKey(pub1)], peers[hexKey(pub2)]
	if p1 == nil || p2 == nil {
		t.Fatal("a configured peer is missing on the device")
	}
	if p2.port != "51999" {
		t.Errorf("peer 2 endpoint port %q, want 51999", p2.port)
	}
	if !slices.Equal(p2.allowed, []string{"192.168.10.0/24", "fd00::/64"}) {
		t.Errorf("peer 2 allowed IPs %v, want unchanged", p2.allowed)
	}
	if p1.port != "51820" || p1.keepalive != 25 || !slices.Equal(p1.allowed, []string{"10.0.0.0/24"}) {
		t.Errorf("peer 1 changed: %+v", *p1)
	}
}
