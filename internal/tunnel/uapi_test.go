package tunnel

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/mrFokin/wgplex/internal/config"
)

// fill returns a fixed test key with every byte set to b.
func fill(b byte) config.Key {
	var k config.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func hexKey(k config.Key) string { return hex.EncodeToString(k[:]) }

func prefixList(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func uapiText(t *testing.T, c uapiConfig) string {
	t.Helper()
	b, err := io.ReadAll(c.reader())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// uapiLines splits a UAPI text into lines. A set operation ends at the first
// blank line, so none may appear inside; trailing newlines are not significant.
func uapiLines(t *testing.T, s string) []string {
	t.Helper()
	body := strings.TrimRight(s, "\n")
	if strings.Contains(body, "\n\n") {
		t.Errorf("blank line inside UAPI text ends the operation early:\n%s", s)
	}
	if body == "" {
		return nil
	}
	return strings.Split(body, "\n")
}

// design 5: the device is configured via UAPI; plan M3: field order and
// optional fields per the buildUAPI doc comment, keys in lowercase hex.
func TestBuildUAPI(t *testing.T) {
	priv, pub1, psk1, pub2, pub3 := fill(0x11), fill(0x22), fill(0x33), fill(0xa4), fill(0xb5)
	tests := []struct {
		name      string
		wg        config.WGConfig
		endpoints []netip.AddrPort
		want      []string
	}{
		{
			name: "several peers, PSK, IPv4 and IPv6 endpoints, keepalive 0",
			wg: config.WGConfig{
				PrivateKey: priv,
				Addresses:  prefixList("10.0.0.2/24", "fd00::2/64"),
				MTU:        1380,
				ListenPort: 51820,
				Peers: []config.Peer{
					{
						PublicKey:           pub1,
						PresharedKey:        psk1,
						Endpoint:            "vpn.example.com:51820",
						AllowedIPs:          prefixList("0.0.0.0/0", "::/0"),
						PersistentKeepalive: 25,
					},
					{
						PublicKey:  pub2,
						Endpoint:   "[2001:db8::5]:51821",
						AllowedIPs: prefixList("10.0.0.0/24", "192.168.10.0/24"),
					},
				},
			},
			endpoints: []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.5:51820"),
				netip.MustParseAddrPort("[2001:db8::5]:51821"),
			},
			want: []string{
				"private_key=" + hexKey(priv),
				"listen_port=51820",
				"replace_peers=true",
				"public_key=" + hexKey(pub1),
				"preshared_key=" + hexKey(psk1),
				"endpoint=203.0.113.5:51820",
				"persistent_keepalive_interval=25",
				"replace_allowed_ips=true",
				"allowed_ip=0.0.0.0/0",
				"allowed_ip=::/0",
				"public_key=" + hexKey(pub2),
				"endpoint=[2001:db8::5]:51821",
				"persistent_keepalive_interval=0",
				"replace_allowed_ips=true",
				"allowed_ip=10.0.0.0/24",
				"allowed_ip=192.168.10.0/24",
			},
		},
		{
			name: "listen_port 0 is omitted, peer without endpoint",
			wg: config.WGConfig{
				PrivateKey: priv,
				Peers: []config.Peer{{
					PublicKey:           pub3,
					AllowedIPs:          prefixList("10.1.0.0/16"),
					PersistentKeepalive: 15,
				}},
			},
			endpoints: []netip.AddrPort{{}},
			want: []string{
				"private_key=" + hexKey(priv),
				"replace_peers=true",
				"public_key=" + hexKey(pub3),
				"persistent_keepalive_interval=15",
				"replace_allowed_ips=true",
				"allowed_ip=10.1.0.0/16",
			},
		},
		{
			name: "peer without AllowedIPs",
			wg: config.WGConfig{
				PrivateKey: priv,
				ListenPort: 1,
				Peers:      []config.Peer{{PublicKey: pub1, Endpoint: "203.0.113.7:65535"}},
			},
			endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:65535")},
			want: []string{
				"private_key=" + hexKey(priv),
				"listen_port=1",
				"replace_peers=true",
				"public_key=" + hexKey(pub1),
				"endpoint=203.0.113.7:65535",
				"persistent_keepalive_interval=0",
				"replace_allowed_ips=true",
			},
		},
		{
			name: "no peers",
			wg:   config.WGConfig{PrivateKey: priv},
			want: []string{
				"private_key=" + hexKey(priv),
				"replace_peers=true",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := buildUAPI(&tt.wg, tt.endpoints)
			got := uapiLines(t, uapiText(t, c))
			if !slices.Equal(got, tt.want) {
				t.Errorf("UAPI mismatch\n got:\n%s\nwant:\n%s",
					strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
		})
	}
}

// Keys are lowercase hex (UAPI rejects base64 and is case-sensitive in practice).
func TestBuildUAPILowercaseHex(t *testing.T) {
	var priv, pub config.Key
	for i := range priv {
		priv[i] = byte(0xa0 + i%16)
		pub[i] = byte(0xf0 - i)
	}
	wg := config.WGConfig{PrivateKey: priv, Peers: []config.Peer{{PublicKey: pub}}}
	s := uapiText(t, buildUAPI(&wg, []netip.AddrPort{{}}))
	for _, want := range []string{"private_key=" + hexKey(priv), "public_key=" + hexKey(pub)} {
		if !strings.Contains(s, want+"\n") && !strings.HasSuffix(s, want) {
			t.Errorf("UAPI lacks line %q:\n%s", want, s)
		}
	}
	if strings.ToLower(s) != s {
		t.Errorf("UAPI has uppercase characters:\n%s", s)
	}
}

// design 9.4: keys never get into logs; plan M3: every formatting path of
// uapiConfig prints "(redacted)".
func TestUAPIConfigRedacted(t *testing.T) {
	priv, pub, psk := testKey(t), testKey(t), testKey(t)
	wg := config.WGConfig{
		PrivateKey: priv,
		ListenPort: 51820,
		Peers: []config.Peer{{
			PublicKey:    pub,
			PresharedKey: psk,
			AllowedIPs:   prefixList("0.0.0.0/0"),
		}},
	}
	c := buildUAPI(&wg, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:51820")})
	secrets := append(keyForms(priv), keyForms(psk)...)

	exact := map[string]string{
		"String()":   c.String(),
		"GoString()": c.GoString(),
		"Sprint":     fmt.Sprint(c),
		"Sprintln":   strings.TrimSuffix(fmt.Sprintln(c), "\n"),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		exact[verb] = fmt.Sprintf(verb, c)
	}
	for name, got := range exact {
		if got != "(redacted)" {
			t.Errorf("%s = %q, want %q", name, got, "(redacted)")
		}
	}

	type holder struct {
		Cfg uapiConfig
		Ptr *uapiConfig
	}
	h := holder{Cfg: c, Ptr: &c}
	nested := map[string]string{
		"pointer %v":       fmt.Sprintf("%v", &c),
		"struct %v":        fmt.Sprintf("%v", h),
		"struct %+v":       fmt.Sprintf("%+v", h),
		"struct %#v":       fmt.Sprintf("%#v", h),
		"slice %v":         fmt.Sprintf("%v", []uapiConfig{c}),
		"map %v":           fmt.Sprintf("%v", map[string]uapiConfig{"nl": c}),
		"error wrap %v":    fmt.Errorf("configure: %v", c).Error(),
		"LogValue.String":  c.LogValue().String(),
		"LogValue.Resolve": c.LogValue().Resolve().String(),
	}
	for name, got := range nested {
		if !strings.Contains(got, "(redacted)") {
			t.Errorf("%s = %q, want it to contain %q", name, got, "(redacted)")
		}
	}
	for name, got := range mergeMaps(exact, nested) {
		for _, s := range secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s leaks a key: %q", name, got)
			}
		}
	}

	for _, hc := range []struct {
		name string
		new  func(io.Writer) slog.Handler
	}{
		{"text", func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) }},
		{"json", func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) }},
	} {
		t.Run("slog "+hc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(hc.new(&buf))
			l.Info("configure", "uapi", c)
			l.Info("configure", slog.Any("uapi", c))
			l.Info("configure", slog.Group("tunnel", slog.Any("uapi", c)))
			l.With("uapi", c).Info("configure")
			l.Info("configure", "ptr", &c)
			out := buf.String()
			if n := strings.Count(out, "(redacted)"); n != 5 {
				t.Errorf("want 5 redacted values, got %d:\n%s", n, out)
			}
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Errorf("slog %s output leaks a key:\n%s", hc.name, out)
				}
			}
		})
	}
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// uapiPeer is one peer as reported by IpcGet.
type uapiPeer struct {
	psk       string
	port      string // endpoint port; bindtest keeps only the port
	keepalive int
	allowed   []string
}

// parseIpcGet reads private_key and peers keyed by public key from IpcGet output.
func parseIpcGet(t *testing.T, s string) (priv string, peers map[string]*uapiPeer) {
	t.Helper()
	peers = map[string]*uapiPeer{}
	var cur *uapiPeer
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "private_key":
			priv = v
		case "public_key":
			cur = &uapiPeer{}
			peers[v] = cur
		case "preshared_key":
			cur.psk = v
		case "endpoint":
			cur.port = v[strings.LastIndex(v, ":")+1:]
		case "persistent_keepalive_interval":
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("bad %s: %v", line, err)
			}
			cur.keepalive = n
		case "allowed_ip":
			cur.allowed = append(cur.allowed, v)
		}
	}
	return priv, peers
}

// The UAPI text is accepted by a real wireguard-go device (in-memory TUN and
// bind, no root) and the device ends up with exactly this configuration.
func TestBuildUAPIAcceptedByDevice(t *testing.T) {
	priv, pub1, psk1, pub2 := testKey(t), testKey(t), testKey(t), testKey(t)
	wg := config.WGConfig{
		PrivateKey: priv,
		ListenPort: 51820,
		Peers: []config.Peer{
			{
				PublicKey:           pub1,
				PresharedKey:        psk1,
				Endpoint:            "vpn.example.com:51820",
				AllowedIPs:          prefixList("10.0.0.0/24", "fd00::/64"),
				PersistentKeepalive: 25,
			},
			{
				PublicKey:  pub2,
				Endpoint:   "[2001:db8::5]:51821",
				AllowedIPs: prefixList("192.168.10.0/24"),
			},
		},
	}
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.5:51820"),
		netip.MustParseAddrPort("[2001:db8::5]:51821"),
	}
	c := buildUAPI(&wg, endpoints)

	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0],
		device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	if err := dev.IpcSetOperation(c.reader()); err != nil {
		t.Fatalf("IpcSetOperation: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, peers := parseIpcGet(t, got)
	if gotPriv != hexKey(priv) {
		t.Errorf("device private key differs from the configured one")
	}
	want := map[string]uapiPeer{
		hexKey(pub1): {psk: hexKey(psk1), port: "51820", keepalive: 25, allowed: []string{"10.0.0.0/24", "fd00::/64"}},
		hexKey(pub2): {psk: hexKey(config.Key{}), port: "51821", keepalive: 0, allowed: []string{"192.168.10.0/24"}},
	}
	if len(peers) != len(want) {
		t.Fatalf("device has %d peers, want %d", len(peers), len(want))
	}
	for pk, w := range want {
		p, ok := peers[pk]
		if !ok {
			t.Errorf("peer %.8s… missing on the device", pk)
			continue
		}
		if p.psk != w.psk {
			t.Errorf("peer %.8s…: preshared key differs", pk)
		}
		if p.port != w.port {
			t.Errorf("peer %.8s…: endpoint port %q, want %q", pk, p.port, w.port)
		}
		if p.keepalive != w.keepalive {
			t.Errorf("peer %.8s…: keepalive %d, want %d", pk, p.keepalive, w.keepalive)
		}
		slices.Sort(p.allowed)
		slices.Sort(w.allowed)
		if !slices.Equal(p.allowed, w.allowed) {
			t.Errorf("peer %.8s…: allowed_ip %v, want %v", pk, p.allowed, w.allowed)
		}
	}

	// replace_peers=true: a second configuration fully replaces the first.
	wg2 := config.WGConfig{
		PrivateKey: priv,
		Peers:      []config.Peer{{PublicKey: pub2, AllowedIPs: prefixList("172.16.0.0/12")}},
	}
	if err := dev.IpcSetOperation(buildUAPI(&wg2, []netip.AddrPort{{}}).reader()); err != nil {
		t.Fatalf("second IpcSetOperation: %v", err)
	}
	got, err = dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	_, peers = parseIpcGet(t, got)
	if len(peers) != 1 || peers[hexKey(pub2)] == nil {
		t.Fatalf("after reconfiguration device has %d peers, want only the second one", len(peers))
	}
	if a := peers[hexKey(pub2)].allowed; !slices.Equal(a, []string{"172.16.0.0/12"}) {
		t.Errorf("replace_allowed_ips=true: allowed_ip %v, want [172.16.0.0/12]", a)
	}
}
