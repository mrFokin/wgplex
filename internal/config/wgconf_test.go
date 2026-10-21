package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func mustParse(t *testing.T, conf string) (WGConfig, []string) {
	t.Helper()
	wg, warns, errs := parseWGConf([]byte(conf))
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	return wg, warns
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func joinErrs(errs []error) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteByte('\n')
	}
	return b.String()
}

func TestParseWGConfFull(t *testing.T) {
	priv, privS := genKey(t)
	pub1, pub1S := genKey(t)
	psk, pskS := genKey(t)
	pub2, pub2S := genKey(t)

	conf := fmt.Sprintf(`# first line comment
[Interface]
PrivateKey = %s
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.1, 10.0.0.53
MTU = 1280
ListenPort = 51820

[Peer]  # inline comment after header
PublicKey = %s
PresharedKey = %s
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/8, 192.168.1.0/24 # trailing comment
AllowedIPs = 172.16.0.0/12
PersistentKeepalive = 20

[peer]
publickey=%s
endpoint=[2001:db8::1]:443
allowedips=0.0.0.0/0,::/0
`, privS, pub1S, pskS, pub2S)

	wg, warns := mustParse(t, conf)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if wg.PrivateKey != priv {
		t.Error("PrivateKey mismatch")
	}
	if !equalPrefixes(wg.Addresses, prefixes(t, "10.0.0.2/32", "fd00::2/128")) {
		t.Errorf("Addresses = %v", wg.Addresses)
	}
	if len(wg.DNS) != 2 || wg.DNS[0] != netip.MustParseAddr("10.0.0.1") || wg.DNS[1] != netip.MustParseAddr("10.0.0.53") {
		t.Errorf("DNS = %v", wg.DNS)
	}
	if wg.MTU != 1280 || wg.ListenPort != 51820 {
		t.Errorf("MTU = %d, ListenPort = %d", wg.MTU, wg.ListenPort)
	}
	if len(wg.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(wg.Peers))
	}
	p := wg.Peers[0]
	if p.PublicKey != pub1 || p.PresharedKey != psk {
		t.Error("peer 1 keys mismatch")
	}
	if p.Endpoint != "vpn.example.com:51820" || p.PersistentKeepalive != 20 {
		t.Errorf("peer 1 Endpoint = %q, PersistentKeepalive = %d", p.Endpoint, p.PersistentKeepalive)
	}
	if !equalPrefixes(p.AllowedIPs, prefixes(t, "10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12")) {
		t.Errorf("peer 1 AllowedIPs = %v", p.AllowedIPs)
	}
	p = wg.Peers[1]
	if p.PublicKey != pub2 || p.PresharedKey != (Key{}) {
		t.Error("peer 2 keys mismatch")
	}
	if p.Endpoint != "[2001:db8::1]:443" || p.PersistentKeepalive != 0 {
		t.Errorf("peer 2 Endpoint = %q, PersistentKeepalive = %d", p.Endpoint, p.PersistentKeepalive)
	}
	if !equalPrefixes(p.AllowedIPs, prefixes(t, "0.0.0.0/0", "::/0")) {
		t.Errorf("peer 2 AllowedIPs = %v", p.AllowedIPs)
	}
}

func TestParseWGConfCRLFAndBOM(t *testing.T) {
	_, privS := genKey(t)
	_, pubS := genKey(t)
	conf := "\xef\xbb\xbf[Interface]\r\nPrivateKey = " + privS + "\r\nAddress = 10.1.0.2\r\n\r\n[Peer]\r\nPublicKey = " + pubS + "\r\nAllowedIPs = 0.0.0.0/0\r\n"
	wg, _ := mustParse(t, conf)
	if !equalPrefixes(wg.Addresses, prefixes(t, "10.1.0.2/32")) || len(wg.Peers) != 1 {
		t.Errorf("got %+v", wg)
	}
}

func TestParseWGConfNormalization(t *testing.T) {
	_, privS := genKey(t)
	_, pubS := genKey(t)
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.0.5, fd00::5, 10.8.0.5/32
DNS = 1.1.1.1, corp.example, 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
AllowedIPs = 10.1.2.3/16, 10.1.0.0/16, 192.0.2.7, 192.0.2.7/32, , 2001:db8::1
PersistentKeepalive = off
`, privS, pubS)
	wg, warns := mustParse(t, conf)

	if !equalPrefixes(wg.Addresses, prefixes(t, "10.8.0.5/32", "fd00::5/128")) {
		t.Errorf("Addresses = %v", wg.Addresses)
	}
	if len(wg.DNS) != 2 || wg.DNS[0] != netip.MustParseAddr("1.1.1.1") || wg.DNS[1] != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("DNS = %v", wg.DNS)
	}
	want := prefixes(t, "10.1.0.0/16", "192.0.2.7/32", "2001:db8::1/128")
	if !equalPrefixes(wg.Peers[0].AllowedIPs, want) {
		t.Errorf("AllowedIPs = %v, want %v", wg.Peers[0].AllowedIPs, want)
	}
	if wg.Peers[0].PersistentKeepalive != 0 {
		t.Errorf("PersistentKeepalive = %d", wg.Peers[0].PersistentKeepalive)
	}

	// Exactly two warnings: the non-IP DNS value and the non-canonical CIDR.
	// Bare addresses and duplicates are normalized silently (design 10.1).
	if len(warns) != 2 {
		t.Fatalf("warnings = %v, want 2", warns)
	}
	all := strings.Join(warns, "\n")
	if !strings.Contains(all, "corp.example") || !strings.Contains(all, "10.1.2.3/16") {
		t.Errorf("warnings = %v", warns)
	}
}

func TestParseWGConfWGQuickFields(t *testing.T) {
	_, privS := genKey(t)
	_, pubS := genKey(t)
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/32
Table = off
PreUp = echo up
PostUp = iptables -A FORWARD -i %%i -j ACCEPT; echo done
PreDown = echo down
PostDown = echo bye
SaveConfig = true

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
`, privS, pubS)
	_, warns := mustParse(t, conf)
	if len(warns) != 6 {
		t.Fatalf("warnings = %v, want 6", warns)
	}
	for _, f := range []string{"Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig"} {
		if !strings.Contains(strings.Join(warns, "\n"), f) {
			t.Errorf("no warning for %s: %v", f, warns)
		}
	}
}

// TestParseWGConfLongLine mirrors the shape of a real work config: one peer,
// ~350 AllowedIPs on a single ~7 KB line, mostly single addresses with and
// without /32, some /13../24 subnets, duplicates including x and x/32, DNS
// servers that are also in AllowedIPs.
func TestParseWGConfLongLine(t *testing.T) {
	_, privS := genKey(t)
	_, pubS := genKey(t)

	var items []string
	var want []netip.Prefix
	add := func(s string, p netip.Prefix, isNew bool) {
		items = append(items, s)
		if isNew {
			want = append(want, p)
		}
	}
	dns := []string{"10.200.0.1", "10.200.0.2", "10.200.0.3"}
	for _, d := range dns {
		a := netip.MustParseAddr(d)
		add(d, netip.PrefixFrom(a, 32), true)
	}
	for i := 0; i < 300; i++ {
		a := netip.AddrFrom4([4]byte{185, byte(100 + i/150), byte(100 + i%150), 211})
		s := a.String()
		if i%2 == 0 {
			s += "/32"
		}
		add(s, netip.PrefixFrom(a, 32), true)
	}
	for i := 0; i < 30; i++ {
		bits := 13 + i%12
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i), 0, 0, 0}), bits)
		add(p.String(), p, true)
	}
	// Duplicates: x after x/32, x/32 after x, exact repeats, a DNS server again.
	add("185.100.100.211", netip.Prefix{}, false)
	add("185.100.101.211/32", netip.Prefix{}, false)
	add("185.100.102.211/32", netip.Prefix{}, false)
	add("11.0.0.0/13", netip.Prefix{}, false)
	add("10.200.0.1/32", netip.Prefix{}, false)
	for i := 0; i < 12; i++ {
		add(want[3+i].String(), netip.Prefix{}, false)
	}

	line := "AllowedIPs = " + strings.Join(items, ", ")
	if len(items) < 340 || len(line) < 6000 {
		t.Fatalf("fixture too small: %d items, %d bytes", len(items), len(line))
	}

	conf := fmt.Sprintf("# work config\n[Interface]\nPrivateKey = %s\nAddress = 10.200.5.17/32\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = 203.0.113.10:51820\n%s\n",
		privS, strings.Join(dns, ", "), pubS, line)

	wg, warns := mustParse(t, conf)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if len(wg.Peers) != 1 {
		t.Fatalf("got %d peers", len(wg.Peers))
	}
	if !equalPrefixes(wg.Peers[0].AllowedIPs, want) {
		t.Errorf("AllowedIPs: got %d items, want %d", len(wg.Peers[0].AllowedIPs), len(want))
	}
	if len(wg.DNS) != 3 {
		t.Errorf("DNS = %v", wg.DNS)
	}
}

func TestParseWGConfKeyErrors(t *testing.T) {
	_, good := genKey(t)
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	// A private key with one character changed so it stays recognizable but
	// becomes invalid base64; it must not appear in the error text.
	badPriv := good[:10] + "!" + good[11:]

	tests := []struct {
		name   string
		conf   string
		want   string
		secret string
	}{
		{
			name:   "private key not base64",
			conf:   "[Interface]\nPrivateKey = " + badPriv + "\n[Peer]\nPublicKey = " + good + "\n",
			want:   "PrivateKey",
			secret: badPriv,
		},
		{
			name:   "private key wrong length",
			conf:   "[Interface]\nPrivateKey = " + short + "\n[Peer]\nPublicKey = " + good + "\n",
			want:   "31 bytes",
			secret: short,
		},
		{
			name: "public key wrong length",
			conf: "[Interface]\nPrivateKey = " + good + "\n[Peer]\nPublicKey = " + short + "\n",
			want: "PublicKey",
		},
		{
			name:   "preshared key not base64",
			conf:   "[Interface]\nPrivateKey = " + good + "\n[Peer]\nPublicKey = " + good + "\nPresharedKey = xyz\n",
			want:   "PresharedKey",
			secret: "xyz",
		},
		{
			name: "missing private key",
			conf: "[Interface]\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + good + "\n",
			want: "missing PrivateKey",
		},
		{
			name: "missing public key",
			conf: "[Interface]\nPrivateKey = " + good + "\n[Peer]\nAllowedIPs = 0.0.0.0/0\n",
			want: "missing PublicKey",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, warns, errs := parseWGConf([]byte(tt.conf))
			if len(errs) == 0 {
				t.Fatal("expected an error")
			}
			msg := joinErrs(errs) + strings.Join(warns, "\n")
			if !strings.Contains(msg, tt.want) {
				t.Errorf("errors %q do not mention %q", msg, tt.want)
			}
			if strings.Contains(msg, good) || (tt.secret != "" && strings.Contains(msg, tt.secret)) {
				t.Errorf("key leaked into message: %q", msg)
			}
		})
	}
}

func TestParseWGConfFormatErrors(t *testing.T) {
	_, k := genKey(t)
	head := "[Interface]\nPrivateKey = " + k + "\n"
	peer := "[Peer]\nPublicKey = " + k + "\n"

	tests := []struct {
		name string
		conf string
		want string
	}{
		{"missing interface", peer, "missing [Interface]"},
		{"no peer", head, "no [Peer]"},
		{"repeated interface", head + head + peer, "repeated [Interface]"},
		{"unknown section", head + peer + "[Foo]\n", "unknown section"},
		{"malformed header", head + peer + "[Peer\n", "malformed section header"},
		{"key outside section", "Address = 10.0.0.1\n" + head + peer, "outside of a section"},
		{"no equals sign", head + "Address 10.0.0.1\n" + peer, "line 3: malformed line"},
		{"unknown interface key", head + "Foo = bar\n" + peer, "unknown key Foo"},
		{"unknown peer key", head + peer + "Bar = 1\n", "unknown key Bar"},
		{"repeated scalar key", head + "MTU = 1280\nMTU = 1400\n" + peer, "repeated key MTU"},
		{"bad mtu", head + "MTU = big\n" + peer, "MTU"},
		{"mtu out of range", head + "MTU = 0\n" + peer, "out of range"},
		{"bad listen port", head + "ListenPort = 70000\n" + peer, "ListenPort"},
		{"bad keepalive", head + peer + "PersistentKeepalive = -1\n", "PersistentKeepalive"},
		{"bad address", head + "Address = 10.0.0.300\n" + peer, "Address"},
		{"bad allowed ip", head + peer + "AllowedIPs = 10.0.0.0/33\n", "AllowedIPs"},
		{"endpoint without port", head + peer + "Endpoint = vpn.example.com\n", "Endpoint"},
		{"endpoint bad port", head + peer + "Endpoint = vpn.example.com:0\n", "Endpoint"},
		{"endpoint empty host", head + peer + "Endpoint = :51820\n", "Endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, errs := parseWGConf([]byte(tt.conf))
			if len(errs) == 0 {
				t.Fatal("expected an error")
			}
			if msg := joinErrs(errs); !strings.Contains(msg, tt.want) {
				t.Errorf("errors %q do not mention %q", msg, tt.want)
			}
		})
	}
}

func TestParseWGConfCollectsAllErrors(t *testing.T) {
	_, k := genKey(t)
	conf := "[Interface]\nPrivateKey = " + k + "\nMTU = x\nAddress = nope\n[Peer]\nPublicKey = " + k + "\nEndpoint = bad\nFoo = 1\n"
	_, _, errs := parseWGConf([]byte(conf))
	if len(errs) != 4 {
		t.Fatalf("got %d errors, want 4: %v", len(errs), errs)
	}
	msg := joinErrs(errs)
	for _, want := range []string{"line 3:", "line 4:", "line 7:", "line 8:"} {
		if !strings.Contains(msg, want) {
			t.Errorf("errors %q lack %q", msg, want)
		}
	}
}

func TestKeyRedacted(t *testing.T) {
	k, s := genKey(t)
	wg := WGConfig{PrivateKey: k, Peers: []Peer{{PublicKey: k, PresharedKey: k}}}
	for _, out := range []string{k.String(), fmt.Sprint(k), fmt.Sprintf("%v %+v", wg, wg)} {
		if strings.Contains(out, s) {
			t.Errorf("key leaked: %q", out)
		}
	}
	if k.String() != "(redacted)" {
		t.Errorf("String() = %q", k.String())
	}
}

func TestParseKey(t *testing.T) {
	k, s := genKey(t)
	got, err := parseKey(s)
	if err != nil || got != k {
		t.Fatalf("parseKey(valid) = %v, %v", got == k, err)
	}
	for _, bad := range []string{"", "AAAA", s + "AAAA", s[:43]} {
		if _, err := parseKey(bad); err == nil {
			t.Errorf("parseKey(%d chars) succeeded", len(bad))
		}
	}
}

// A mistyped key line ("PrivateKey <key>", "PrivateKey: <key>") must not echo
// the key into errors: base64 padding "=" would otherwise be taken as the
// separator and the key as part of the name (design 10.1).
func TestParseWGConfMalformedKeyLineNoLeak(t *testing.T) {
	_, pubS := genKey(t)
	_, secret := genKey(t)
	// 32 bytes encode to 43 characters plus one "=" of padding.
	if !strings.HasSuffix(secret, "=") {
		t.Fatalf("generated key %d chars has no padding", len(secret))
	}
	tests := []struct {
		name, iface, peer string
	}{
		{"private key without equals", "PrivateKey " + secret + "\n", ""},
		{"private key with colon", "PrivateKey: " + secret + "\n", ""},
		{"preshared key without equals", "", "PresharedKey " + secret + "\n"},
		{"preshared key with colon", "", "PresharedKey: " + secret + "\n"},
		{"private key before any section", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, privS := genKey(t)
			conf := "[Interface]\nPrivateKey = " + privS + "\n" + tt.iface +
				"[Peer]\nPublicKey = " + pubS + "\n" + tt.peer
			if tt.iface == "" && tt.peer == "" {
				conf = "PrivateKey: " + secret + "\n" + conf
			}
			_, warns, errs := parseWGConf([]byte(conf))
			if len(errs) != 1 {
				t.Fatalf("errors = %v, want 1", errs)
			}
			msg := joinErrs(errs) + strings.Join(warns, "\n")
			if !strings.Contains(msg, "malformed line") {
				t.Errorf("errors %q do not mention malformed line", msg)
			}
			// No part of the key, not even its padding-free prefix, may leak.
			if strings.Contains(msg, secret[:20]) || strings.Contains(msg, privS[:20]) {
				t.Errorf("key leaked into message: %q", msg)
			}
		})
	}
}

// Address is an interface address with a prefix length: host bits are kept
// without a warning, and two addresses in the same /24 stay distinct (design 10.1).
func TestParseWGConfAddressKeepsHostBits(t *testing.T) {
	_, privS := genKey(t)
	_, pubS := genKey(t)
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/24, 10.0.0.3/24, 10.0.0.2/24, fd00::2/64
Address = 10.0.0.9, 10.0.0.9/32

[Peer]
PublicKey = %s
`, privS, pubS)
	wg, warns := mustParse(t, conf)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	want := prefixes(t, "10.0.0.2/24", "10.0.0.3/24", "fd00::2/64", "10.0.0.9/32")
	if !equalPrefixes(wg.Addresses, want) {
		t.Errorf("Addresses = %v, want %v", wg.Addresses, want)
	}
}

func TestParseWGConfFwMarkWarns(t *testing.T) {
	_, k := genKey(t)
	conf := "[Interface]\nPrivateKey = " + k + "\nFwMark = 0x1234\n[Peer]\nPublicKey = " + k + "\n"
	_, warns := mustParse(t, conf)
	if len(warns) != 1 || !strings.Contains(warns[0], "FwMark") {
		t.Errorf("warnings = %v, want one about FwMark", warns)
	}
}

// Keys of an unknown section are skipped: one error for the whole section.
func TestParseWGConfUnknownSectionOneError(t *testing.T) {
	_, k := genKey(t)
	conf := "[Interface]\nPrivateKey = " + k + "\n[Peer]\nPublicKey = " + k + "\n" +
		"[Foo]\nBar = 1\nBaz = 2\nPrivateKey = " + k + "\n"
	_, _, errs := parseWGConf([]byte(conf))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "unknown section [Foo]") {
		t.Errorf("errors = %v, want one unknown section error", errs)
	}
}

func TestParseWGConfMalformedHeaderNoContent(t *testing.T) {
	_, k := genKey(t)
	conf := "[Interface]\nPrivateKey = " + k + "\n[Peer]\nPublicKey = " + k + "\n[Peer " + k + "]\n"
	_, _, errs := parseWGConf([]byte(conf))
	msg := joinErrs(errs)
	if len(errs) != 1 || !strings.Contains(msg, "malformed section header") {
		t.Errorf("errors = %v, want one malformed header error", errs)
	}
	if strings.Contains(msg, k[:20]) {
		t.Errorf("key leaked into message: %q", msg)
	}
}

func TestKeyRedactedGoStringAndJSON(t *testing.T) {
	k, s := genKey(t)
	wg := WGConfig{PrivateKey: k, Peers: []Peer{{PublicKey: k, PresharedKey: k}}}
	if got := fmt.Sprintf("%#v", k); got != "(redacted)" {
		t.Errorf("%%#v = %q", got)
	}
	b, err := json.Marshal(k)
	if err != nil || string(b) != `"(redacted)"` {
		t.Errorf("json.Marshal(key) = %s, %v", b, err)
	}
	gs := fmt.Sprintf("%#v", wg)
	jb, err := json.Marshal(wg)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{gs, string(jb)} {
		if strings.Contains(out, s) || !strings.Contains(out, "(redacted)") {
			t.Errorf("key not redacted: %q", out)
		}
	}
}
