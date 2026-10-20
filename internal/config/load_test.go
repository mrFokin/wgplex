package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// Tests in this file follow docs/design.md sections 5, 9.1–9.3, not the implementation.
// All keys are generated per test; all addresses are private or documentation ranges.

// --- helpers ---------------------------------------------------------------

// genKey returns a fresh random WireGuard key and its base64 form.
func genKey(t *testing.T) (Key, string) {
	t.Helper()
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k, base64.StdEncoding.EncodeToString(k[:])
}

// genConf is a rendered .conf with the keys it was generated with.
type genConf struct {
	text  string
	priv  Key
	peers []Key
}

// makeConf renders a .conf: [Interface] with a generated PrivateKey plus iface lines,
// and one [Peer] per body, each with a generated PublicKey.
func makeConf(t *testing.T, iface string, peers ...string) genConf {
	t.Helper()
	priv, privB64 := genKey(t)
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n%s\n", privB64, iface)
	g := genConf{priv: priv}
	for _, p := range peers {
		pub, pubB64 := genKey(t)
		g.peers = append(g.peers, pub)
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n%s\n", pubB64, p)
	}
	g.text = b.String()
	return g
}

// simpleConf is a minimal valid .conf with a DNS server.
func simpleConf(t *testing.T) string {
	t.Helper()
	return makeConf(t,
		"Address = 10.66.0.2/32\nDNS = 10.66.0.1",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0",
	).text
}

// noDNSConf is a minimal valid .conf without DNS.
func noDNSConf(t *testing.T) string {
	t.Helper()
	return makeConf(t,
		"Address = 10.67.0.2/32",
		"Endpoint = 203.0.113.2:51820\nAllowedIPs = 10.67.0.0/16",
	).text
}

func filesOf(yaml string, confs map[string]string) map[string][]byte {
	m := map[string][]byte{"wgplex.yaml": []byte(yaml)}
	for name, c := range confs {
		m[name] = []byte(c)
	}
	return m
}

// load calls Load and turns a panic (e.g. not implemented yet) into a test failure.
func load(t *testing.T, files map[string][]byte) (cfg *Config, warnings []string, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Load panicked: %v", r)
		}
	}()
	return Load(files)
}

func mustLoad(t *testing.T, files map[string][]byte) (*Config, []string) {
	t.Helper()
	cfg, warns, err := load(t, files)
	if err != nil {
		t.Fatalf("Load: unexpected error:\n%v", err)
	}
	if cfg == nil {
		t.Fatal("Load: nil config without error")
	}
	return cfg, warns
}

// mustFail checks the design 9.2 failure contract: err is Errors, non-empty, cfg is nil.
func mustFail(t *testing.T, files map[string][]byte) Errors {
	t.Helper()
	cfg, _, err := load(t, files)
	if err == nil {
		t.Fatal("Load: expected an error, got nil")
	}
	if cfg != nil {
		t.Error("Load: cfg must be nil on error")
	}
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("Load: error is %T, want Errors", err)
	}
	if len(errs) == 0 {
		t.Fatal("Load: empty Errors")
	}
	return errs
}

func sameSet[T comparable](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	n := map[T]int{}
	for _, v := range want {
		n[v]++
	}
	for _, v := range got {
		n[v]--
		if n[v] < 0 {
			return false
		}
	}
	return true
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

func pfxs(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = pfx(s)
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = addr(s)
	}
	return out
}

func suffixes(ss ...string) []Domain {
	out := make([]Domain, len(ss))
	for i, s := range ss {
		out[i] = Domain{Name: s}
	}
	return out
}

func hasWarning(warns []string, sub string) bool {
	for _, w := range warns {
		if strings.Contains(strings.ToLower(w), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func tunnelByName(t *testing.T, cfg *Config, name string) Tunnel {
	t.Helper()
	for _, tn := range cfg.Tunnels {
		if tn.Name == name {
			return tn
		}
	}
	t.Fatalf("tunnel %q not found", name)
	return Tunnel{}
}

// baseYAML is a valid minimal config used as a starting point.
const baseYAML = `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
  - name: de
    conf: de.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl, de]
`

func baseConfs(t *testing.T) map[string]string {
	return map[string]string{"nl.conf": simpleConf(t), "de.conf": simpleConf(t)}
}

// --- design 9.1: the full example ------------------------------------------

const exampleYAML = `# <prefix>/etc/wgplex/wgplex.yaml

ipv6_filter: true

# Порядок туннелей = приоритет при одинаковых префиксах
tunnels:
  - name: work
    conf: work.conf            # файл в этой же папке (можно симлинк)
    routes: config             # AllowedIPs → таблица маршрутов
    autostart: true
    dns_domains:               # резолвить через DNS из work.conf
      - corp.example
    check: 10.0.0.1            # необязательно: ping через туннель

  - name: home
    conf: home.conf
    routes: config
    autostart: false

  - name: nl
    conf: nl.conf
    routes: rules              # только маршруты из правил
    autostart: true
    check: 1.1.1.1

  - name: de
    conf: de.conf
    routes: rules
    autostart: true
    check: 1.1.1.1

services:
  youtube:
    domains: [youtube.com, googlevideo.com, ytimg.com, youtu.be, ggpht.com]
  ai:
    domains: [openai.com, chatgpt.com, anthropic.com, claude.ai, gemini.google.com]
  telegram:
    cidrs: [91.108.4.0/22, 149.154.160.0/20]

rules:
  - services: [youtube, telegram]
    via: [nl, de]
    fallback: default
  - services: [ai]
    via: [nl, de]
    fallback: block
`

// workAllowedIPs builds a work-like AllowedIPs line (plan "Форма реальных конфигов"):
// ~330 entries in one line, single addresses with and without /32, a few subnets,
// duplicates including x and x/32, and the DNS servers. Returns the line and the
// expected deduplicated set.
func workAllowedIPs() (line string, want []netip.Prefix) {
	var items []string
	seen := map[netip.Prefix]bool{}
	add := func(item string, p netip.Prefix) {
		items = append(items, item)
		if !seen[p] {
			seen[p] = true
			want = append(want, p)
		}
	}
	for i := 0; i < 300; i++ {
		a := fmt.Sprintf("10.20.%d.%d", i/200, i%200+1)
		p := netip.PrefixFrom(addr(a), 32)
		if i%2 == 0 {
			add(a, p)
		} else {
			add(a+"/32", p)
		}
	}
	// Duplicates in the other spelling: x vs x/32.
	for i := 0; i < 20; i++ {
		a := fmt.Sprintf("10.20.%d.%d", i/200, i%200+1)
		p := netip.PrefixFrom(addr(a), 32)
		if i%2 == 0 {
			add(a+"/32", p)
		} else {
			add(a, p)
		}
	}
	for _, s := range []string{"10.48.0.0/13", "172.20.0.0/14", "192.168.100.0/22", "10.99.1.0/24", "10.99.1.0/24"} {
		add(s, pfx(s))
	}
	for _, s := range []string{"10.10.0.53/32", "10.10.1.53", "10.10.2.53/32"} {
		add(s, netip.PrefixFrom(addr(strings.TrimSuffix(s, "/32")), 32))
	}
	return strings.Join(items, ", "), want
}

// design 9.1: Load accepts the example and produces the expected Config.
func TestLoadExample(t *testing.T) {
	allowed, wantAllowed := workAllowedIPs()
	work := makeConf(t,
		"Address = 10.200.0.2/32\nDNS = 10.10.0.53, 10.10.1.53, 10.10.2.53",
		"Endpoint = vpn.corp.example:51820\nAllowedIPs = "+allowed,
	)
	// Comment in the first line, as in real work configs.
	work.text = "# work tunnel\n" + work.text
	home := makeConf(t,
		"Address = 10.77.0.2\nListenPort = 51821",
		"Endpoint = 198.51.100.7:51820\nAllowedIPs = 192.168.1.0/24",
		"Endpoint = 198.51.100.8:51820\nAllowedIPs = 192.168.2.0/24\nPersistentKeepalive = 25",
	)
	// A PresharedKey on the second peer.
	pskKey, pskB64 := genKey(t)
	home.text += "PresharedKey = " + pskB64 + "\n"
	foreign := func(host string) genConf {
		return makeConf(t,
			"Address = 10.88.0.2\nDNS = 10.88.0.1\nMTU = 1280",
			"Endpoint = "+host+":51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 20",
		)
	}
	nl, de := foreign("nl.example.net"), foreign("de.example.net")

	files := filesOf(exampleYAML, map[string]string{
		"work.conf": work.text, "home.conf": home.text, "nl.conf": nl.text, "de.conf": de.text,
	})
	cfg, warns := mustLoad(t, files)

	// design 9.2: nothing in the example needs a warning (bare addresses and
	// duplicates are normalized silently, all services are used).
	if len(warns) != 0 {
		t.Errorf("warnings = %q, want none", warns)
	}

	if !cfg.IPv6Filter {
		t.Error("IPv6Filter = false, want true")
	}

	type wantTunnel struct {
		name      string
		routes    RouteMode
		autostart bool
		dnsDom    []Domain
		check     netip.Addr
		wg        WGConfig
	}
	foreignWG := func(g genConf, host string) WGConfig {
		return WGConfig{
			PrivateKey: g.priv,
			Addresses:  pfxs("10.88.0.2/32"),
			DNS:        addrs("10.88.0.1"),
			MTU:        1280,
			Peers: []Peer{{
				PublicKey:           g.peers[0],
				Endpoint:            host + ":51820",
				AllowedIPs:          pfxs("0.0.0.0/0"),
				PersistentKeepalive: 20,
			}},
		}
	}
	want := []wantTunnel{
		{
			name: "work", routes: RoutesConfig, autostart: true,
			dnsDom: suffixes("corp.example"), check: addr("10.0.0.1"),
			wg: WGConfig{
				PrivateKey: work.priv,
				Addresses:  pfxs("10.200.0.2/32"),
				DNS:        addrs("10.10.0.53", "10.10.1.53", "10.10.2.53"),
				Peers: []Peer{{
					PublicKey:  work.peers[0],
					Endpoint:   "vpn.corp.example:51820",
					AllowedIPs: wantAllowed,
				}},
			},
		},
		{
			name: "home", routes: RoutesConfig, autostart: false,
			wg: WGConfig{
				PrivateKey: home.priv,
				Addresses:  pfxs("10.77.0.2/32"),
				ListenPort: 51821,
				Peers: []Peer{
					{PublicKey: home.peers[0], Endpoint: "198.51.100.7:51820", AllowedIPs: pfxs("192.168.1.0/24")},
					{PublicKey: home.peers[1], PresharedKey: pskKey, Endpoint: "198.51.100.8:51820",
						AllowedIPs: pfxs("192.168.2.0/24"), PersistentKeepalive: 25},
				},
			},
		},
		{name: "nl", routes: RoutesRules, autostart: true, check: addr("1.1.1.1"), wg: foreignWG(nl, "nl.example.net")},
		{name: "de", routes: RoutesRules, autostart: true, check: addr("1.1.1.1"), wg: foreignWG(de, "de.example.net")},
	}

	// design 6.2: tunnel order is preserved.
	if len(cfg.Tunnels) != len(want) {
		t.Fatalf("got %d tunnels, want %d", len(cfg.Tunnels), len(want))
	}
	for i, w := range want {
		got := cfg.Tunnels[i]
		if got.Name != w.name {
			t.Errorf("Tunnels[%d].Name = %q, want %q", i, got.Name, w.name)
			continue
		}
		checkTunnel(t, got, w.routes, w.autostart, w.dnsDom, w.check, w.wg)
	}

	wantServices := map[string]Service{
		"youtube":  {Domains: suffixes("youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com")},
		"ai":       {Domains: suffixes("openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google.com")},
		"telegram": {CIDRs: pfxs("91.108.4.0/22", "149.154.160.0/20")},
	}
	if len(cfg.Services) != len(wantServices) {
		t.Errorf("got %d services, want %d", len(cfg.Services), len(wantServices))
	}
	for name, w := range wantServices {
		got, ok := cfg.Services[name]
		if !ok {
			t.Errorf("service %q missing", name)
			continue
		}
		if !sameSet(got.Domains, w.Domains) {
			t.Errorf("service %q domains = %v, want %v", name, got.Domains, w.Domains)
		}
		if !sameSet(got.CIDRs, w.CIDRs) {
			t.Errorf("service %q cidrs = %v, want %v", name, got.CIDRs, w.CIDRs)
		}
	}

	wantRules := []Rule{
		{Services: []string{"youtube", "telegram"}, Via: []string{"nl", "de"}, Fallback: FallbackDefault},
		{Services: []string{"ai"}, Via: []string{"nl", "de"}, Fallback: FallbackBlock},
	}
	checkRules(t, cfg.Rules, wantRules)
}

func checkTunnel(t *testing.T, got Tunnel, routes RouteMode, autostart bool, dnsDom []Domain, check netip.Addr, wg WGConfig) {
	t.Helper()
	n := got.Name
	if got.Routes != routes {
		t.Errorf("%s: Routes = %q, want %q", n, got.Routes, routes)
	}
	if got.Autostart != autostart {
		t.Errorf("%s: Autostart = %v, want %v", n, got.Autostart, autostart)
	}
	if !sameSet(got.DNSDomains, dnsDom) {
		t.Errorf("%s: DNSDomains = %v, want %v", n, got.DNSDomains, dnsDom)
	}
	if got.Check != check {
		t.Errorf("%s: Check = %v, want %v", n, got.Check, check)
	}
	g := got.WG
	if g.PrivateKey != wg.PrivateKey {
		t.Errorf("%s: PrivateKey differs from the generated one", n)
	}
	if !sameSet(g.Addresses, wg.Addresses) {
		t.Errorf("%s: Addresses = %v, want %v", n, g.Addresses, wg.Addresses)
	}
	if !sameSet(g.DNS, wg.DNS) {
		t.Errorf("%s: DNS = %v, want %v", n, g.DNS, wg.DNS)
	}
	if g.MTU != wg.MTU {
		t.Errorf("%s: MTU = %d, want %d", n, g.MTU, wg.MTU)
	}
	if g.ListenPort != wg.ListenPort {
		t.Errorf("%s: ListenPort = %d, want %d", n, g.ListenPort, wg.ListenPort)
	}
	if len(g.Peers) != len(wg.Peers) {
		t.Errorf("%s: %d peers, want %d", n, len(g.Peers), len(wg.Peers))
		return
	}
	for i, wp := range wg.Peers {
		gp := g.Peers[i]
		if gp.PublicKey != wp.PublicKey {
			t.Errorf("%s: peer %d PublicKey differs", n, i)
		}
		if gp.PresharedKey != wp.PresharedKey {
			t.Errorf("%s: peer %d PresharedKey differs", n, i)
		}
		if gp.Endpoint != wp.Endpoint {
			t.Errorf("%s: peer %d Endpoint = %q, want %q", n, i, gp.Endpoint, wp.Endpoint)
		}
		if gp.PersistentKeepalive != wp.PersistentKeepalive {
			t.Errorf("%s: peer %d PersistentKeepalive = %d, want %d", n, i, gp.PersistentKeepalive, wp.PersistentKeepalive)
		}
		if !sameSet(gp.AllowedIPs, wp.AllowedIPs) {
			t.Errorf("%s: peer %d AllowedIPs: got %d entries, want %d (deduplicated)", n, i, len(gp.AllowedIPs), len(wp.AllowedIPs))
		}
	}
}

func checkRules(t *testing.T, got, want []Rule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if !slices.Equal(g.Services, w.Services) {
			t.Errorf("Rules[%d].Services = %v, want %v", i, g.Services, w.Services)
		}
		// design 6.3: via is ordered.
		if !slices.Equal(g.Via, w.Via) {
			t.Errorf("Rules[%d].Via = %v, want %v", i, g.Via, w.Via)
		}
		if g.Fallback != w.Fallback {
			t.Errorf("Rules[%d].Fallback = %q, want %q", i, g.Fallback, w.Fallback)
		}
	}
}

// design 9.4: a key prints as "(redacted)" under any formatting (%v, %#v, JSON),
// alone and nested in WGConfig/Peer.
func TestKeyRedactedLoad(t *testing.T) {
	priv, privB64 := genKey(t)
	pub, pubB64 := genKey(t)
	psk, pskB64 := genKey(t)
	// Every raw form a [32]byte could be printed in.
	leaks := func(k Key, b64 string) []string {
		raw := [32]byte(k)
		goSyntax := fmt.Sprintf("%#v", raw)
		return []string{
			b64,
			base64.RawStdEncoding.EncodeToString(raw[:]),
			hex.EncodeToString(raw[:]),
			strings.Trim(fmt.Sprint(raw), "[]"),                        // "%v": 12 34 ...
			goSyntax[strings.Index(goSyntax, "{")+1 : len(goSyntax)-1], // "%#v": 0xc, 0x22, ...
		}
	}
	var forbidden []string
	forbidden = append(forbidden, leaks(priv, privB64)...)
	forbidden = append(forbidden, leaks(pub, pubB64)...)
	forbidden = append(forbidden, leaks(psk, pskB64)...)

	wg := WGConfig{
		PrivateKey: priv,
		Addresses:  pfxs("10.66.0.2/32"),
		Peers:      []Peer{{PublicKey: pub, PresharedKey: psk, Endpoint: "203.0.113.1:51820"}},
	}
	js, err := json.Marshal(wg)
	if err != nil {
		t.Fatalf("json.Marshal(WGConfig): %v", err)
	}
	jsKey, err := json.Marshal(priv)
	if err != nil {
		t.Fatalf("json.Marshal(Key): %v", err)
	}

	outputs := map[string]string{
		"String()":          priv.String(),
		"Sprint":            fmt.Sprint(priv),
		"%v key":            fmt.Sprintf("%v", priv),
		"%s key":            fmt.Sprintf("%s", priv),
		"%+v key":           fmt.Sprintf("%+v", priv),
		"%#v key":           fmt.Sprintf("%#v", priv),
		"%v WGConfig":       fmt.Sprintf("%v", wg),
		"%+v WGConfig":      fmt.Sprintf("%+v", wg),
		"%#v WGConfig":      fmt.Sprintf("%#v", wg),
		"%#v Peer":          fmt.Sprintf("%#v", wg.Peers[0]),
		"%#v *WGConfig":     fmt.Sprintf("%#v", &wg),
		"json Key":          string(jsKey),
		"json WGConfig":     string(js),
		"%v Tunnel":         fmt.Sprintf("%v", Tunnel{Name: "nl", WG: wg}),
		"%#v Tunnel":        fmt.Sprintf("%#v", Tunnel{Name: "nl", WG: wg}),
		"json Tunnel slice": mustJSON(t, []Tunnel{{Name: "nl", WG: wg}}),
	}
	for name, s := range outputs {
		for _, f := range forbidden {
			if strings.Contains(s, f) {
				t.Errorf("%s: key leaked (%q) in %q", name, f, s)
				break
			}
		}
		if !strings.Contains(s, "(redacted)") {
			t.Errorf("%s: no \"(redacted)\" in %q", name, s)
		}
	}
	// design 9.4: JSON of a key is the string "(redacted)".
	if string(jsKey) != `"(redacted)"` {
		t.Errorf(`json.Marshal(Key) = %s, want "(redacted)"`, jsKey)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

// --- design 9.2: validation errors -----------------------------------------

// errorsMention reports which of subs are missing from the error text
// (case-insensitive substring).
func errorsMention(errs Errors, subs ...string) (missing []string) {
	text := strings.ToLower(errs.Error())
	for _, s := range subs {
		if !strings.Contains(text, strings.ToLower(s)) {
			missing = append(missing, s)
		}
	}
	return missing
}

// design 9.2: every problem fails Load, and the message points the user at the
// problem: it mentions the offending value or name (want). Key material must
// never appear in it (notWant, design 9.4).
func TestLoadValidationErrors(t *testing.T) {
	type tc struct {
		name    string
		yaml    string
		confs   map[string]string // nil: baseConfs
		want    []string          // substrings the error text must contain
		notWant []string          // substrings the error text must not contain
	}
	var cases []tc

	// design 9.2: unique tunnel names.
	cases = append(cases, tc{name: "duplicate tunnel name", want: []string{"twin"}, yaml: `
tunnels:
  - name: twin
    conf: nl.conf
    routes: rules
  - name: twin
    conf: de.conf
    routes: rules
`})

	// design 9.2: unique service names. In YAML a service name is a mapping key,
	// so a duplicate is a repeated key.
	cases = append(cases, tc{name: "duplicate service name", want: []string{"youtube"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
  youtube:
    domains: [ytimg.com]
rules:
  - services: [youtube]
    via: [nl]
`})

	// design 9.2: existing conf.
	cases = append(cases, tc{name: "conf file missing", want: []string{"missing.conf"}, yaml: `
tunnels:
  - name: nl
    conf: missing.conf
    routes: rules
`})
	cases = append(cases, tc{name: "conf field empty", want: []string{"lonely", "conf"}, yaml: `
tunnels:
  - name: lonely
    routes: rules
`})
	// design 9.3: conf refers to a base file name; a path never matches a delivered file.
	cases = append(cases, tc{name: "conf with a path", want: []string{"sub/nl.conf"}, yaml: `
tunnels:
  - name: nl
    conf: sub/nl.conf
    routes: rules
`})

	// design 9.2: one .conf must not be used by several tunnels.
	cases = append(cases, tc{name: "conf shared by two tunnels", want: []string{"shared.conf"},
		confs: map[string]string{"shared.conf": simpleConf(t)}, yaml: `
tunnels:
  - name: nl
    conf: shared.conf
    routes: rules
  - name: de
    conf: shared.conf
    routes: rules
`})

	// design 9.2: rule references existing services and tunnels.
	cases = append(cases, tc{name: "rule references unknown service", want: []string{"nosuch"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube, nosuch]
    via: [nl]
`})
	cases = append(cases, tc{name: "rule references unknown tunnel", want: []string{"ghost"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl, ghost]
`})

	// design 9.2: valid domains. Masks are not supported (design 6.4).
	for _, d := range []string{
		`"exa mple.com"`, `"*.youtube.com"`, `"foo..com"`, `".youtube.com"`, `"-foo.com"`, `"foo-.com"`,
		`"="`, `""`, `"https://youtube.com"`, `"youtube.com/watch"`, `"youtube.com:443"`,
		`"` + strings.Repeat("a", 64) + `.com"`, `"==youtube.com"`,
	} {
		// The value itself; an empty or bare "=" value can only be found by its service.
		want := []string{strings.Trim(d, `"`)}
		if want[0] == "" || want[0] == "=" {
			want = []string{"badsvc"}
		}
		cases = append(cases, tc{name: "invalid service domain " + d, want: want, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  badsvc:
    domains: [` + d + `]
rules:
  - services: [badsvc]
    via: [nl]
`})
	}
	cases = append(cases, tc{name: "invalid dns_domains entry", want: []string{"corp example"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    dns_domains: ["corp example"]
`})
	// design 9.2: dns_domains are zones, "=" (exact name) is not allowed there.
	cases = append(cases, tc{name: "exact name in dns_domains", want: []string{"=corp.example"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    dns_domains: [intra.example, "=corp.example"]
`})

	// design 9.2: valid CIDRs.
	for _, c := range []string{`"91.108.4.0/33"`, `"not-a-cidr"`, `"300.1.1.0/24"`, `""`, `"2001:db8::/129"`, `"10.0.0.0/-1"`} {
		want := []string{strings.Trim(c, `"`)}
		if want[0] == "" {
			want = []string{"badsvc"}
		}
		cases = append(cases, tc{name: "invalid service cidr " + c, want: want, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  badsvc:
    cidrs: [` + c + `]
rules:
  - services: [badsvc]
    via: [nl]
`})
	}

	// design 9.2: .conf is parsed completely; its errors fail Load and name the file.
	// design 9.4: key material never appears in the error text.
	oneTunnel := `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
`
	{
		g := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1",
			"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0")
		privB64 := base64.StdEncoding.EncodeToString(g.priv[:])
		bad := "!!notbase64" + privB64
		cases = append(cases, tc{name: ".conf bad private key", yaml: oneTunnel,
			confs:   map[string]string{"nl.conf": strings.Replace(g.text, privB64, bad, 1)},
			want:    []string{"nl.conf"},
			notWant: []string{bad, privB64, privB64[:16]},
		})
	}
	{
		short := make([]byte, 16)
		if _, err := rand.Read(short); err != nil {
			t.Fatal(err)
		}
		shortB64 := base64.StdEncoding.EncodeToString(short)
		_, pubB64 := genKey(t)
		conf := "[Interface]\nPrivateKey = " + shortB64 + "\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = " +
			pubB64 + "\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0\n"
		cases = append(cases, tc{name: ".conf 16-byte key", yaml: oneTunnel,
			confs:   map[string]string{"nl.conf": conf},
			want:    []string{"nl.conf"},
			notWant: []string{shortB64, shortB64[:12]},
		})
	}
	{
		g := makeConf(t, "Address = 10.66.0.2/32",
			"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.0.0.0/8, bogus")
		privB64 := base64.StdEncoding.EncodeToString(g.priv[:])
		cases = append(cases, tc{name: ".conf bad AllowedIPs", yaml: oneTunnel,
			confs:   map[string]string{"nl.conf": g.text},
			want:    []string{"nl.conf", "bogus"},
			notWant: []string{privB64},
		})
	}

	// design 9.2: unknown YAML keys are an error, at every level; the key is named.
	cases = append(cases,
		tc{name: "unknown top-level key", want: []string{"colour"}, yaml: baseYAML + "colour: red\n"},
		tc{name: "unknown tunnel key", want: []string{"mtu"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    mtu: 1280
`},
		tc{name: "unknown service key", want: []string{"ips"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
    ips: [10.0.0.0/8]
rules:
  - services: [youtube]
    via: [nl]
`},
		tc{name: "unknown rule key", want: []string{"priority"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl]
    priority: 1
`},
	)

	// design 9.2: wgplex.yaml holds a single YAML document.
	// The design names no value to point at, so only the failure is checked.
	cases = append(cases,
		tc{name: "two yaml documents", yaml: baseYAML + "---\n" + baseYAML},
		tc{name: "two yaml documents, second differs", yaml: baseYAML + "---\nipv6_filter: false\n"},
	)

	// design 9.2: a tunnel with dns_domains needs DNS in its .conf.
	cases = append(cases, tc{name: "dns_domains without DNS in conf", want: []string{"work"}, yaml: `
tunnels:
  - name: work
    conf: work.conf
    routes: config
    dns_domains: [corp.example]
`, confs: map[string]string{"work.conf": noDNSConf(t)}})
	// design ambiguity: DNS holding only non-IP values (wg-quick search domains,
	// design 5) is ignored, so the tunnel effectively has no DNS — treated as an error.
	cases = append(cases, tc{name: "dns_domains with only search-domain DNS", want: []string{"work"}, yaml: `
tunnels:
  - name: work
    conf: work.conf
    routes: config
    dns_domains: [corp.example]
`, confs: map[string]string{"work.conf": makeConf(t,
		"Address = 10.67.0.2/32\nDNS = search.example",
		"Endpoint = 203.0.113.2:51820\nAllowedIPs = 10.67.0.0/16").text}})

	// design 9.2: routes is required; only config|rules are valid (design 5.1).
	cases = append(cases,
		tc{name: "routes missing", want: []string{"routes"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
`},
		tc{name: "routes invalid", want: []string{"everything"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: everything
`},
	)

	// design 6.3: fallback is default|block.
	cases = append(cases, tc{name: "fallback invalid", want: []string{"drop"}, yaml: baseYAML + "    fallback: drop\n"})

	// design ambiguity: check is "an address" (design 9.1); a non-IP value is
	// assumed to be an error rather than ignored.
	cases = append(cases, tc{name: "check not an IP", want: []string{"gateway.local"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    check: gateway.local
`})

	// design ambiguity: a tunnel without a name cannot be referenced or shown — assumed an error.
	cases = append(cases, tc{name: "tunnel without name", want: []string{"name"}, yaml: `
tunnels:
  - conf: nl.conf
    routes: rules
`})

	// design 9.2: a routes: config tunnel must not have 0.0.0.0/0 or ::/0 in
	// AllowedIPs (conflict with the system default route). The error names the
	// tunnel and the prefix.
	defaultRouteYAML := `
tunnels:
  - name: work
    conf: work.conf
    routes: config
`
	cases = append(cases,
		tc{name: "routes config with 0.0.0.0/0", want: []string{"work", "0.0.0.0/0"}, yaml: defaultRouteYAML,
			confs: map[string]string{"work.conf": makeConf(t, "Address = 10.66.0.2/32",
				"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.66.0.0/16, 0.0.0.0/0").text}},
		tc{name: "routes config with ::/0", want: []string{"work", "::/0"}, yaml: defaultRouteYAML,
			confs: map[string]string{"work.conf": makeConf(t, "Address = 10.66.0.2/32",
				"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.66.0.0/16, ::/0").text}},
		// The default route in a second [Peer] is found too.
		tc{name: "routes config with 0.0.0.0/0 in second peer", want: []string{"work", "0.0.0.0/0"}, yaml: defaultRouteYAML,
			confs: map[string]string{"work.conf": makeConf(t, "Address = 10.66.0.2/32",
				"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.66.0.0/16",
				"Endpoint = 203.0.113.2:51820\nAllowedIPs = 0.0.0.0/0").text}},
		// Non-canonical /0 (design 9.2 normalization) is still a default route;
		// only the tunnel name is required since the spelling in the message may vary.
		tc{name: "routes config with non-canonical /0", want: []string{"work", "/0"}, yaml: defaultRouteYAML,
			confs: map[string]string{"work.conf": makeConf(t, "Address = 10.66.0.2/32",
				"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.2.3/0").text}},
	)

	// Malformed YAML / wrong types. A syntax error points at the line.
	cases = append(cases,
		tc{name: "yaml syntax error", want: []string{"line"}, yaml: "tunnels:\n  - name: nl\n   conf: [\n"},
		tc{name: "autostart not a bool", want: []string{"maybe"}, yaml: `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    autostart: maybe
`},
		tc{name: "ipv6_filter not a bool", want: []string{"sometimes"}, yaml: "ipv6_filter: sometimes\n" + baseYAML},
	)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			confs := c.confs
			if confs == nil {
				confs = baseConfs(t)
			}
			errs := mustFail(t, filesOf(c.yaml, confs))
			if missing := errorsMention(errs, c.want...); len(missing) > 0 {
				t.Errorf("error text does not mention %q:\n%v", missing, errs)
			}
			for _, s := range c.notWant {
				if strings.Contains(errs.Error(), s) {
					t.Errorf("error text leaks key material %q", s)
				}
			}
		})
	}
}

// design 9.2, 5.1: the default-route ban applies to routes: config only; a
// routes: rules tunnel (foreign VPN) normally has 0.0.0.0/0 and ::/0.
func TestLoadRoutesRulesAllowsDefaultRoute(t *testing.T) {
	conf := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0").text
	cfg, _ := mustLoad(t, filesOf(baseYAML, map[string]string{"nl.conf": conf, "de.conf": simpleConf(t)}))
	want := pfxs("0.0.0.0/0", "::/0")
	if got := tunnelByName(t, cfg, "nl").WG.Peers[0].AllowedIPs; !sameSet(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
}

// design 9.2: wgplex.yaml is one YAML document; an explicit document start
// marker on that single document is fine.
func TestLoadSingleDocumentWithMarker(t *testing.T) {
	cfg, _ := mustLoad(t, filesOf("---\n"+baseYAML, baseConfs(t)))
	if len(cfg.Tunnels) != 2 {
		t.Errorf("got %d tunnels, want 2", len(cfg.Tunnels))
	}
}

// design ambiguity: design 9.3 names wgplex.yaml the main file but does not say
// what happens without it; assumed an error.
func TestLoadMissingMainFile(t *testing.T) {
	mustFail(t, map[string][]byte{"nl.conf": []byte(simpleConf(t))})
}

// design 9.2: all errors are collected, not only the first; each one is
// reported, recognizable by its value or name.
func TestLoadCollectsAllErrors(t *testing.T) {
	yaml := `
tunnels:
  - name: twin
    conf: nl.conf
    routes: rules
  - name: twin
    conf: de.conf
    routes: rules
  - name: work
    conf: missing.conf
    routes: config
  - name: nodns
    conf: home.conf
    routes: config
    dns_domains: [corp.example]
  - name: broken
    conf: broken.conf
    routes: rules
  - name: zoned
    conf: zoned.conf
    routes: rules
    dns_domains: ["=zone.example"]
  - name: first
    conf: shared.conf
    routes: rules
  - name: second
    conf: shared.conf
    routes: rules
  - name: everything
    conf: everything.conf
    routes: config
services:
  bad_domain:
    domains: ["exa mple.com"]
  bad_cidr:
    cidrs: [10.0.0.0/33]
rules:
  - services: [bad_domain, bad_cidr, nosuch]
    via: [twin, ghost]
`
	confs := map[string]string{
		"nl.conf":     simpleConf(t),
		"de.conf":     simpleConf(t),
		"home.conf":   noDNSConf(t),
		"broken.conf": strings.Replace(simpleConf(t), "PrivateKey = ", "PrivateKey = !!", 1),
		"zoned.conf":  simpleConf(t),
		"shared.conf": simpleConf(t),
		"everything.conf": makeConf(t, "Address = 10.68.0.2/32",
			"Endpoint = 203.0.113.3:51820\nAllowedIPs = 0.0.0.0/0").text,
	}
	// One identifier per independent problem.
	problems := map[string]string{
		"duplicate tunnel name":         "twin",
		"missing conf":                  "missing.conf",
		"dns_domains without DNS":       "nodns",
		"broken .conf":                  "broken.conf",
		"exact name in dns_domains":     "=zone.example",
		"conf shared by two tunnels":    "shared.conf",
		"invalid domain":                "exa mple.com",
		"invalid CIDR":                  "10.0.0.0/33",
		"rule with unknown service":     "nosuch",
		"rule with unknown tunnel":      "ghost",
		"default route, routes: config": "everything",
	}
	errs := mustFail(t, filesOf(yaml, confs))
	for problem, id := range problems {
		if missing := errorsMention(errs, id); len(missing) > 0 {
			t.Errorf("%s: no error mentions %q", problem, id)
		}
	}
	if t.Failed() {
		t.Logf("errors:\n%v", errs)
	}
}

// design 9.2: errors in several .conf files are all reported.
func TestLoadCollectsErrorsAcrossConfFiles(t *testing.T) {
	broken := func() string { return strings.Replace(simpleConf(t), "PrivateKey = ", "PrivateKey = !!", 1) }
	errs := mustFail(t, filesOf(baseYAML, map[string]string{"nl.conf": broken(), "de.conf": broken()}))
	if len(errs) < 2 {
		t.Errorf("got %d errors, want at least 2 (one per .conf):\n%v", len(errs), errs)
	}
}

// --- design 9.2: defaults ----------------------------------------------------

func TestLoadDefaults(t *testing.T) {
	cfg, _ := mustLoad(t, filesOf(baseYAML, baseConfs(t)))
	if !cfg.IPv6Filter {
		t.Error("ipv6_filter default: got false, want true")
	}
	for _, tn := range cfg.Tunnels {
		if tn.Autostart {
			t.Errorf("%s: autostart default: got true, want false", tn.Name)
		}
		if tn.Check.IsValid() {
			t.Errorf("%s: Check = %v, want zero (no active check)", tn.Name, tn.Check)
		}
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Fallback != FallbackDefault {
		t.Errorf("fallback default: got %+v, want %q", cfg.Rules, FallbackDefault)
	}
}

func TestLoadExplicitValuesOverrideDefaults(t *testing.T) {
	yaml := `
ipv6_filter: false
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    autostart: true
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl]
    fallback: block
`
	cfg, _ := mustLoad(t, filesOf(yaml, map[string]string{"nl.conf": simpleConf(t)}))
	if cfg.IPv6Filter {
		t.Error("ipv6_filter: false was ignored")
	}
	if !cfg.Tunnels[0].Autostart {
		t.Error("autostart: true was ignored")
	}
	if cfg.Rules[0].Fallback != FallbackBlock {
		t.Errorf("fallback = %q, want block", cfg.Rules[0].Fallback)
	}
}

// design 6.3: an empty via is valid (always direct).
func TestLoadEmptyVia(t *testing.T) {
	for _, via := range []string{"    via: []\n", ""} {
		yaml := `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
  music:
    domains: [music.youtube.com]
rules:
  - services: [youtube]
    via: [nl]
  - services: [music]
` + via
		cfg, _ := mustLoad(t, filesOf(yaml, map[string]string{"nl.conf": simpleConf(t)}))
		if len(cfg.Rules) != 2 || len(cfg.Rules[1].Via) != 0 {
			t.Errorf("via %q: Rules = %+v, want second rule with empty Via", via, cfg.Rules)
		}
	}
}

// design 6.2/6.4: tunnel and rule order is preserved as written.
func TestLoadPreservesOrder(t *testing.T) {
	yaml := `
tunnels:
  - name: c
    conf: c.conf
    routes: rules
  - name: a
    conf: a.conf
    routes: rules
  - name: b
    conf: b.conf
    routes: rules
services:
  s1:
    domains: [one.example]
  s2:
    domains: [two.example]
  s3:
    domains: [three.example]
rules:
  - services: [s3]
    via: [b, c]
  - services: [s1]
    via: [a]
  - services: [s2]
    via: [c, a, b]
`
	cfg, _ := mustLoad(t, filesOf(yaml, map[string]string{"a.conf": simpleConf(t), "b.conf": simpleConf(t), "c.conf": simpleConf(t)}))
	var names []string
	for _, tn := range cfg.Tunnels {
		names = append(names, tn.Name)
	}
	if !slices.Equal(names, []string{"c", "a", "b"}) {
		t.Errorf("tunnel order = %v, want [c a b]", names)
	}
	checkRules(t, cfg.Rules, []Rule{
		{Services: []string{"s3"}, Via: []string{"b", "c"}, Fallback: FallbackDefault},
		{Services: []string{"s1"}, Via: []string{"a"}, Fallback: FallbackDefault},
		{Services: []string{"s2"}, Via: []string{"c", "a", "b"}, Fallback: FallbackDefault},
	})
}

// --- design 6.4/9.2: normalization -------------------------------------------

func TestLoadNormalizesDomains(t *testing.T) {
	yaml := `
tunnels:
  - name: work
    conf: work.conf
    routes: config
    dns_domains: [Corp.Example., INTRA.corp.example]
services:
  mixed:
    domains: [YouTube.COM., "=Google.Com", "=Exact.Example."]
rules:
  - services: [mixed]
    via: [work]
`
	// routes: config forbids a default route in AllowedIPs (design 9.2), so not simpleConf.
	work := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.66.0.0/16").text
	cfg, _ := mustLoad(t, filesOf(yaml, map[string]string{"work.conf": work}))
	wantSvc := []Domain{{Name: "youtube.com"}, {Name: "google.com", Exact: true}, {Name: "exact.example", Exact: true}}
	if got := cfg.Services["mixed"].Domains; !sameSet(got, wantSvc) {
		t.Errorf("service domains = %v, want %v", got, wantSvc)
	}
	wantDNS := suffixes("corp.example", "intra.corp.example")
	if got := tunnelByName(t, cfg, "work").DNSDomains; !sameSet(got, wantDNS) {
		t.Errorf("dns_domains = %v, want %v", got, wantDNS)
	}
}

// design 9.2: a CIDR with host bits in wgplex.yaml is canonicalized with a warning.
func TestLoadCanonicalizesYAMLCIDR(t *testing.T) {
	yaml := `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  tg:
    cidrs: [10.1.2.3/16, 149.154.160.0/20, "2001:db8::1/32"]
rules:
  - services: [tg]
    via: [nl]
`
	cfg, warns := mustLoad(t, filesOf(yaml, map[string]string{"nl.conf": simpleConf(t)}))
	want := pfxs("10.1.0.0/16", "149.154.160.0/20", "2001:db8::/32")
	if got := cfg.Services["tg"].CIDRs; !sameSet(got, want) {
		t.Errorf("cidrs = %v, want %v", got, want)
	}
	if !hasWarning(warns, "10.1.2.3/16") {
		t.Errorf("no warning mentioning 10.1.2.3/16: %q", warns)
	}
	if !hasWarning(warns, "2001:db8::1/32") {
		t.Errorf("no warning mentioning 2001:db8::1/32: %q", warns)
	}
	if hasWarning(warns, "149.154.160.0/20") {
		t.Errorf("canonical CIDR must not warn: %q", warns)
	}
}

// design 9.2: non-canonical AllowedIPs in .conf is canonicalized with a warning, as wg does.
func TestLoadCanonicalizesConfCIDR(t *testing.T) {
	conf := makeConf(t, "Address = 10.66.0.2/32",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.2.3/16, 192.0.2.0/24").text
	yaml := `
tunnels:
  - name: work
    conf: work.conf
    routes: config
`
	cfg, warns := mustLoad(t, filesOf(yaml, map[string]string{"work.conf": conf}))
	want := pfxs("10.1.0.0/16", "192.0.2.0/24")
	if got := tunnelByName(t, cfg, "work").WG.Peers[0].AllowedIPs; !sameSet(got, want) {
		t.Errorf("AllowedIPs = %v, want %v", got, want)
	}
	if !hasWarning(warns, "10.1.2.3/16") {
		t.Errorf("no warning mentioning 10.1.2.3/16: %q", warns)
	}
}

// design 9.2 "без предупреждения": bare addresses become /32 or /128, duplicates in
// Address, AllowedIPs and DNS (including x and x/32) are dropped — silently.
func TestLoadSilentConfNormalization(t *testing.T) {
	conf := makeConf(t,
		"Address = 10.66.0.2, 10.66.0.2/32, fd00:66::2\nDNS = 10.66.0.1, 10.66.0.1, fd00:66::1",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 192.0.2.7, 192.0.2.7/32, 2001:db8::7, 2001:db8::7/128, 198.51.100.0/24, 198.51.100.0/24",
	).text
	yaml := `
tunnels:
  - name: work
    conf: work.conf
    routes: config
    dns_domains: [corp.example]
`
	cfg, warns := mustLoad(t, filesOf(yaml, map[string]string{"work.conf": conf}))
	if len(warns) != 0 {
		t.Errorf("warnings = %q, want none", warns)
	}
	wg := tunnelByName(t, cfg, "work").WG
	if want := pfxs("10.66.0.2/32", "fd00:66::2/128"); !sameSet(wg.Addresses, want) {
		t.Errorf("Addresses = %v, want %v", wg.Addresses, want)
	}
	if want := addrs("10.66.0.1", "fd00:66::1"); !sameSet(wg.DNS, want) {
		t.Errorf("DNS = %v, want %v", wg.DNS, want)
	}
	if want := pfxs("192.0.2.7/32", "2001:db8::7/128", "198.51.100.0/24"); !sameSet(wg.Peers[0].AllowedIPs, want) {
		t.Errorf("AllowedIPs = %v, want %v", wg.Peers[0].AllowedIPs, want)
	}
}

// design 9.2: Address is an interface address with a prefix length; host bits are
// kept as written (no canonicalization) and no warning is issued.
func TestLoadKeepsAddressAsWritten(t *testing.T) {
	conf := makeConf(t,
		"Address = 10.0.0.2/24, fd00:66::2/64\nDNS = 10.0.0.1",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0",
	).text
	cfg, warns := mustLoad(t, filesOf(baseYAML, map[string]string{"nl.conf": conf, "de.conf": simpleConf(t)}))
	if len(warns) != 0 {
		t.Errorf("warnings = %q, want none", warns)
	}
	got := tunnelByName(t, cfg, "nl").WG.Addresses
	if want := pfxs("10.0.0.2/24", "fd00:66::2/64"); !sameSet(got, want) {
		t.Errorf("Addresses = %v, want %v (as written, not canonical)", got, want)
	}
}

// --- warnings (design 5, 9.2, 9.3) ---------------------------------------------

// design 9.2: a service not used by any rule is a warning, the config still loads.
func TestLoadWarnsUnusedService(t *testing.T) {
	yaml := baseYAML[:strings.Index(baseYAML, "rules:")] + `  forgotten:
    domains: [forgotten.example]
rules:
  - services: [youtube]
    via: [nl, de]
`
	cfg, warns := mustLoad(t, filesOf(yaml, baseConfs(t)))
	if !hasWarning(warns, "forgotten") {
		t.Errorf("no warning about unused service: %q", warns)
	}
	if hasWarning(warns, "youtube") {
		t.Errorf("used service must not warn: %q", warns)
	}
	if _, ok := cfg.Services["forgotten"]; !ok {
		t.Error("unused service must stay in Config")
	}
}

// design 9.3: other *.yaml files are ignored with a warning — even when they are
// not valid YAML or not a valid config.
func TestLoadWarnsExtraYAML(t *testing.T) {
	files := filesOf(baseYAML, baseConfs(t))
	files["old.yaml"] = []byte("tunnels: [\n  this is: not yaml")
	files["backup.yaml"] = []byte(baseYAML + "unknown_key: 1\n")
	cfg, warns := mustLoad(t, files)
	for _, f := range []string{"old.yaml", "backup.yaml"} {
		if !hasWarning(warns, f) {
			t.Errorf("no warning about %s: %q", f, warns)
		}
	}
	if len(cfg.Tunnels) != 2 {
		t.Errorf("got %d tunnels, want 2 from wgplex.yaml", len(cfg.Tunnels))
	}
}

// design 5: wg-quick specific fields are ignored with a warning.
func TestLoadWarnsWGQuickFields(t *testing.T) {
	for _, field := range []string{
		"PreUp = echo up", "PostUp = iptables -A FORWARD", "PreDown = echo down",
		"PostDown = echo bye", "Table = off", "SaveConfig = true",
	} {
		key := strings.TrimSpace(strings.SplitN(field, "=", 2)[0])
		t.Run(key, func(t *testing.T) {
			conf := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1\n"+field,
				"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0").text
			_, warns := mustLoad(t, filesOf(baseYAML, map[string]string{"nl.conf": conf, "de.conf": simpleConf(t)}))
			if !hasWarning(warns, key) {
				t.Errorf("no warning about %s: %q", key, warns)
			}
		})
	}
}

// design 5: non-IP DNS values (wg-quick search domains) are ignored with a warning.
func TestLoadWarnsNonIPDNS(t *testing.T) {
	conf := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1, corp.example",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0").text
	cfg, warns := mustLoad(t, filesOf(baseYAML, map[string]string{"nl.conf": conf, "de.conf": simpleConf(t)}))
	if !hasWarning(warns, "corp.example") {
		t.Errorf("no warning about the search domain: %q", warns)
	}
	if got, want := tunnelByName(t, cfg, "nl").WG.DNS, addrs("10.66.0.1"); !sameSet(got, want) {
		t.Errorf("DNS = %v, want %v", got, want)
	}
}

// design 9.4 / CLAUDE.md: private keys never appear in errors or warnings.
func TestLoadDoesNotLeakKeys(t *testing.T) {
	g := makeConf(t, "Address = 10.66.0.2/32\nDNS = 10.66.0.1\nPostUp = echo",
		"Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.1.2.3/16")
	privB64 := base64.StdEncoding.EncodeToString(g.priv[:])

	_, warns := mustLoad(t, filesOf(baseYAML, map[string]string{"nl.conf": g.text, "de.conf": simpleConf(t)}))
	for _, w := range warns {
		if strings.Contains(w, privB64) {
			t.Errorf("warning leaks the private key: %q", w)
		}
	}

	// An error in the same file (unknown tunnel in a rule) must not leak it either.
	bad := strings.Replace(baseYAML, "via: [nl, de]", "via: [nl, ghost]", 1)
	_, _, err := load(t, filesOf(bad, map[string]string{"nl.conf": g.text, "de.conf": simpleConf(t)}))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), privB64) {
		t.Errorf("error leaks the private key: %v", err)
	}
}
