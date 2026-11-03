package rpc

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
	"time"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/tunnel"
)

// Tests follow design 7.2, 7.3, 7.4, 8, 10.1 Keys, 14, 13, not the
// implementation. The config is built with config.Load from YAML and .conf
// text; every key is generated per run.

var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// --- fixture -----------------------------------------------------------------

// keyList collects the generated keys of the fixture in base64 and hex.
type keyList []string

func (ks *keyList) gen(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(k[:])
	*ks = append(*ks, b64, hex.EncodeToString(k[:]))
	return b64
}

// fixture is a loaded config with the keys of its .conf files.
type fixture struct {
	cfg  *config.Config
	keys keyList
}

// Rule indexes of fixtureYAML.
const (
	rTun     = 0 // ifconfig.me via [de, fi] → de
	rAI      = 1 // openai.com, 198.51.100.0/24 via [home] block → in fallback
	rCorp    = 2 // icanhazip.com, 192.168.1.0/24, empty via → direct
	rDefFall = 3 // =www.example.org via [home] default → in fallback
	rOrg     = 4 // example.org, 104.18.0.0/16 via [fi] → fi
	rTg      = 5 // 91.108.4.0/22, 10.1.0.0/16 via [home, de] → de, degraded
)

// fixtureYAML: tunnels work (config, dns_domains corp.example), home (config,
// off), de (rules, no IPv6), fi (rules, IPv6, no DNS → 1.1.1.1), bad (config,
// dns_domains bad.example, failed to start).
const fixtureYAML = `tunnels:
  - name: work
    conf: work.conf
    routes: config
    autostart: true
    dns_domains: [corp.example]
  - name: home
    conf: home.conf
    routes: config
  - name: de
    conf: de.conf
    routes: rules
    autostart: true
  - name: fi
    conf: fi.conf
    routes: rules
    autostart: true
  - name: bad
    conf: bad.conf
    routes: config
    dns_domains: [bad.example]
services:
  tun:
    domains: [ifconfig.me]
  ai:
    domains: [openai.com]
    cidrs: [198.51.100.0/24]
  corp:
    domains: [icanhazip.com]
    cidrs: [192.168.1.0/24]
  deffall:
    domains: ["=www.example.org"]
  org:
    domains: [example.org]
    cidrs: [104.18.0.0/16]
  tg:
    cidrs: [91.108.4.0/22, 10.1.0.0/16]
rules:
  - services: [tun]
    via: [de, fi]
  - services: [ai]
    via: [home]
    fallback: block
  - services: [corp]
    via: []
  - services: [deffall]
    via: [home]
  - services: [org]
    via: [fi]
  - services: [tg]
    via: [home, de]
`

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	conf := func(iface string, peers ...string) []byte {
		var b strings.Builder
		fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n%s\n", f.keys.gen(t), iface)
		for _, p := range peers {
			fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n%s\n", f.keys.gen(t), p)
		}
		return []byte(b.String())
	}
	files := map[string][]byte{
		"wgplex.yaml": []byte(fixtureYAML),
		"work.conf": conf("Address = 10.0.0.2/32\nDNS = 10.0.0.53",
			fmt.Sprintf("PresharedKey = %s\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 10.0.0.0/8", f.keys.gen(t))),
		"home.conf": conf("Address = 10.3.0.2/32",
			"Endpoint = 203.0.113.3:51820\nAllowedIPs = 192.168.50.0/24"),
		"de.conf": conf("Address = 10.1.0.2/32\nDNS = 1.0.0.1",
			"Endpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0",
			"AllowedIPs = 10.99.0.0/16"), // no endpoint
		"fi.conf": conf("Address = 10.2.0.2/32, fd00::2/128",
			"Endpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0, ::/0"),
		"bad.conf": conf("Address = 10.4.0.2/32\nDNS = 10.4.0.1",
			"Endpoint = bad.invalid:51820\nAllowedIPs = 198.18.0.0/24"),
	}
	cfg, _, err := config.Load(files)
	if err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	f.cfg = cfg
	return f
}

func addrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
func prefix(s string) netip.Prefix     { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr         { return netip.MustParseAddr(s) }

const badErr = "resolve endpoints: lookup bad.invalid: no such host"

// fixtureTable is the last synced table of newState, sorted as router.Table is
// (address, then bits).
func fixtureTable() router.Table {
	return router.Table{
		{Prefix: prefix("10.0.0.0/8"), Target: router.TargetTunnel, Tunnel: "work", Source: router.SourceAllowedIPs, Rule: -1},
		{Prefix: prefix("10.1.0.0/16"), Target: router.TargetTunnel, Tunnel: "de", Source: router.SourceRuleCIDR, Rule: rTg},
		{Prefix: prefix("34.160.111.145/32"), Target: router.TargetTunnel, Tunnel: "de", Source: router.SourceDynamic, Rule: rTun},
		{Prefix: prefix("91.108.4.0/22"), Target: router.TargetTunnel, Tunnel: "de", Source: router.SourceRuleCIDR, Rule: rTg},
		{Prefix: prefix("104.18.0.0/16"), Target: router.TargetTunnel, Tunnel: "fi", Source: router.SourceRuleCIDR, Rule: rOrg},
		{Prefix: prefix("104.18.32.7/32"), Target: router.TargetTunnel, Tunnel: "fi", Source: router.SourceDynamic, Rule: rOrg},
		{Prefix: prefix("192.168.1.0/24"), Target: router.TargetDirect, Source: router.SourceRuleCIDR, Rule: rCorp},
		// bad has no utun: Sync makes this reject, the table keeps the tunnel.
		{Prefix: prefix("198.18.0.0/24"), Target: router.TargetTunnel, Tunnel: "bad", Source: router.SourceAllowedIPs, Rule: -1},
		{Prefix: prefix("198.51.100.0/24"), Target: router.TargetReject, Source: router.SourceRuleCIDR, Rule: rAI},
		{Prefix: prefix("203.0.113.1/32"), Target: router.TargetDirect, Source: router.SourceEndpoint, Rule: -1},
		{Prefix: prefix("203.0.113.5/32"), Target: router.TargetDirect, Source: router.SourceEndpoint, Rule: -1},
		{Prefix: prefix("203.0.113.7/32"), Target: router.TargetDirect, Source: router.SourceEndpoint, Rule: -1},
	}
}

const skipReason = "a route not added by wgplex exists"

// newState: work, de, fi up; bad enabled with an error; home off.
func newState(f *fixture) *State {
	tbl := fixtureTable()
	return &State{
		Cfg:      f.cfg,
		Warnings: []string{`service "x" is not used by any rule`},
		Tunnels: map[string]TunnelRuntime{
			"work": {
				Interface: "utun5",
				Endpoints: []netip.AddrPort{addrPort("203.0.113.1:51820")},
				Peers:     []tunnel.PeerStats{{LastHandshake: t0.Add(-12 * time.Second), RxBytes: 1258291, TxBytes: 307200}},
			},
			"de": {
				Interface: "utun6",
				Endpoints: []netip.AddrPort{addrPort("203.0.113.5:51820"), {}},
				Peers: []tunnel.PeerStats{
					{LastHandshake: t0.Add(-time.Minute), RxBytes: 10, TxBytes: 20},
					{RxBytes: 0, TxBytes: 92},
				},
			},
			"fi": {
				Interface: "utun7",
				Endpoints: []netip.AddrPort{addrPort("203.0.113.7:51820")},
				Peers:     []tunnel.PeerStats{{}},
			},
			"bad": {Err: badErr},
		},
		Rules: []router.RuleState{
			rTun:     {Tunnel: "de"},
			rAI:      {Fallback: true},
			rCorp:    {},
			rDefFall: {Fallback: true},
			rOrg:     {Tunnel: "fi"},
			rTg:      {Tunnel: "de"},
		},
		Table: tbl,
		Skips: []router.Skip{{Route: tbl[6], Reason: skipReason}},
		Pairs: []dns.Pair{
			{Name: "ifconfig.me", Addr: addr("34.160.111.145"), Deadline: t0.Add(time.Hour)},
			{Name: "ifconfig.me", Addr: addr("34.160.111.146"), Deadline: t0.Add(time.Hour)},
			{Name: "www.example.org", Addr: addr("104.18.32.7"), Deadline: t0.Add(time.Hour)},
			{Name: "www.ifconfig.me", Addr: addr("34.160.111.145"), Deadline: t0.Add(time.Hour)},
		},
		Ifaces: map[string]int{"work": 5, "de": 6, "fi": 7},
	}
}

// --- helpers -------------------------------------------------------------------

func statusOf(t *testing.T, s *State) (got Status) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("StatusOf panicked: %v", r)
		}
	}()
	return StatusOf(s)
}

func explainOf(t *testing.T, s *State, q string) (got Explanation, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Explain(%q) panicked: %v", q, r)
		}
	}()
	return Explain(s, q)
}

func routesOf(t *testing.T, s *State) (got Routes) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RoutesOf panicked: %v", r)
		}
	}()
	return RoutesOf(s)
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(js)
}

// sameStrings compares string lists, nil equal to empty.
func sameStrings(a, b []string) bool { return len(a) == 0 && len(b) == 0 || slices.Equal(a, b) }

func tunnelByName(st Status, name string) (TunnelStatus, bool) {
	for _, ts := range st.Tunnels {
		if ts.Name == name {
			return ts, true
		}
	}
	return TunnelStatus{}, false
}

// checkRule compares a RuleStatus with the wanted one; Degraded is checked
// only when checkDegraded (see TestStatusRules).
func checkRule(t *testing.T, what string, got *RuleStatus, want RuleStatus, checkDegraded bool) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: rule nil, want #%d", what, want.Index)
		return
	}
	if got.Index != want.Index || !sameStrings(got.Services, want.Services) || !sameStrings(got.Via, want.Via) ||
		got.Fallback != want.Fallback || got.Tunnel != want.Tunnel || got.InFallback != want.InFallback ||
		(checkDegraded && got.Degraded != want.Degraded) {
		t.Errorf("%s: rule = %+v\nwant %+v", what, *got, want)
	}
}

// wantRules is the RuleStatus of every rule of newState.
func wantRules() []RuleStatus {
	return []RuleStatus{
		{Index: rTun, Services: []string{"tun"}, Via: []string{"de", "fi"}, Fallback: "default", Tunnel: "de"},
		{Index: rAI, Services: []string{"ai"}, Via: []string{"home"}, Fallback: "block", InFallback: true},
		{Index: rCorp, Services: []string{"corp"}, Fallback: "default"},
		{Index: rDefFall, Services: []string{"deffall"}, Via: []string{"home"}, Fallback: "default", InFallback: true},
		{Index: rOrg, Services: []string{"org"}, Via: []string{"fi"}, Fallback: "default", Tunnel: "fi"},
		{Index: rTg, Services: []string{"tg"}, Via: []string{"home", "de"}, Fallback: "default", Tunnel: "de", Degraded: true},
	}
}

// --- StatusOf ------------------------------------------------------------------

// design 4.1: before any applied config the daemon is empty: not
// configured, icon off, no tunnels or rules.
func TestStatusNoConfig(t *testing.T) {
	got := statusOf(t, &State{})
	if got.Configured || got.Icon != "off" || len(got.Tunnels) != 0 || len(got.Rules) != 0 || len(got.ConfigErrors) != 0 {
		t.Errorf("empty state: %+v, want not configured, icon off, nothing else", got)
	}

	// The first apply failed: still not configured, the errors are
	// shown and the icon is warn.
	errs := []string{`tunnel "x": conf "x.conf" not found`}
	got = statusOf(t, &State{ConfigErrors: errs})
	if got.Configured || got.Icon != "warn" || !slices.Equal(got.ConfigErrors, errs) {
		t.Errorf("failed first apply: %+v, want not configured, icon warn, errors %q", got, errs)
	}
}

// design 14, 13: tunnels in config order with their state; addresses, route
// mode, interface; peers in .conf order with their endpoint as written, the
// resolved address and the stats.
func TestStatusTunnels(t *testing.T) {
	f := newFixture(t)
	got := statusOf(t, newState(f))
	if !got.Configured {
		t.Error("Configured = false with a config")
	}
	if !slices.Equal(got.Warnings, []string{`service "x" is not used by any rule`}) {
		t.Errorf("Warnings = %q", got.Warnings)
	}
	var names []string
	for _, ts := range got.Tunnels {
		names = append(names, ts.Name)
	}
	if !slices.Equal(names, []string{"work", "home", "de", "fi", "bad"}) {
		t.Fatalf("tunnels = %v, want config order work home de fi bad", names)
	}

	type want struct {
		enabled    bool
		state      string
		err        string
		iface      string
		addrs      []string
		routes     string
		routeCount int
		peers      []PeerStatus
	}
	wants := map[string]want{
		"work": {true, "up", "", "utun5", []string{"10.0.0.2/32"}, "config", 1, []PeerStatus{
			{Endpoint: "203.0.113.1:51820", Resolved: "203.0.113.1:51820", LastHandshake: t0.Add(-12 * time.Second), RxBytes: 1258291, TxBytes: 307200},
		}},
		"home": {false, "off", "", "", []string{"10.3.0.2/32"}, "config", 0, nil},
		"de": {true, "up", "", "utun6", []string{"10.1.0.2/32"}, "rules", 3, []PeerStatus{
			{Endpoint: "vpn.example.net:51820", Resolved: "203.0.113.5:51820", LastHandshake: t0.Add(-time.Minute), RxBytes: 10, TxBytes: 20},
			{Endpoint: "", Resolved: "", TxBytes: 92},
		}},
		"fi": {true, "up", "", "utun7", []string{"10.2.0.2/32", "fd00::2/128"}, "rules", 2, []PeerStatus{
			{Endpoint: "203.0.113.7:51820", Resolved: "203.0.113.7:51820"},
		}},
		// Enabled, failed to start; its AllowedIPs stay in the table.
		"bad": {true, "error", badErr, "", []string{"10.4.0.2/32"}, "config", 1, nil},
	}
	for _, ts := range got.Tunnels {
		w := wants[ts.Name]
		if ts.Enabled != w.enabled || ts.State != w.state || ts.Error != w.err || ts.Interface != w.iface || ts.Routes != w.routes {
			t.Errorf("%s: enabled %v state %q error %q iface %q routes %q; want %v %q %q %q %q",
				ts.Name, ts.Enabled, ts.State, ts.Error, ts.Interface, ts.Routes, w.enabled, w.state, w.err, w.iface, w.routes)
		}
		if !sameStrings(ts.Addresses, w.addrs) {
			t.Errorf("%s: Addresses = %q, want %q", ts.Name, ts.Addresses, w.addrs)
		}
		// RouteCount: table routes with Target tunnel via it; endpoint
		// routes are direct and do not count.
		if ts.RouteCount != w.routeCount {
			t.Errorf("%s: RouteCount = %d, want %d", ts.Name, ts.RouteCount, w.routeCount)
		}
		if len(ts.Peers) != len(w.peers) {
			t.Errorf("%s: %d peers, want %d: %+v", ts.Name, len(ts.Peers), len(w.peers), ts.Peers)
			continue
		}
		for i, p := range ts.Peers {
			wp := w.peers[i]
			if p.Endpoint != wp.Endpoint || p.Resolved != wp.Resolved || !p.LastHandshake.Equal(wp.LastHandshake) ||
				p.RxBytes != wp.RxBytes || p.TxBytes != wp.TxBytes {
				t.Errorf("%s: peer %d = %+v\nwant %+v", ts.Name, i, p, wp)
			}
		}
	}
}

// design 7.3, 14: rules in config order with via, fallback and
// the decision; Degraded when on a backup tunnel of via.
func TestStatusRules(t *testing.T) {
	f := newFixture(t)
	// Fixture check: newState.Rules is what SelectRules gives for these
	// tunnels (bad is Up without being Alive).
	sel := router.SelectRules(f.cfg, map[string]router.TunnelState{
		"work": {Up: true, Alive: true},
		"de":   {Up: true, Alive: true},
		"fi":   {Up: true, Alive: true},
		"bad":  {Up: true},
	}, nil)
	if !slices.Equal(sel, newState(f).Rules) {
		t.Fatalf("fixture: SelectRules = %+v, newState.Rules = %+v", sel, newState(f).Rules)
	}

	got := statusOf(t, newState(f))
	want := wantRules()
	if len(got.Rules) != len(want) {
		t.Fatalf("%d rules, want %d", len(got.Rules), len(want))
	}
	for i := range want {
		// Degraded of a rule in fallback is left open: "via non-empty and not
		// on via[0]" literally holds sample does not show it.
		check := !want[i].InFallback
		checkRule(t, fmt.Sprintf("rule %d", i), &got.Rules[i], want[i], check)
	}
	// An empty via is never degraded.
	if got.Rules[rCorp].Degraded {
		t.Error("rule with empty via is Degraded")
	}
}

// The icon.
func TestStatusIcon(t *testing.T) {
	f := newFixture(t)
	up := func(names ...string) map[string]TunnelRuntime {
		m := map[string]TunnelRuntime{}
		for i, n := range names {
			m[n] = TunnelRuntime{Interface: fmt.Sprintf("utun%d", 10+i)}
		}
		return m
	}
	cases := []struct {
		name string
		edit func(s *State)
		want string
	}{
		{"enabled tunnel with error", func(s *State) {}, "warn"},
		{"config error, all up", func(s *State) {
			s.Tunnels = up("work", "de")
			s.ConfigErrors = []string{"wgplex.yaml: bad"}
		}, "warn"},
		{"some up, rest turned off by the user", func(s *State) {
			s.Tunnels = up("work")
			s.Rules = []router.RuleState{{Fallback: true}, {Fallback: true}, {}, {Fallback: true}, {Fallback: true}, {Fallback: true}}
		}, "on"},
		{"all turned off by the user, rules in fallback", func(s *State) {
			s.Tunnels = nil
			s.Rules = []router.RuleState{{Fallback: true}, {Fallback: true}, {}, {Fallback: true}, {Fallback: true}, {Fallback: true}}
		}, "off"},
		{"all off, config error", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{}
			s.ConfigErrors = []string{"wgplex.yaml: bad"}
		}, "warn"},
		{"only an enabled tunnel with error", func(s *State) {
			s.Tunnels = map[string]TunnelRuntime{"bad": {Err: badErr}}
		}, "warn"},
	}
	for _, c := range cases {
		s := newState(f)
		c.edit(s)
		got := statusOf(t, s)
		if got.Icon != c.want {
			t.Errorf("%s: icon %q, want %q", c.name, got.Icon, c.want)
		}
		if !got.Configured {
			t.Errorf("%s: Configured false", c.name)
		}
	}

	// A config error on top of an applied config is shown (it is cleared
	// only by a successful apply, which the daemon does).
	s := newState(f)
	s.ConfigErrors = []string{"a", "b"}
	if got := statusOf(t, s); !slices.Equal(got.ConfigErrors, []string{"a", "b"}) {
		t.Errorf("ConfigErrors = %q, want a b", got.ConfigErrors)
	}
}

// design 10.1 Keys, 14: no key of the fixture, public ones included, in any reply.
func TestNoKeysInReplies(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	outs := map[string]string{
		"status.get":  jsonOf(t, statusOf(t, s)),
		"diag.routes": jsonOf(t, routesOf(t, s)),
	}
	for _, q := range []string{"ifconfig.me", "vault.corp.example", "34.160.111.145", "203.0.113.5"} {
		e, err := explainOf(t, s, q)
		if err != nil {
			t.Fatalf("Explain(%q): %v", q, err)
		}
		outs["diag.explain "+q] = jsonOf(t, e)
	}
	outs["status %+v"] = fmt.Sprintf("%+v", statusOf(t, s))
	for what, out := range outs {
		for _, k := range f.keys {
			if strings.Contains(out, k) {
				t.Errorf("%s contains a key", what)
			}
		}
	}
}

// --- Explain: domains ------------------------------------------------------------

// design 7.4, 8 (dns.Choose): the rule, the upstream and its servers, the
// zone, AAAA filtering and the dynamic addresses of the name.
func TestExplainDomain(t *testing.T) {
	f := newFixture(t)
	rules := wantRules()
	cases := []struct {
		q        string
		query    string
		rule     *RuleStatus
		skipped  *RuleStatus
		upstream string
		zone     string
		servers  []string
		dropAAAA bool
		addrs    []string
	}{
		// A rule on a tunnel: its DNS, AAAA dropped (de has no IPv6), the
		// addresses recorded for this very name (not www.ifconfig.me).
		{q: "ifconfig.me", query: "ifconfig.me", rule: &rules[rTun], upstream: "de",
			servers: []string{"1.0.0.1"}, dropAAAA: true, addrs: []string{"34.160.111.145", "34.160.111.146"}},
		// Case and the trailing dot are ignored (design 7.4).
		{q: "IfConfig.ME.", query: "ifconfig.me", rule: &rules[rTun], upstream: "de",
			servers: []string{"1.0.0.1"}, dropAAAA: true, addrs: []string{"34.160.111.145", "34.160.111.146"}},
		// A subdomain: same rule, its own addresses.
		{q: "www.ifconfig.me", query: "www.ifconfig.me", rule: &rules[rTun], upstream: "de",
			servers: []string{"1.0.0.1"}, dropAAAA: true, addrs: []string{"34.160.111.145"}},
		// A name without recorded addresses.
		{q: "api.ifconfig.me", query: "api.ifconfig.me", rule: &rules[rTun], upstream: "de",
			servers: []string{"1.0.0.1"}, dropAAAA: true},
		// fallback: block in fallback: NODATA (design 7.3, 8 step 2).
		{q: "chat.openai.com", query: "chat.openai.com", rule: &rules[rAI], upstream: "block"},
		// Empty via: the system DNS (design 8 step 4).
		{q: "icanhazip.com", query: "icanhazip.com", rule: &rules[rCorp], upstream: "system"},
		// The exact rule in fallback: default is passed over; the next match
		// (example.org via fi) wins (design 7.4). fi has IPv6
		// and no DNS: 1.1.1.1 (design 8).
		{q: "www.example.org", query: "www.example.org", rule: &rules[rOrg], skipped: &rules[rDefFall],
			upstream: "fi", servers: []string{"1.1.1.1"}, addrs: []string{"104.18.32.7"}},
		// dns_domains of a tunnel with a utun (design 8 step 5).
		{q: "vault.corp.example", query: "vault.corp.example", upstream: "work", zone: "corp.example",
			servers: []string{"10.0.0.53"}},
		{q: "corp.example", query: "corp.example", upstream: "work", zone: "corp.example",
			servers: []string{"10.0.0.53"}},
		// dns_domains of a tunnel without a utun (bad failed): the system DNS
		// as if there were no field (design 8).
		{q: "x.bad.example", query: "x.bad.example", upstream: "system"},
		// Nothing matches: the system DNS (design 8 step 6).
		{q: "unknown.test", query: "unknown.test", upstream: "system"},
	}
	s := newState(f)
	for _, c := range cases {
		got, err := explainOf(t, s, c.q)
		if err != nil {
			t.Errorf("Explain(%q): %v", c.q, err)
			continue
		}
		if got.Query != c.query || got.Kind != "domain" {
			t.Errorf("Explain(%q): query %q kind %q, want %q domain", c.q, got.Query, got.Kind, c.query)
		}
		if c.rule == nil {
			if got.Rule != nil {
				t.Errorf("Explain(%q): rule %+v, want none", c.q, *got.Rule)
			}
		} else {
			checkRule(t, "Explain("+c.q+").Rule", got.Rule, *c.rule, !c.rule.InFallback)
		}
		if c.skipped == nil {
			if got.Skipped != nil {
				t.Errorf("Explain(%q): skipped %+v, want none", c.q, *got.Skipped)
			}
		} else {
			checkRule(t, "Explain("+c.q+").Skipped", got.Skipped, *c.skipped, false)
		}
		if got.Upstream != c.upstream || got.Zone != c.zone || got.DropAAAA != c.dropAAAA {
			t.Errorf("Explain(%q): upstream %q zone %q dropAAAA %v; want %q %q %v",
				c.q, got.Upstream, got.Zone, got.DropAAAA, c.upstream, c.zone, c.dropAAAA)
		}
		if !sameStrings(got.Servers, c.servers) {
			t.Errorf("Explain(%q): servers %q, want %q", c.q, got.Servers, c.servers)
		}
		if !sameStrings(got.Addrs, c.addrs) {
			t.Errorf("Explain(%q): addrs %q, want %q", c.q, got.Addrs, c.addrs)
		}
		if got.Route != nil {
			t.Errorf("Explain(%q): Route %+v for a domain", c.q, *got.Route)
		}
	}
}

// design 8: a rule tunnel without a utun is not chosen (SelectRules skips
// it); with dns_domains of a tunnel turned off the name goes to the
// system DNS.
func TestExplainTunnelWithoutUtun(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	delete(s.Ifaces, "work")
	delete(s.Tunnels, "work")
	got, err := explainOf(t, s, "vault.corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Upstream != "system" || got.Zone != "" || len(got.Servers) != 0 {
		t.Errorf("work without utun: upstream %q zone %q servers %q, want system", got.Upstream, got.Zone, got.Servers)
	}
}

// design 8: with ipv6_filter off AAAA is never dropped.
func TestExplainIPv6FilterOff(t *testing.T) {
	f := newFixture(t)
	f.cfg.IPv6Filter = false
	got, err := explainOf(t, newState(f), "ifconfig.me")
	if err != nil {
		t.Fatal(err)
	}
	if got.DropAAAA {
		t.Error("DropAAAA with ipv6_filter: false")
	}
}

// A query that is neither an IP nor a domain is Invalid params.
func TestExplainInvalid(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	for _, q := range []string{"", "не_домен!", "exa mple.com", "1.2.3.4/24", "a..b", "http://ifconfig.me/"} {
		_, err := explainOf(t, s, q)
		var je *jrpc.JRPCError
		if !errors.As(err, &je) || je.Code != -32602 {
			t.Errorf("Explain(%q) = %v, want a jrpc error -32602", q, err)
		}
	}
}

// Before any config: a domain goes to the system DNS, an IP has no route.
func TestExplainNoConfig(t *testing.T) {
	got, err := explainOf(t, &State{}, "ifconfig.me")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "domain" || got.Rule != nil || got.Upstream != "system" {
		t.Errorf("no config, domain: %+v", got)
	}
	got, err = explainOf(t, &State{}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "ip" || got.Route != nil {
		t.Errorf("no config, IP: %+v", got)
	}
}

// --- Explain: IPs -------------------------------------------------------------------

// design 7.2: the longest prefix of the table; Names of a dynamic route;
// Skipped from Skips; Rule of a rule route; no route: nil (the system
// default route); IPv4-mapped IPv6 is IPv4.
func TestExplainIP(t *testing.T) {
	f := newFixture(t)
	rules := wantRules()
	cases := []struct {
		q       string
		query   string
		route   *RouteInfo
		rule    *RuleStatus
		skipped string
	}{
		{q: "34.160.111.145", query: "34.160.111.145",
			route: &RouteInfo{Prefix: "34.160.111.145/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: rTun,
				Names: []string{"ifconfig.me", "www.ifconfig.me"}},
			rule: &rules[rTun]},
		{q: "::ffff:34.160.111.145", query: "34.160.111.145",
			route: &RouteInfo{Prefix: "34.160.111.145/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: rTun,
				Names: []string{"ifconfig.me", "www.ifconfig.me"}},
			rule: &rules[rTun]},
		// 10.1.0.0/16 (rule) is longer than 10.0.0.0/8 (AllowedIPs of work).
		{q: "10.1.2.3", query: "10.1.2.3",
			route: &RouteInfo{Prefix: "10.1.0.0/16", Target: "tunnel", Tunnel: "de", Source: "rule-cidr", Rule: rTg},
			rule:  &rules[rTg]},
		{q: "10.2.3.4", query: "10.2.3.4",
			route: &RouteInfo{Prefix: "10.0.0.0/8", Target: "tunnel", Tunnel: "work", Source: "allowed-ips", Rule: -1}},
		// The /32 inside the rule CIDR of the same rule.
		{q: "104.18.32.7", query: "104.18.32.7",
			route: &RouteInfo{Prefix: "104.18.32.7/32", Target: "tunnel", Tunnel: "fi", Source: "dynamic", Rule: rOrg,
				Names: []string{"www.example.org"}},
			rule: &rules[rOrg]},
		{q: "104.18.32.8", query: "104.18.32.8",
			route: &RouteInfo{Prefix: "104.18.0.0/16", Target: "tunnel", Tunnel: "fi", Source: "rule-cidr", Rule: rOrg},
			rule:  &rules[rOrg]},
		{q: "192.168.1.10", query: "192.168.1.10",
			route: &RouteInfo{Prefix: "192.168.1.0/24", Target: "direct", Source: "rule-cidr", Rule: rCorp},
			rule:  &rules[rCorp], skipped: skipReason},
		{q: "198.51.100.1", query: "198.51.100.1",
			route: &RouteInfo{Prefix: "198.51.100.0/24", Target: "reject", Source: "rule-cidr", Rule: rAI},
			rule:  &rules[rAI]},
		{q: "203.0.113.5", query: "203.0.113.5",
			route: &RouteInfo{Prefix: "203.0.113.5/32", Target: "direct", Source: "endpoint", Rule: -1}},
		{q: "8.8.8.8", query: "8.8.8.8"},
		{q: "2001:db8::1", query: "2001:db8::1"},
	}
	s := newState(f)
	for _, c := range cases {
		got, err := explainOf(t, s, c.q)
		if err != nil {
			t.Errorf("Explain(%q): %v", c.q, err)
			continue
		}
		if got.Query != c.query || got.Kind != "ip" {
			t.Errorf("Explain(%q): query %q kind %q, want %q ip", c.q, got.Query, got.Kind, c.query)
		}
		switch {
		case c.route == nil && got.Route != nil:
			t.Errorf("Explain(%q): route %+v, want none", c.q, *got.Route)
		case c.route != nil && got.Route == nil:
			t.Errorf("Explain(%q): no route, want %+v", c.q, *c.route)
		case c.route != nil:
			r := *got.Route
			if r.Prefix != c.route.Prefix || r.Target != c.route.Target || r.Tunnel != c.route.Tunnel ||
				r.Source != c.route.Source || r.Rule != c.route.Rule || !sameStrings(r.Names, c.route.Names) || r.Skipped != c.skipped {
				t.Errorf("Explain(%q): route %+v\nwant %+v skipped %q", c.q, r, *c.route, c.skipped)
			}
		}
		if c.rule == nil {
			if got.Rule != nil {
				t.Errorf("Explain(%q): rule %+v, want none", c.q, *got.Rule)
			}
		} else {
			checkRule(t, "Explain("+c.q+").Rule", got.Rule, *c.rule, !c.rule.InFallback)
		}
	}
}

// --- RoutesOf ------------------------------------------------------------------------

// design 13, 14: the last synced table in its order, with Names of dynamic
// routes, Skipped of routes not in the kernel and the Sync error.
func TestRoutesOf(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	got := routesOf(t, s)
	tbl := fixtureTable()
	if len(got.Routes) != len(tbl) {
		t.Fatalf("%d routes, want %d", len(got.Routes), len(tbl))
	}
	names := map[string][]string{
		"34.160.111.145/32": {"ifconfig.me", "www.ifconfig.me"},
		"104.18.32.7/32":    {"www.example.org"},
	}
	for i, r := range tbl {
		g := got.Routes[i]
		skipped := ""
		if r.Prefix == prefix("192.168.1.0/24") {
			skipped = skipReason
		}
		// A tunnel route of a tunnel without a utun (bad, not in
		// Ifaces) is shown as the kernel has it: reject, the tunnel kept.
		target := string(r.Target)
		if r.Target == router.TargetTunnel && s.Ifaces[r.Tunnel] == 0 {
			target = "reject"
		}
		if g.Prefix != r.Prefix.String() || g.Target != target || g.Tunnel != r.Tunnel ||
			g.Source != string(r.Source) || g.Rule != r.Rule || g.Skipped != skipped ||
			!sameStrings(g.Names, names[g.Prefix]) {
			t.Errorf("route %d = %+v\nwant %v target %q names %q skipped %q", i, g, r, target, names[g.Prefix], skipped)
		}
	}
	if got.SyncError != "" {
		t.Errorf("SyncError = %q without an error", got.SyncError)
	}

	s.SyncErr = errors.New("route add 10.0.0.0/8: file exists")
	if got := routesOf(t, s); got.SyncError != "route add 10.0.0.0/8: file exists" {
		t.Errorf("SyncError = %q", got.SyncError)
	}

	if got := routesOf(t, &State{}); len(got.Routes) != 0 || got.SyncError != "" {
		t.Errorf("empty state: %+v", got)
	}
}

// --- A tunnel being brought up ---------------------------------------

// design 14: a tunnel being brought up (Starting) is enabled in
// state "starting" without an error, an interface or peers; its AllowedIPs
// stay in the table (reject in the kernel) and count in RouteCount.
func TestStatusStarting(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	s.Tunnels["bad"] = TunnelRuntime{Starting: true, Endpoints: []netip.AddrPort{{}}}
	got := statusOf(t, s)
	ts, ok := tunnelByName(got, "bad")
	if !ok {
		t.Fatal("tunnel bad missing")
	}
	if !ts.Enabled || ts.State != "starting" || ts.Error != "" || ts.Interface != "" {
		t.Errorf("starting: enabled %v state %q error %q iface %q; want true starting, no error, no iface",
			ts.Enabled, ts.State, ts.Error, ts.Interface)
	}
	if len(ts.Peers) != 0 {
		t.Errorf("starting: peers %+v, want none (State up only)", ts.Peers)
	}
	if ts.RouteCount != 1 {
		t.Errorf("starting: RouteCount = %d, want 1 (198.18.0.0/24)", ts.RouteCount)
	}
	// The other tunnels are not affected.
	if w, _ := tunnelByName(got, "work"); w.State != "up" {
		t.Errorf("work: state %q, want up", w.State)
	}
}

// "starting" never gives warn.
func TestStatusIconStarting(t *testing.T) {
	f := newFixture(t)
	starting := TunnelRuntime{Starting: true}
	cases := []struct {
		name    string
		tunnels map[string]TunnelRuntime
		cfgErrs []string
		want    string
	}{
		{"only starting", map[string]TunnelRuntime{"bad": starting}, nil, "off"},
		{"two starting", map[string]TunnelRuntime{"bad": starting, "home": starting}, nil, "off"},
		{"starting and up", map[string]TunnelRuntime{"bad": starting, "work": {Interface: "utun5"}}, nil, "on"},
		{"starting and error", map[string]TunnelRuntime{"home": starting, "bad": {Err: badErr}}, nil, "warn"},
		{"starting and config error", map[string]TunnelRuntime{"bad": starting}, []string{"wgplex.yaml: bad"}, "warn"},
	}
	for _, c := range cases {
		s := newState(f)
		s.Tunnels = c.tunnels
		s.ConfigErrors = c.cfgErrs
		s.Ifaces = map[string]int{}
		for n, rt := range c.tunnels {
			if rt.Interface != "" {
				s.Ifaces[n] = 5
			}
		}
		if got := statusOf(t, s); got.Icon != c.want {
			t.Errorf("%s: icon %q, want %q", c.name, got.Icon, c.want)
		}
	}
}

// --- Tunnel routes of a tunnel without a utun -------------------------

// diag.routes and diag.explain show a TargetTunnel
// route of a tunnel without a utun (no Ifaces entry, or index 0) as reject
// with its Tunnel kept, the way the kernel has it; with a utun index it is
// "tunnel". RouteCount still counts such a route.
func TestRoutesWithoutUtun(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		edit   func(s *State)
		target string
	}{
		{"error, no Ifaces entry", func(s *State) {}, "reject"},
		{"starting, no Ifaces entry", func(s *State) {
			s.Tunnels["bad"] = TunnelRuntime{Starting: true}
		}, "reject"},
		{"starting, index 0", func(s *State) {
			s.Tunnels["bad"] = TunnelRuntime{Starting: true}
			s.Ifaces["bad"] = 0
		}, "reject"},
		{"up, index > 0", func(s *State) {
			s.Tunnels["bad"] = TunnelRuntime{Interface: "utun9"}
			s.Ifaces["bad"] = 9
		}, "tunnel"},
	}
	const prefix = "198.18.0.0/24"
	for _, c := range cases {
		s := newState(f)
		c.edit(s)

		var got *RouteInfo
		rs := routesOf(t, s)
		for i := range rs.Routes {
			if rs.Routes[i].Prefix == prefix {
				got = &rs.Routes[i]
			}
		}
		if got == nil {
			t.Errorf("%s: RoutesOf has no %s", c.name, prefix)
		} else if got.Target != c.target || got.Tunnel != "bad" || got.Source != "allowed-ips" || got.Rule != -1 {
			t.Errorf("%s: RoutesOf %s = %+v, want target %q tunnel bad allowed-ips rule -1", c.name, prefix, *got, c.target)
		}

		e, err := explainOf(t, s, "198.18.0.5")
		if err != nil {
			t.Fatalf("%s: Explain: %v", c.name, err)
		}
		if e.Route == nil {
			t.Errorf("%s: Explain 198.18.0.5: no route", c.name)
		} else if e.Route.Prefix != prefix || e.Route.Target != c.target || e.Route.Tunnel != "bad" || e.Route.Rule != -1 {
			t.Errorf("%s: Explain 198.18.0.5 route = %+v, want %s target %q tunnel bad", c.name, *e.Route, prefix, c.target)
		}

		ts, _ := tunnelByName(statusOf(t, s), "bad")
		if ts.RouteCount != 1 {
			t.Errorf("%s: RouteCount of bad = %d, want 1", c.name, ts.RouteCount)
		}
	}
}

// A rule route of a tunnel that lost its utun keeps the rule in
// Explain and RoutesOf; only Target becomes reject. The endpoint and direct
// routes are not touched.
func TestRoutesWithoutUtunRule(t *testing.T) {
	f := newFixture(t)
	s := newState(f)
	delete(s.Ifaces, "de")
	s.Tunnels["de"] = TunnelRuntime{Starting: true}
	rules := wantRules()

	e, err := explainOf(t, s, "10.1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	want := RouteInfo{Prefix: "10.1.0.0/16", Target: "reject", Tunnel: "de", Source: "rule-cidr", Rule: rTg}
	if e.Route == nil || e.Route.Prefix != want.Prefix || e.Route.Target != want.Target || e.Route.Tunnel != want.Tunnel ||
		e.Route.Source != want.Source || e.Route.Rule != want.Rule {
		t.Errorf("Explain 10.1.2.3: route %+v, want %+v", e.Route, want)
	}
	checkRule(t, "Explain 10.1.2.3 rule", e.Rule, rules[rTg], true)

	byPrefix := map[string]RouteInfo{}
	for _, r := range routesOf(t, s).Routes {
		byPrefix[r.Prefix] = r
	}
	wants := map[string][2]string{ // prefix → target, tunnel
		"10.1.0.0/16":       {"reject", "de"},
		"34.160.111.145/32": {"reject", "de"},
		"91.108.4.0/22":     {"reject", "de"},
		"10.0.0.0/8":        {"tunnel", "work"},
		"104.18.0.0/16":     {"tunnel", "fi"},
		"192.168.1.0/24":    {"direct", ""},
		"198.51.100.0/24":   {"reject", ""},
		"203.0.113.5/32":    {"direct", ""},
	}
	for p, w := range wants {
		r, ok := byPrefix[p]
		if !ok {
			t.Errorf("RoutesOf: %s missing", p)
			continue
		}
		if r.Target != w[0] || r.Tunnel != w[1] {
			t.Errorf("RoutesOf %s: target %q tunnel %q, want %q %q", p, r.Target, r.Tunnel, w[0], w[1])
		}
	}
	if r := byPrefix["34.160.111.145/32"]; !sameStrings(r.Names, []string{"ifconfig.me", "www.ifconfig.me"}) || r.Rule != rTun {
		t.Errorf("RoutesOf 34.160.111.145/32: names %q rule %d, want the names and rule %d", r.Names, r.Rule, rTun)
	}
}
