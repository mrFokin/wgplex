package dns

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow docs/design.md 7.3, 7.4, 8 and the Wirefork M5 plan ("Модель", steps
// 1–6 of the upstream choice; decisions 1, 6, 7), not the implementation.
// Configs are built as literals: no keys at all.

// --- helpers ---------------------------------------------------------------

func m5Pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func m5Addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// m5Domains parses domain patterns as written in YAML ("=name" is exact).
func m5Domains(ss ...string) []config.Domain {
	var out []config.Domain
	for _, s := range ss {
		if s[0] == '=' {
			out = append(out, config.Domain{Name: s[1:], Exact: true})
		} else {
			out = append(out, config.Domain{Name: s})
		}
	}
	return out
}

// m5Tunnel is a tunnel with the given Address, DNS and dns_domains.
func m5Tunnel(name string, addrs, dns []string, domains ...string) config.Tunnel {
	return config.Tunnel{
		Name:       name,
		Routes:     config.RoutesRules,
		DNSDomains: m5Domains(domains...),
		WG: config.WGConfig{
			Addresses: m5Pfxs(addrs...),
			DNS:       m5Addrs(dns...),
		},
	}
}

// m5NoPanic runs f and turns a panic into a test failure.
func m5NoPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// Rule indexes of m5ChooseCfg.
const (
	m5RTun       = 0 // via [de], de has no IPv6
	m5RDirect    = 1 // empty via
	m5RBlock     = 2 // fallback: block, in fallback
	m5RDefFallen = 3 // fallback: default, in fallback (decision 1)
	m5RLow       = 4 // below m5RDefFallen, via [v6], v6 has IPv6
	m5RInZone    = 5 // a rule domain inside a dns_domains zone, via [work]
	m5RBlockUp   = 6 // fallback: block, its tunnel is up
	m5RDefUp     = 7 // fallback: default, its tunnel is up
)

// m5ChooseCfg: tunnels in order de, v6, work, off; v6 has an IPv6 Address
// and no DNS; dns_domains: corp.example in de and work (tie by tunnel order),
// a.corp.example in v6 (longer zone), offline.example in work, off.example in
// off (no utun in m5Ifaces).
func m5ChooseCfg(ipv6Filter bool) *config.Config {
	return &config.Config{
		IPv6Filter: ipv6Filter,
		Tunnels: []config.Tunnel{
			m5Tunnel("de", []string{"10.0.0.2/32"}, []string{"1.0.0.1"}, "corp.example"),
			m5Tunnel("v6", []string{"10.1.0.2/32", "fd00:1::2/128"}, nil, "a.corp.example"),
			m5Tunnel("work", []string{"10.2.0.2/24"}, []string{"10.199.17.1"}, "corp.example", "offline.example"),
			m5Tunnel("off", []string{"10.3.0.2/32"}, []string{"10.3.0.1"}, "off.example"),
		},
		Services: map[string]config.Service{
			"tun":      {Domains: m5Domains("ifconfig.me", "ipinfo.io")},
			"direct":   {Domains: m5Domains("icanhazip.com")},
			"block":    {Domains: m5Domains("example.com")},
			"deffall":  {Domains: m5Domains("=www.example.org", "default.example", "fb.corp.example")},
			"low":      {Domains: m5Domains("example.org")},
			"inzone":   {Domains: m5Domains("rule.corp.example")},
			"blockup":  {Domains: m5Domains("blockup.example")},
			"defup":    {Domains: m5Domains("defup.example")},
			"tunnelv6": {Domains: m5Domains("v6only.example")},
		},
		Rules: []config.Rule{
			m5RTun:       {Services: []string{"tun"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
			m5RDirect:    {Services: []string{"direct"}, Fallback: config.FallbackDefault},
			m5RBlock:     {Services: []string{"block"}, Via: []string{"home"}, Fallback: config.FallbackBlock},
			m5RDefFallen: {Services: []string{"deffall"}, Via: []string{"home"}, Fallback: config.FallbackDefault},
			m5RLow:       {Services: []string{"low", "tunnelv6"}, Via: []string{"v6"}, Fallback: config.FallbackDefault},
			m5RInZone:    {Services: []string{"inzone"}, Via: []string{"work"}, Fallback: config.FallbackDefault},
			m5RBlockUp:   {Services: []string{"blockup"}, Via: []string{"de"}, Fallback: config.FallbackBlock},
			m5RDefUp:     {Services: []string{"defup"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
		},
	}
}

// m5ChooseRules is the SelectRules result for m5ChooseCfg: home is down.
func m5ChooseRules() []router.RuleState {
	return []router.RuleState{
		m5RTun:       {Tunnel: "de"},
		m5RDirect:    {},
		m5RBlock:     {Fallback: true},
		m5RDefFallen: {Fallback: true},
		m5RLow:       {Tunnel: "v6"},
		m5RInZone:    {Tunnel: "work"},
		m5RBlockUp:   {Tunnel: "de"},
		m5RDefUp:     {Tunnel: "de"},
	}
}

// m5Ifaces: de, v6 and work have a utun, off does not.
func m5Ifaces() map[string]int {
	return map[string]int{"de": 15, "v6": 16, "work": 17}
}

func m5Choose(t *testing.T, cfg *config.Config, rules []router.RuleState, ifaces map[string]int, name string) Choice {
	t.Helper()
	var c Choice
	m5NoPanic(t, "Choose", func() { c = Choose(cfg, rules, ifaces, name) })
	return c
}

// m5CheckChoice compares got with want. For a Block choice only Rule and
// Block are compared: the plan does not say what Tunnel and DropAAAA hold
// when no upstream is asked.
func m5CheckChoice(t *testing.T, name string, got, want Choice) {
	t.Helper()
	if want.Block {
		if got.Rule != want.Rule || !got.Block {
			t.Errorf("Choose(%q) = %+v, want Rule %d with Block", name, got, want.Rule)
		}
		return
	}
	if got != want {
		t.Errorf("Choose(%q) = %+v, want %+v", name, got, want)
	}
}

// --- Choose ------------------------------------------------------------------

// design 8 "Выбор апстрима" 1–6, 7.3, 7.4, Wirefork M5 decisions 1, 6, 7.
func TestM5Choose(t *testing.T) {
	cfg := m5ChooseCfg(true)
	rules := m5ChooseRules()
	ifaces := m5Ifaces()
	sys := Choice{Rule: -1}
	cases := []struct {
		why  string
		name string
		want Choice
	}{
		// Step 3: a rule on a tunnel; de has no IPv6 Address → DropAAAA.
		{"rule on a tunnel", "ifconfig.me", Choice{Rule: m5RTun, Tunnel: "de", DropAAAA: true}},
		{"rule on a tunnel, subdomain", "www.ipinfo.io", Choice{Rule: m5RTun, Tunnel: "de", DropAAAA: true}},
		// Step 3: the tunnel has IPv6 → no DropAAAA.
		{"rule on a tunnel with IPv6", "v6only.example", Choice{Rule: m5RLow, Tunnel: "v6"}},
		// Step 4: empty via → system upstream, the rule is kept; direct is
		// not filtered (design 8 IPv6: only when the target tunnel lacks it).
		{"empty via: system upstream", "icanhazip.com", Choice{Rule: m5RDirect}},
		{"empty via: subdomain", "a.icanhazip.com", Choice{Rule: m5RDirect}},
		// Step 2: fallback: block in fallback → NODATA.
		{"fallback block", "example.com", Choice{Rule: m5RBlock, Block: true}},
		{"fallback block, subdomain", "www.example.com", Choice{Rule: m5RBlock, Block: true}},
		// A block rule whose tunnel is up is an ordinary tunnel rule.
		{"block rule with its tunnel up", "blockup.example", Choice{Rule: m5RBlockUp, Tunnel: "de", DropAAAA: true}},
		// Step 1, decision 1: a rule in fallback: default does not take
		// part; the name goes to the rule below (exact above, suffix below).
		{"fallback default: the lower rule gets the name", "www.example.org", Choice{Rule: m5RLow, Tunnel: "v6"}},
		{"fallback default: no lower rule → system", "default.example", sys},
		{"fallback default: no lower rule, dns_domains apply", "fb.corp.example", Choice{Rule: -1, Tunnel: "de"}},
		// A default rule whose tunnel is up takes part as usual.
		{"fallback default rule with its tunnel up", "defup.example", Choice{Rule: m5RDefUp, Tunnel: "de", DropAAAA: true}},
		// Step 5: dns_domains — the longest zone, ties by tunnel order, no
		// dynamic addresses (Rule -1), no AAAA filter.
		{"dns_domains: zone apex", "corp.example", Choice{Rule: -1, Tunnel: "de"}},
		{"dns_domains: tie by tunnel order (de before work)", "host.corp.example", Choice{Rule: -1, Tunnel: "de"}},
		{"dns_domains: longest zone wins over tunnel order", "x.a.corp.example", Choice{Rule: -1, Tunnel: "v6"}},
		{"dns_domains: longest zone, apex", "a.corp.example", Choice{Rule: -1, Tunnel: "v6"}},
		{"dns_domains: second zone of a tunnel", "vault.offline.example", Choice{Rule: -1, Tunnel: "work"}},
		// Decision 7: a tunnel without a utun → as if the field were absent.
		{"dns_domains of a tunnel without utun → system", "y.off.example", sys},
		// Decision 6: a rule wins over dns_domains, even inside a longer zone.
		{"rule wins over dns_domains", "rule.corp.example", Choice{Rule: m5RInZone, Tunnel: "work", DropAAAA: true}},
		{"rule wins over dns_domains, subdomain", "x.rule.corp.example", Choice{Rule: m5RInZone, Tunnel: "work", DropAAAA: true}},
		// Zone boundary: label boundary as in 7.4.
		{"dns_domains: label boundary", "notcorp.example", sys},
		// Step 6.
		{"nothing matches → system", "apple.com", sys},
		{"PTR name → system", "1.0.0.10.in-addr.arpa", sys},
		// 7.4: case and trailing dot.
		{"case and trailing dot: rule", "IfConfig.ME.", Choice{Rule: m5RTun, Tunnel: "de", DropAAAA: true}},
		{"case and trailing dot: block", "WWW.Example.COM.", Choice{Rule: m5RBlock, Block: true}},
		{"case and trailing dot: fallback default", "WWW.example.ORG.", Choice{Rule: m5RLow, Tunnel: "v6"}},
		{"case and trailing dot: dns_domains", "X.A.Corp.Example.", Choice{Rule: -1, Tunnel: "v6"}},
		{"case and trailing dot: system", "Apple.COM.", sys},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m5CheckChoice(t, c.name, m5Choose(t, cfg, rules, ifaces, c.name), c.want)
		})
	}
}

// design 8 step 5, decision 7: without de's utun its zone goes to the next
// tunnel with the same zone; without any, to the system upstream.
func TestM5ChooseDNSDomainsWithoutUtun(t *testing.T) {
	cfg := m5ChooseCfg(true)
	rules := m5ChooseRules()
	cases := []struct {
		why    string
		ifaces map[string]int
		name   string
		want   Choice
	}{
		{"de down: work has the same zone", map[string]int{"v6": 16, "work": 17}, "host.corp.example", Choice{Rule: -1, Tunnel: "work"}},
		{"v6 down: longest zone gone, shorter zone of de", map[string]int{"de": 15, "work": 17}, "x.a.corp.example", Choice{Rule: -1, Tunnel: "de"}},
		{"no utun at all → system", map[string]int{}, "host.corp.example", Choice{Rule: -1}},
		{"nil ifaces → system", nil, "vault.offline.example", Choice{Rule: -1}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m5CheckChoice(t, c.name, m5Choose(t, cfg, rules, c.ifaces, c.name), c.want)
		})
	}
}

// design 8 "IPv6", 10.1: with ipv6_filter: false nothing is filtered.
func TestM5ChooseIPv6FilterOff(t *testing.T) {
	cfg := m5ChooseCfg(false)
	rules := m5ChooseRules()
	ifaces := m5Ifaces()
	cases := []struct {
		name string
		want Choice
	}{
		{"ifconfig.me", Choice{Rule: m5RTun, Tunnel: "de"}},
		{"v6only.example", Choice{Rule: m5RLow, Tunnel: "v6"}},
		{"icanhazip.com", Choice{Rule: m5RDirect}},
		{"rule.corp.example", Choice{Rule: m5RInZone, Tunnel: "work"}},
		{"host.corp.example", Choice{Rule: -1, Tunnel: "de"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m5CheckChoice(t, c.name, m5Choose(t, cfg, rules, ifaces, c.name), c.want)
		})
	}
}

// design 7.4: ties between rules go by rule order also when the upper one is
// in fallback: default and so skipped (decision 1): the next equal one wins.
func TestM5ChooseEqualRulesFallback(t *testing.T) {
	cfg := &config.Config{
		IPv6Filter: true,
		Tunnels: []config.Tunnel{
			m5Tunnel("nl", []string{"10.0.0.2/32", "fd00::2/128"}, nil),
			m5Tunnel("de", []string{"10.1.0.2/32", "fd00:1::2/128"}, nil),
			m5Tunnel("fi", []string{"10.2.0.2/32", "fd00:2::2/128"}, nil),
		},
		Services: map[string]config.Service{
			"a": {Domains: m5Domains("youtube.com")},
			"b": {Domains: m5Domains("youtube.com")},
			"c": {Domains: m5Domains("youtube.com")},
		},
		Rules: []config.Rule{
			{Services: []string{"a"}, Via: []string{"nl"}, Fallback: config.FallbackDefault},
			{Services: []string{"b"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
			{Services: []string{"c"}, Via: []string{"fi"}, Fallback: config.FallbackDefault},
		},
	}
	ifaces := map[string]int{"nl": 15, "de": 16, "fi": 17}
	cases := []struct {
		why   string
		rules []router.RuleState
		want  Choice
	}{
		{"all up: the first rule", []router.RuleState{{Tunnel: "nl"}, {Tunnel: "de"}, {Tunnel: "fi"}}, Choice{Rule: 0, Tunnel: "nl"}},
		{"first in fallback: the second", []router.RuleState{{Fallback: true}, {Tunnel: "de"}, {Tunnel: "fi"}}, Choice{Rule: 1, Tunnel: "de"}},
		{"two in fallback: the third", []router.RuleState{{Fallback: true}, {Fallback: true}, {Tunnel: "fi"}}, Choice{Rule: 2, Tunnel: "fi"}},
		{"all in fallback: system", []router.RuleState{{Fallback: true}, {Fallback: true}, {Fallback: true}}, Choice{Rule: -1}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m5CheckChoice(t, "www.youtube.com", m5Choose(t, cfg, c.rules, ifaces, "www.youtube.com"), c.want)
		})
	}
}

// --- useRule -----------------------------------------------------------------

// Wirefork M5 decision 1: only rules in fallback: default (and in fallback) are left
// out; block and empty via take part.
func TestM5UseRule(t *testing.T) {
	cfg := m5ChooseCfg(true)
	rules := m5ChooseRules()
	var use func(int) bool
	m5NoPanic(t, "useRule", func() { use = useRule(cfg, rules) })
	if use == nil {
		t.Fatal("useRule returned nil")
	}
	want := map[int]bool{
		m5RTun:       true,
		m5RDirect:    true,
		m5RBlock:     true,
		m5RDefFallen: false,
		m5RLow:       true,
		m5RInZone:    true,
		m5RBlockUp:   true,
		m5RDefUp:     true,
	}
	for i := range cfg.Rules {
		var got bool
		m5NoPanic(t, "use", func() { got = use(i) })
		if got != want[i] {
			t.Errorf("useRule(%d) = %v, want %v", i, got, want[i])
		}
	}
}

// --- Servers -----------------------------------------------------------------

// design 8: DNS from the .conf of the tunnel, else 1.1.1.1.
func TestM5Servers(t *testing.T) {
	cases := []struct {
		why  string
		dns  []string
		want []string
	}{
		{"one DNS", []string{"1.0.0.1"}, []string{"1.0.0.1"}},
		{"several DNS, order kept", []string{"10.199.17.1", "10.199.17.2", "2606:4700:4700::1001"}, []string{"10.199.17.1", "10.199.17.2", "2606:4700:4700::1001"}},
		{"no DNS → 1.1.1.1", nil, []string{"1.1.1.1"}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			tun := m5Tunnel("x", []string{"10.0.0.2/32"}, c.dns)
			var got []netip.Addr
			m5NoPanic(t, "Servers", func() { got = Servers(&tun) })
			if !slices.Equal(got, m5Addrs(c.want...)) {
				t.Errorf("Servers = %v, want %v", got, c.want)
			}
		})
	}
}
