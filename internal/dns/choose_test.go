package dns

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow docs/design.md 7.3, 7.4, 8 ("Модель", steps
// 1–6 of the upstream choice), not the implementation.
// Configs are built as literals: no keys at all.

// --- helpers ---------------------------------------------------------------

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func parseAddrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// domainList parses domain patterns as written in YAML ("=name" is exact).
func domainList(ss ...string) []config.Domain {
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

// tunnelCfg is a tunnel with the given Address, DNS and dns_domains.
func tunnelCfg(name string, addrs, dns []string, domains ...string) config.Tunnel {
	return config.Tunnel{
		Name:       name,
		Routes:     config.RoutesRules,
		DNSDomains: domainList(domains...),
		WG: config.WGConfig{
			Addresses: prefixes(addrs...),
			DNS:       parseAddrs(dns...),
		},
	}
}

// noPanic runs f and turns a panic into a test failure.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// Rule indexes of chooseCfg.
const (
	rTun       = 0 // via [de], de has no IPv6
	rDirect    = 1 // empty via
	rBlock     = 2 // fallback: block, in fallback
	rDefFallen = 3 // fallback: default, in fallback
	rLow       = 4 // below rDefFallen, via [v6], v6 has IPv6
	rInZone    = 5 // a rule domain inside a dns_domains zone, via [work]
	rBlockUp   = 6 // fallback: block, its tunnel is up
	rDefUp     = 7 // fallback: default, its tunnel is up
)

// chooseCfg: tunnels in order de, v6, work, off; v6 has an IPv6 Address
// and no DNS; dns_domains: corp.example in de and work (tie by tunnel order),
// a.corp.example in v6 (longer zone), offline.example in work, off.example in
// off (no utun in ifaceIndexes).
func chooseCfg(ipv6Filter bool) *config.Config {
	return &config.Config{
		IPv6Filter: ipv6Filter,
		Tunnels: []config.Tunnel{
			tunnelCfg("de", []string{"10.0.0.2/32"}, []string{"1.0.0.1"}, "corp.example"),
			tunnelCfg("v6", []string{"10.1.0.2/32", "fd00:1::2/128"}, nil, "a.corp.example"),
			tunnelCfg("work", []string{"10.2.0.2/24"}, []string{"10.199.17.1"}, "corp.example", "offline.example"),
			tunnelCfg("off", []string{"10.3.0.2/32"}, []string{"10.3.0.1"}, "off.example"),
		},
		Services: map[string]config.Service{
			"tun":      {Domains: domainList("ifconfig.me", "ipinfo.io")},
			"direct":   {Domains: domainList("icanhazip.com")},
			"block":    {Domains: domainList("example.com")},
			"deffall":  {Domains: domainList("=www.example.org", "default.example", "fb.corp.example")},
			"low":      {Domains: domainList("example.org")},
			"inzone":   {Domains: domainList("rule.corp.example")},
			"blockup":  {Domains: domainList("blockup.example")},
			"defup":    {Domains: domainList("defup.example")},
			"tunnelv6": {Domains: domainList("v6only.example")},
		},
		Rules: []config.Rule{
			rTun:       {Services: []string{"tun"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
			rDirect:    {Services: []string{"direct"}, Fallback: config.FallbackDefault},
			rBlock:     {Services: []string{"block"}, Via: []string{"home"}, Fallback: config.FallbackBlock},
			rDefFallen: {Services: []string{"deffall"}, Via: []string{"home"}, Fallback: config.FallbackDefault},
			rLow:       {Services: []string{"low", "tunnelv6"}, Via: []string{"v6"}, Fallback: config.FallbackDefault},
			rInZone:    {Services: []string{"inzone"}, Via: []string{"work"}, Fallback: config.FallbackDefault},
			rBlockUp:   {Services: []string{"blockup"}, Via: []string{"de"}, Fallback: config.FallbackBlock},
			rDefUp:     {Services: []string{"defup"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
		},
	}
}

// chooseRules is the SelectRules result for chooseCfg: home is down.
func chooseRules() []router.RuleState {
	return []router.RuleState{
		rTun:       {Tunnel: "de"},
		rDirect:    {},
		rBlock:     {Fallback: true},
		rDefFallen: {Fallback: true},
		rLow:       {Tunnel: "v6"},
		rInZone:    {Tunnel: "work"},
		rBlockUp:   {Tunnel: "de"},
		rDefUp:     {Tunnel: "de"},
	}
}

// ifaceIndexes: de, v6 and work have a utun, off does not.
func ifaceIndexes() map[string]int {
	return map[string]int{"de": 15, "v6": 16, "work": 17}
}

func chooseFor(t *testing.T, cfg *config.Config, rules []router.RuleState, ifaces map[string]int, name string) Choice {
	t.Helper()
	var c Choice
	noPanic(t, "Choose", func() { c = Choose(cfg, rules, ifaces, name) })
	return c
}

// checkChoice compares got with want. For a Block choice only Rule and
// Block are compared: what Tunnel and DropAAAA hold
// when no upstream is asked is not specified.
func checkChoice(t *testing.T, name string, got, want Choice) {
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

// design 8 "Выбор апстрима" 1–6, 6.3, 6.4.
func TestChoose(t *testing.T) {
	cfg := chooseCfg(true)
	rules := chooseRules()
	ifaces := ifaceIndexes()
	sys := Choice{Rule: -1}
	cases := []struct {
		why  string
		name string
		want Choice
	}{
		// Step 3: a rule on a tunnel; de has no IPv6 Address → DropAAAA.
		{"rule on a tunnel", "ifconfig.me", Choice{Rule: rTun, Tunnel: "de", DropAAAA: true}},
		{"rule on a tunnel, subdomain", "www.ipinfo.io", Choice{Rule: rTun, Tunnel: "de", DropAAAA: true}},
		// Step 3: the tunnel has IPv6 → no DropAAAA.
		{"rule on a tunnel with IPv6", "v6only.example", Choice{Rule: rLow, Tunnel: "v6"}},
		// Step 4: empty via → system upstream, the rule is kept; direct is
		// not filtered (design 8 IPv6: only when the target tunnel lacks it).
		{"empty via: system upstream", "icanhazip.com", Choice{Rule: rDirect}},
		{"empty via: subdomain", "a.icanhazip.com", Choice{Rule: rDirect}},
		// Step 2: fallback: block in fallback → NODATA.
		{"fallback block", "example.com", Choice{Rule: rBlock, Block: true}},
		{"fallback block, subdomain", "www.example.com", Choice{Rule: rBlock, Block: true}},
		// A block rule whose tunnel is up is an ordinary tunnel rule.
		{"block rule with its tunnel up", "blockup.example", Choice{Rule: rBlockUp, Tunnel: "de", DropAAAA: true}},
		// Step 1: a rule in fallback: default does not take
		// part; the name goes to the rule below (exact above, suffix below).
		{"fallback default: the lower rule gets the name", "www.example.org", Choice{Rule: rLow, Tunnel: "v6"}},
		{"fallback default: no lower rule → system", "default.example", sys},
		{"fallback default: no lower rule, dns_domains apply", "fb.corp.example", Choice{Rule: -1, Tunnel: "de"}},
		// A default rule whose tunnel is up takes part as usual.
		{"fallback default rule with its tunnel up", "defup.example", Choice{Rule: rDefUp, Tunnel: "de", DropAAAA: true}},
		// Step 5: dns_domains — the longest zone, ties by tunnel order, no
		// dynamic addresses (Rule -1), no AAAA filter.
		{"dns_domains: zone apex", "corp.example", Choice{Rule: -1, Tunnel: "de"}},
		{"dns_domains: tie by tunnel order (de before work)", "host.corp.example", Choice{Rule: -1, Tunnel: "de"}},
		{"dns_domains: longest zone wins over tunnel order", "x.a.corp.example", Choice{Rule: -1, Tunnel: "v6"}},
		{"dns_domains: longest zone, apex", "a.corp.example", Choice{Rule: -1, Tunnel: "v6"}},
		{"dns_domains: second zone of a tunnel", "vault.offline.example", Choice{Rule: -1, Tunnel: "work"}},
		// A tunnel without a utun → as if the field were absent.
		{"dns_domains of a tunnel without utun → system", "y.off.example", sys},
		// A rule wins over dns_domains, even inside a longer zone.
		{"rule wins over dns_domains", "rule.corp.example", Choice{Rule: rInZone, Tunnel: "work", DropAAAA: true}},
		{"rule wins over dns_domains, subdomain", "x.rule.corp.example", Choice{Rule: rInZone, Tunnel: "work", DropAAAA: true}},
		// Zone boundary: label boundary as in 6.4.
		{"dns_domains: label boundary", "notcorp.example", sys},
		// Step 6.
		{"nothing matches → system", "apple.com", sys},
		{"PTR name → system", "1.0.0.10.in-addr.arpa", sys},
		// 6.4: case and trailing dot.
		{"case and trailing dot: rule", "IfConfig.ME.", Choice{Rule: rTun, Tunnel: "de", DropAAAA: true}},
		{"case and trailing dot: block", "WWW.Example.COM.", Choice{Rule: rBlock, Block: true}},
		{"case and trailing dot: fallback default", "WWW.example.ORG.", Choice{Rule: rLow, Tunnel: "v6"}},
		{"case and trailing dot: dns_domains", "X.A.Corp.Example.", Choice{Rule: -1, Tunnel: "v6"}},
		{"case and trailing dot: system", "Apple.COM.", sys},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			checkChoice(t, c.name, chooseFor(t, cfg, rules, ifaces, c.name), c.want)
		})
	}
}

// design 8 step 5: without de's utun its zone goes to the next
// tunnel with the same zone; without any, to the system upstream.
func TestChooseDNSDomainsWithoutUtun(t *testing.T) {
	cfg := chooseCfg(true)
	rules := chooseRules()
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
			checkChoice(t, c.name, chooseFor(t, cfg, rules, c.ifaces, c.name), c.want)
		})
	}
}

// design 8 "IPv6", 9.2: with ipv6_filter: false nothing is filtered.
func TestChooseIPv6FilterOff(t *testing.T) {
	cfg := chooseCfg(false)
	rules := chooseRules()
	ifaces := ifaceIndexes()
	cases := []struct {
		name string
		want Choice
	}{
		{"ifconfig.me", Choice{Rule: rTun, Tunnel: "de"}},
		{"v6only.example", Choice{Rule: rLow, Tunnel: "v6"}},
		{"icanhazip.com", Choice{Rule: rDirect}},
		{"rule.corp.example", Choice{Rule: rInZone, Tunnel: "work"}},
		{"host.corp.example", Choice{Rule: -1, Tunnel: "de"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkChoice(t, c.name, chooseFor(t, cfg, rules, ifaces, c.name), c.want)
		})
	}
}

// design 7.4: ties between rules go by rule order also when the upper one is
// in fallback: default and so skipped: the next equal one wins.
func TestChooseEqualRulesFallback(t *testing.T) {
	cfg := &config.Config{
		IPv6Filter: true,
		Tunnels: []config.Tunnel{
			tunnelCfg("nl", []string{"10.0.0.2/32", "fd00::2/128"}, nil),
			tunnelCfg("de", []string{"10.1.0.2/32", "fd00:1::2/128"}, nil),
			tunnelCfg("fi", []string{"10.2.0.2/32", "fd00:2::2/128"}, nil),
		},
		Services: map[string]config.Service{
			"a": {Domains: domainList("youtube.com")},
			"b": {Domains: domainList("youtube.com")},
			"c": {Domains: domainList("youtube.com")},
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
			checkChoice(t, "www.youtube.com", chooseFor(t, cfg, c.rules, ifaces, "www.youtube.com"), c.want)
		})
	}
}

// --- useRule -----------------------------------------------------------------

// Only rules in fallback: default (and in fallback) are left
// out; block and empty via take part.
func TestUseRule(t *testing.T) {
	cfg := chooseCfg(true)
	rules := chooseRules()
	var use func(int) bool
	noPanic(t, "useRule", func() { use = useRule(cfg, rules) })
	if use == nil {
		t.Fatal("useRule returned nil")
	}
	want := map[int]bool{
		rTun:       true,
		rDirect:    true,
		rBlock:     true,
		rDefFallen: false,
		rLow:       true,
		rInZone:    true,
		rBlockUp:   true,
		rDefUp:     true,
	}
	for i := range cfg.Rules {
		var got bool
		noPanic(t, "use", func() { got = use(i) })
		if got != want[i] {
			t.Errorf("useRule(%d) = %v, want %v", i, got, want[i])
		}
	}
}

// --- Servers -----------------------------------------------------------------

// design 8: DNS from the .conf of the tunnel, else 1.1.1.1.
func TestServers(t *testing.T) {
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
			tun := tunnelCfg("x", []string{"10.0.0.2/32"}, c.dns)
			var got []netip.Addr
			noPanic(t, "Servers", func() { got = Servers(&tun) })
			if !slices.Equal(got, parseAddrs(c.want...)) {
				t.Errorf("Servers = %v, want %v", got, c.want)
			}
		})
	}
}
