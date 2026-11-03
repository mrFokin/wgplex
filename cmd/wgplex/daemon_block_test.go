package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/dns"
	"github.com/mrFokin/wgplex/internal/router"
	"github.com/mrFokin/wgplex/internal/state"
)

// Tests of design 9.1, 10.2, 11 (the block snapshot): what goes into it, the
// config built from it, the reject routes and NODATA it gives, and its
// replacement at an applied config. Pure logic, no system calls.

// blockCfgYAML has two block rules sharing a service (each entry once), a
// service of a rule with fallback: default that must stay out, and an exact
// domain.
func blockCfgYAML() string {
	return "tunnels:\n" + tunnelYAML("de", "rules", true) + `services:
  tg:
    cidrs: [91.108.4.0/22, 2001:db8::/32]
    domains: [tg.example]
  ai:
    domains: [ai.example, =exact.example.org]
  video:
    cidrs: [203.0.113.0/24]
    domains: [video.example]
rules:
  - services: [tg, ai]
    via: [de]
    fallback: block
  - services: [video]
    via: [de]
    fallback: default
  - services: [tg]
    via: []
    fallback: block
`
}

func blockTestConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	return loadConfig(t, yaml, newConfFiles(t).texts(nil))
}

// design 9.1: the snapshot holds the CIDRs and the domains of the services of
// the rules with fallback: block, each once, an exact domain with its "=";
// the services of a fallback: default rule stay out.
func TestBlockOf(t *testing.T) {
	got := blockOf(blockTestConfig(t, blockCfgYAML()))
	if got == nil {
		t.Fatal("blockOf = nil, want the snapshot")
	}
	wantCIDRs := []string{"91.108.4.0/22", "2001:db8::/32"}
	wantDomains := []string{"tg.example", "ai.example", "=exact.example.org"}
	if !slices.Equal(got.CIDRs, wantCIDRs) {
		t.Errorf("CIDRs = %v, want %v", got.CIDRs, wantCIDRs)
	}
	if !slices.Equal(got.Domains, wantDomains) {
		t.Errorf("Domains = %v, want %v", got.Domains, wantDomains)
	}
}

// design 9.1: an empty config or a config without block rules gives an empty
// snapshot (nil).
func TestBlockOfEmpty(t *testing.T) {
	cases := map[string]string{
		"empty config":     "tunnels: []\n",
		"no block rule":    baseYAML(baseTunnels()...),
		"default fallback": "tunnels:\n" + tunnelYAML("de", "rules", true) + "services:\n  s:\n    cidrs: [198.51.100.0/24]\nrules:\n  - services: [s]\n    via: [de]\n    fallback: default\n",
	}
	for name, yaml := range cases {
		if b := blockOf(blockTestConfig(t, yaml)); b != nil {
			t.Errorf("%s: blockOf = %+v, want nil", name, b)
		}
	}
}

// design 9.1: blockConfig makes of the snapshot a config without tunnels
// whose table holds a reject route on every CIDR, with RuleState Fallback.
func TestBlockConfigTable(t *testing.T) {
	b := &state.Block{
		CIDRs:   []string{"91.108.4.0/22", "198.51.100.0/24", "2001:db8::/32"},
		Domains: []string{"tg.example", "=exact.example.org"},
	}
	cfg, rules := blockConfig(b)
	if cfg == nil {
		t.Fatal("blockConfig = nil")
	}
	if len(cfg.Tunnels) != 0 {
		t.Errorf("tunnels = %v, want none", cfg.Tunnels)
	}
	if len(rules) != len(cfg.Rules) || len(rules) == 0 || !rules[0].Fallback || rules[0].Tunnel != "" {
		t.Errorf("rule states = %+v for %d rules, want fallback", rules, len(cfg.Rules))
	}
	table := tableFor(cfg, nil, rules, nil, nil)
	var got []string
	for _, r := range table {
		if r.Target != router.TargetReject {
			t.Errorf("route %v: target %q, want reject", r.Prefix, r.Target)
		}
		got = append(got, r.Prefix.String())
	}
	slices.Sort(got)
	want := []string{"198.51.100.0/24", "2001:db8::/32", "91.108.4.0/22"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("table prefixes = %v, want %v", got, want)
	}
}

// design 8, 9.1: the resolver answers NODATA (Block) for the domains of the
// snapshot: a suffix for its subdomains too, an exact one only for the name;
// other names are not blocked.
func TestBlockConfigDNS(t *testing.T) {
	b := &state.Block{Domains: []string{"tg.example", "=exact.example.org"}}
	cfg, rules := blockConfig(b)
	if cfg == nil {
		t.Fatal("blockConfig = nil")
	}
	cases := []struct {
		name  string
		block bool
	}{
		{"tg.example", true},
		{"www.tg.example", true},
		{"TG.Example.", true}, // case and trailing dot
		{"exact.example.org", true},
		{"sub.exact.example.org", false}, // exact: not the subdomains
		{"nottg.example", false},         // a suffix matches on a label boundary
		{"other.test", false},
	}
	for _, c := range cases {
		if got := dns.Choose(cfg, rules, nil, c.name); got.Block != c.block {
			t.Errorf("Choose(%q).Block = %v, want %v", c.name, got.Block, c.block)
		}
	}
	if !cfg.NeedsDNS() {
		t.Error("NeedsDNS = false for a snapshot with domains: the capture must be set")
	}
}

// design 9.1: a snapshot of CIDRs alone gives routes and no DNS work; one of
// domains alone gives no routes.
func TestBlockConfigParts(t *testing.T) {
	cfg, rules := blockConfig(&state.Block{CIDRs: []string{"198.51.100.0/24"}})
	if cfg == nil {
		t.Fatal("blockConfig(cidrs) = nil")
	}
	if cfg.NeedsDNS() {
		t.Error("NeedsDNS = true for a snapshot without domains")
	}
	if table := tableFor(cfg, nil, rules, nil, nil); len(table) != 1 {
		t.Errorf("table = %v, want one reject route", table)
	}

	cfg, rules = blockConfig(&state.Block{Domains: []string{"tg.example"}})
	if cfg == nil {
		t.Fatal("blockConfig(domains) = nil")
	}
	if table := tableFor(cfg, nil, rules, nil, nil); len(table) != 0 {
		t.Errorf("table = %v, want no routes", table)
	}
	if !cfg.NeedsDNS() {
		t.Error("NeedsDNS = false for a snapshot with domains")
	}
}

// design 9.1: an empty or missing snapshot gives nothing: no config, no
// rules, so the table is empty and the capture is not set.
func TestBlockConfigEmpty(t *testing.T) {
	for name, b := range map[string]*state.Block{"nil": nil, "empty": {}} {
		cfg, rules := blockConfig(b)
		if cfg != nil || len(rules) != 0 {
			t.Errorf("%s: blockConfig = %+v, %+v; want nil, none", name, cfg, rules)
		}
		if cfg.NeedsDNS() {
			t.Errorf("%s: NeedsDNS = true", name)
		}
		if table := tableFor(cfg, nil, rules, nil, nil); len(table) != 0 {
			t.Errorf("%s: table = %v, want empty", name, table)
		}
	}
}

// blockConfig doc: an entry that does not parse (a hand-edited state.json) is
// skipped, the rest is kept.
func TestBlockConfigBadEntry(t *testing.T) {
	cfg, rules := blockConfig(&state.Block{CIDRs: []string{"not-a-cidr", "198.51.100.0/24"}})
	if cfg == nil {
		t.Fatal("blockConfig = nil, want the valid entry kept")
	}
	table := tableFor(cfg, nil, rules, nil, nil)
	if len(table) != 1 || table[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") {
		t.Errorf("table = %v, want one route on 198.51.100.0/24", table)
	}
}

// design 9.1: the snapshot of a config gives, through blockConfig, the same
// reject routes and blocked names as the config itself in fallback.
func TestBlockSnapshotMatchesConfig(t *testing.T) {
	yaml := "tunnels:\n" + tunnelYAML("de", "rules", true) + `services:
  s:
    cidrs: [91.108.4.0/22, 198.51.100.0/24]
    domains: [s.example, =exact.example.org]
rules:
  - services: [s]
    via: [de]
    fallback: block
`
	orig := blockTestConfig(t, yaml)
	fallback := []router.RuleState{{Fallback: true}}
	want := tableFor(orig, nil, fallback, nil, nil)

	cfg, rules := blockConfig(blockOf(orig))
	got := tableFor(cfg, nil, rules, nil, nil)
	if len(got) != len(want) {
		t.Fatalf("table = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Prefix != want[i].Prefix || got[i].Target != want[i].Target {
			t.Errorf("route %d = %v %s, want %v %s", i, got[i].Prefix, got[i].Target, want[i].Prefix, want[i].Target)
		}
	}
	for _, name := range []string{"s.example", "x.s.example", "exact.example.org", "x.exact.example.org", "other.test"} {
		w := dns.Choose(orig, fallback, nil, name).Block
		if g := dns.Choose(cfg, rules, nil, name).Block; g != w {
			t.Errorf("Choose(%q).Block = %v, the config itself gives %v", name, g, w)
		}
	}
}

// design 9.1, 11: a successful apply replaces the snapshot; the same snapshot
// again is no change (state.json is not rewritten); a config without block
// rules empties it.
func TestDaemonSetBlock(t *testing.T) {
	d := testDaemon(t, t.TempDir()+"/state.json", state.State{})
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()

	a := blockTestConfig(t, blockCfgYAML())
	if !d.setBlock(a) {
		t.Error("setBlock(first config) = false, want a change")
	}
	if want := blockOf(a); d.toggles.Block == nil || !slices.Equal(d.toggles.Block.CIDRs, want.CIDRs) || !slices.Equal(d.toggles.Block.Domains, want.Domains) {
		t.Errorf("snapshot = %+v, want %+v", d.toggles.Block, want)
	}
	if d.setBlock(a) {
		t.Error("setBlock(same config) = true, want no change")
	}
	if d.setBlock(blockTestConfig(t, blockCfgYAML())) {
		t.Error("setBlock(equal config) = true, want no change")
	}

	b := blockTestConfig(t, "tunnels:\n"+tunnelYAML("de", "rules", true)+"services:\n  s:\n    cidrs: [198.51.100.0/24]\nrules:\n  - services: [s]\n    via: [de]\n    fallback: block\n")
	if !d.setBlock(b) {
		t.Error("setBlock(other config) = false, want a change")
	}
	if d.toggles.Block == nil || !slices.Equal(d.toggles.Block.CIDRs, []string{"198.51.100.0/24"}) || len(d.toggles.Block.Domains) != 0 {
		t.Errorf("snapshot = %+v, want the CIDR of the new config only (replaced, not merged)", d.toggles.Block)
	}

	none := blockTestConfig(t, baseYAML(baseTunnels()...))
	if !d.setBlock(none) {
		t.Error("setBlock(config without block) = false, want a change")
	}
	if d.toggles.Block != nil {
		t.Errorf("snapshot = %+v, want none", d.toggles.Block)
	}
	if d.setBlock(none) {
		t.Error("setBlock(config without block) twice = true, want no change")
	}
}

// design 9.1: effectiveCfg is the applied config; while there is none, the
// synthetic config of the snapshot; neither: nil. A config applied wins.
func TestDaemonEffectiveCfg(t *testing.T) {
	d := testDaemon(t, t.TempDir()+"/state.json", state.State{})
	d.mu.Lock()
	defer d.mu.Unlock()
	if got := d.effectiveCfg(); got != nil {
		t.Errorf("effectiveCfg with nothing = %+v, want nil", got)
	}

	syn, _ := blockConfig(&state.Block{CIDRs: []string{"198.51.100.0/24"}})
	d.blockCfg = syn
	if got := d.effectiveCfg(); got != syn {
		t.Errorf("effectiveCfg with only a snapshot = %p, want the synthetic config %p", got, syn)
	}
	if d.cfg != nil {
		t.Error("the snapshot must not become d.cfg (configured stays false)")
	}

	applied := blockTestConfig(t, baseYAML(baseTunnels()...))
	d.cfg = applied
	if got := d.effectiveCfg(); got != applied {
		t.Errorf("effectiveCfg with a config = %p, want the applied one %p", got, applied)
	}
}

// design 9.1, 10.2: with a snapshot and no config status.get says "no
// config" (configured false), and tunnel.* stay code 2: the synthetic
// config is not an applied one.
func TestDaemonBlockSnapshotIsNotAConfig(t *testing.T) {
	d := testDaemon(t, t.TempDir()+"/state.json", state.State{})
	d.mu.Lock()
	d.blockCfg, _ = blockConfig(&state.Block{CIDRs: []string{"198.51.100.0/24"}, Domains: []string{"tg.example"}})
	d.mu.Unlock()
	if st := d.State(); st.Cfg != nil {
		t.Errorf("State().Cfg = %+v, want nil (not configured)", st.Cfg)
	}
	_, err := d.Enable("de")
	wantCode(t, "Enable", err, 2)
	wantCode(t, "DisableAll", d.DisableAll(), 2)
}
