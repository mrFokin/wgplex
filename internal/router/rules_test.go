package router

import (
	"fmt"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests in this file follow docs/design.md sections 7.3 and 9 and the Wirefork M2 plan
// (docs/plans/m2-router.md, "Алгоритм", "Решения"), not the implementation.

// tSelect calls SelectRules and turns a panic (not implemented yet) into a test failure.
func tSelect(t *testing.T, cfg *config.Config, tunnels map[string]TunnelState, prev []RuleState) []RuleState {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SelectRules panicked: %v", r)
		}
	}()
	return SelectRules(cfg, tunnels, prev)
}

// tRuleCfg is a config with tunnels nl, de, fi (routes: rules) and one rule per via list.
func tRuleCfg(fallback config.Fallback, vias ...[]string) *config.Config {
	cfg := &config.Config{
		Tunnels: []config.Tunnel{
			{Name: "nl", Routes: config.RoutesRules},
			{Name: "de", Routes: config.RoutesRules},
			{Name: "fi", Routes: config.RoutesRules},
		},
		Services: map[string]config.Service{
			"svc": {Domains: []config.Domain{{Name: "example.com"}}},
		},
	}
	for _, via := range vias {
		cfg.Rules = append(cfg.Rules, config.Rule{Services: []string{"svc"}, Via: via, Fallback: fallback})
	}
	return cfg
}

var (
	tUp   = TunnelState{Up: true, Alive: true}
	tDead = TunnelState{Up: true, Alive: false}
	tOff  = TunnelState{Up: false, Alive: true} // Alive is ignored when !Up (design 9, router.go)
)

func tOn(name string) RuleState { return RuleState{Tunnel: name} }

var tFallback = RuleState{Fallback: true}

func tFmtRules(rs []RuleState) string {
	if rs == nil {
		return "nil"
	}
	return fmt.Sprintf("%+v", rs)
}

// design 7.3, 9: the first tunnel from via that is enabled (Up) and alive is used.
func TestSelectRulesSingleRule(t *testing.T) {
	cases := []struct {
		name     string
		via      []string
		fallback config.Fallback
		tunnels  map[string]TunnelState
		prev     []RuleState
		want     RuleState
	}{
		// design 7.3: via is ordered; the first usable one wins.
		{name: "first in via usable", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp}, want: tOn("nl")},
		{name: "via order, not config order", via: []string{"de", "nl"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp}, want: tOn("de")},
		{name: "third tunnel when first two unusable", via: []string{"nl", "de", "fi"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tOff, "fi": tUp}, want: tOn("fi")},

		// design 7.3: a tunnel disabled by the user does not exist for rules.
		{name: "disabled: missing from map", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"de": tUp}, want: tOn("de")},
		{name: "disabled: Up=false even if Alive", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tOff, "de": tUp}, want: tOn("de")},
		{name: "nil tunnels map: all down", via: []string{"nl"},
			tunnels: nil, want: tFallback},

		// design 9: a dead tunnel is excluded from via.
		{name: "dead first tunnel skipped", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp}, want: tOn("de")},

		// design 7.3: no usable tunnel → fallback, independent of default/block.
		{name: "all dead, fallback default", via: []string{"nl", "de"}, fallback: config.FallbackDefault,
			tunnels: map[string]TunnelState{"nl": tDead, "de": tDead}, want: tFallback},
		{name: "all dead, fallback block", via: []string{"nl", "de"}, fallback: config.FallbackBlock,
			tunnels: map[string]TunnelState{"nl": tDead, "de": tDead}, want: tFallback},
		{name: "all disabled", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tOff}, want: tFallback},
		{name: "mixed dead and disabled", via: []string{"nl", "de", "fi"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tOff}, want: tFallback},

		// design 7.3: empty via is always direct — never fallback.
		{name: "empty via", via: nil,
			tunnels: map[string]TunnelState{"nl": tUp}, want: RuleState{}},
		{name: "empty via, everything dead", via: []string{},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tDead}, want: RuleState{}},
		{name: "empty via ignores prev", via: nil,
			tunnels: map[string]TunnelState{"nl": tUp}, prev: []RuleState{tOn("nl")}, want: RuleState{}},

		// design 7.3: no return to a higher-priority tunnel.
		{name: "no return: stays on de while nl is alive again", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp}, prev: []RuleState{tOn("de")}, want: tOn("de")},
		{name: "prev on de, de dies: back to nl", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tDead}, prev: []RuleState{tOn("de")}, want: tOn("nl")},
		{name: "prev on de, de disabled: back to nl", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tOff}, prev: []RuleState{tOn("de")}, want: tOn("nl")},
		{name: "prev on de, de missing from map: back to nl", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp}, prev: []RuleState{tOn("de")}, want: tOn("nl")},
		{name: "prev on fi, fi dies: first usable in via order", via: []string{"nl", "de", "fi"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp, "fi": tDead}, prev: []RuleState{tOn("fi")}, want: tOn("de")},
		{name: "prev on de, everything dead: fallback", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tDead}, prev: []RuleState{tOn("de")}, want: tFallback},
		{name: "prev in fallback, nl revives: nl", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tDead}, prev: []RuleState{tFallback}, want: tOn("nl")},
		{name: "prev in fallback, de revives: de", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp}, prev: []RuleState{tFallback}, want: tOn("de")},
		// The prev tunnel is usable but no longer in via: it must not be kept.
		{name: "prev tunnel not in via anymore", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp, "fi": tUp}, prev: []RuleState{tOn("fi")}, want: tOn("nl")},
		{name: "prev tunnel unknown", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp}, prev: []RuleState{tOn("ghost")}, want: tOn("de")},

		// Decision 5: after a config load prev is nil, selection starts over.
		{name: "prev nil: first usable", via: []string{"nl", "de"},
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp}, prev: nil, want: tOn("nl")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fb := c.fallback
			if fb == "" {
				fb = config.FallbackDefault
			}
			cfg := tRuleCfg(fb, c.via)
			got := tSelect(t, cfg, c.tunnels, c.prev)
			if len(got) != 1 {
				t.Fatalf("SelectRules returned %d states, want 1: %s", len(got), tFmtRules(got))
			}
			if got[0] != c.want {
				t.Errorf("SelectRules = %+v, want %+v", got[0], c.want)
			}
		})
	}
}

// design 7.3: every rule gets its own decision; the result is indexed like cfg.Rules.
func TestSelectRulesSeveralRules(t *testing.T) {
	cfg := tRuleCfg(config.FallbackDefault,
		[]string{"nl", "de"}, // 0
		nil,                  // 1: direct
		[]string{"de", "nl"}, // 2
		[]string{"fi"},       // 3
		[]string{"nl", "de"}, // 4: was moved to de earlier
	)
	tunnels := map[string]TunnelState{"nl": tUp, "de": tUp, "fi": tDead}
	prev := []RuleState{tOn("nl"), {}, tOn("de"), tOn("fi"), tOn("de")}
	want := []RuleState{tOn("nl"), {}, tOn("de"), tFallback, tOn("de")}

	got := tSelect(t, cfg, tunnels, prev)
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (len(cfg.Rules)): %s", len(got), len(want), tFmtRules(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// The result always has len(cfg.Rules) entries, also with no prev or no rules.
func TestSelectRulesLength(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		prev []RuleState
	}{
		{name: "no rules", cfg: tRuleCfg(config.FallbackDefault)},
		{name: "three rules, prev nil", cfg: tRuleCfg(config.FallbackDefault, []string{"nl"}, nil, []string{"de"})},
		{name: "three rules, prev given", cfg: tRuleCfg(config.FallbackBlock, []string{"nl"}, nil, []string{"de"}),
			prev: []RuleState{tOn("nl"), {}, tFallback}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tSelect(t, c.cfg, map[string]TunnelState{"nl": tUp}, c.prev)
			if len(got) != len(c.cfg.Rules) {
				t.Errorf("len = %d, want %d", len(got), len(c.cfg.Rules))
			}
		})
	}
}

// design 7.3, 9 over time on the 10.1 example rules (via [nl, de]):
// all alive → nl; nl dies → de; nl revives → still de; de dies → nl.
func TestSelectRulesSequence(t *testing.T) {
	cfg := tRuleCfg(config.FallbackDefault, []string{"nl", "de"}, []string{"nl", "de"})
	steps := []struct {
		name    string
		tunnels map[string]TunnelState
		want    RuleState
	}{
		{"all alive", map[string]TunnelState{"nl": tUp, "de": tUp}, tOn("nl")},
		{"nl dead", map[string]TunnelState{"nl": tDead, "de": tUp}, tOn("de")},
		{"nl revived", map[string]TunnelState{"nl": tUp, "de": tUp}, tOn("de")},
		{"de dead", map[string]TunnelState{"nl": tUp, "de": tDead}, tOn("nl")},
		{"both dead", map[string]TunnelState{"nl": tDead, "de": tDead}, tFallback},
		{"de revived first", map[string]TunnelState{"nl": tDead, "de": tUp}, tOn("de")},
		{"nl revived again", map[string]TunnelState{"nl": tUp, "de": tUp}, tOn("de")},
	}
	var prev []RuleState
	for _, s := range steps {
		got := tSelect(t, cfg, s.tunnels, prev)
		if len(got) != 2 {
			t.Fatalf("%s: len = %d, want 2", s.name, len(got))
		}
		for i := range got {
			if got[i] != s.want {
				t.Errorf("%s: rule %d = %+v, want %+v", s.name, i, got[i], s.want)
			}
		}
		prev = got
	}
}
