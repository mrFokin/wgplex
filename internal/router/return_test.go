package router

import (
	"reflect"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 7.3, 9 and 9.2 (return to a priority tunnel), not the
// implementation. TunnelState.Return: the tunnel may take rules back, i.e. its
// active check has been Alive long enough (decided by the daemon, health.Returnable).

var (
	rtnUpRet   = TunnelState{Up: true, Alive: true, Return: true}
	rtnDeadRet = TunnelState{Up: true, Alive: false, Return: true} // Return on an unusable tunnel changes nothing
	rtnOffRet  = TunnelState{Up: false, Alive: true, Return: true}
)

func TestSelectRulesReturn(t *testing.T) {
	via3 := []string{"nl", "de", "fi"}
	via2 := []string{"nl", "de"}

	tests := []struct {
		name    string
		cfg     *config.Config
		tunnels map[string]TunnelState
		prev    []RuleState
		want    []RuleState
	}{
		{
			name:    "design 9.2: returns to a higher tunnel with Return",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": rtnUpRet, "de": tUp},
			prev:    []RuleState{tOn("de")},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9.2: Alive without Return does not pull the rule back",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp},
			prev:    []RuleState{tOn("de")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2: first of several returnable tunnels wins",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": rtnUpRet, "de": rtnUpRet, "fi": tUp},
			prev:    []RuleState{tOn("fi")},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9.2: skips a higher tunnel without Return for the next returnable one",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": tUp, "de": rtnUpRet, "fi": tUp},
			prev:    []RuleState{tOn("fi")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2: Return on a dead tunnel is ignored",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": rtnDeadRet, "de": tUp},
			prev:    []RuleState{tOn("de")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2: Return on a disabled tunnel is ignored",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": rtnOffRet, "de": tUp},
			prev:    []RuleState{tOn("de")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2: Return on a lower tunnel does not move the rule down",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp, "fi": rtnUpRet},
			prev:    []RuleState{tOn("de")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2: the current tunnel with Return stays, nothing above it",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": rtnUpRet, "de": rtnUpRet},
			prev:    []RuleState{tOn("nl")},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9.2: a lower returnable tunnel does not pull a rule off the first one",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": tUp, "de": rtnUpRet},
			prev:    []RuleState{tOn("nl")},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9: current tunnel died, first usable wins even without Return",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp, "fi": tDead},
			prev:    []RuleState{tOn("fi")},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9.2: a rule in fallback takes any usable tunnel, Return not needed",
			cfg:     tRuleCfg(config.FallbackDefault, via2),
			tunnels: map[string]TunnelState{"nl": tUp, "de": tDead},
			prev:    []RuleState{tFallback},
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9: a rule in fallback block takes a revived tunnel",
			cfg:     tRuleCfg(config.FallbackBlock, via2),
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp},
			prev:    []RuleState{tFallback},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9: a rule in fallback with no usable tunnel stays in fallback",
			cfg:     tRuleCfg(config.FallbackBlock, via2),
			tunnels: map[string]TunnelState{"nl": tDead, "de": rtnDeadRet},
			prev:    []RuleState{tFallback},
			want:    []RuleState{tFallback},
		},
		{
			name:    "design 9.2/7.3: prev == nil selects from scratch, first usable even without Return",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": tUp, "de": tUp, "fi": tUp},
			prev:    nil,
			want:    []RuleState{tOn("nl")},
		},
		{
			name:    "design 9.2/7.3: prev == nil skips a dead first tunnel",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"nl": tDead, "de": tUp, "fi": tUp},
			prev:    nil,
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 9.2/7.3: prev == nil with nothing usable falls back",
			cfg:     tRuleCfg(config.FallbackBlock, via2),
			tunnels: map[string]TunnelState{"nl": tOff, "de": tDead},
			prev:    nil,
			want:    []RuleState{tFallback},
		},
		{
			name:    "design 9.2: a missing tunnel entry counts as down, Return elsewhere still applies",
			cfg:     tRuleCfg(config.FallbackDefault, via3),
			tunnels: map[string]TunnelState{"de": rtnUpRet, "fi": tUp},
			prev:    []RuleState{tOn("fi")},
			want:    []RuleState{tOn("de")},
		},
		{
			name:    "design 7.3: empty via stays direct, Return on tunnels changes nothing",
			cfg:     tRuleCfg(config.FallbackDefault, nil),
			tunnels: map[string]TunnelState{"nl": rtnUpRet, "de": rtnUpRet},
			prev:    []RuleState{{Tunnel: ""}},
			want:    []RuleState{{Tunnel: ""}},
		},
		{
			name:    "design 7.3: empty via with prev == nil is direct",
			cfg:     tRuleCfg(config.FallbackBlock, nil),
			tunnels: map[string]TunnelState{"nl": rtnUpRet},
			prev:    nil,
			want:    []RuleState{{Tunnel: ""}},
		},
		{
			name:    "design 9.2: rules are independent",
			cfg:     tRuleCfg(config.FallbackDefault, via2, []string{"de", "nl"}, nil, via3),
			tunnels: map[string]TunnelState{"nl": rtnUpRet, "de": tUp, "fi": tUp},
			prev:    []RuleState{tOn("de"), tOn("de"), {Tunnel: ""}, tOn("fi")},
			want:    []RuleState{tOn("nl"), tOn("de"), {Tunnel: ""}, tOn("nl")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tSelect(t, tc.cfg, tc.tunnels, tc.prev)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SelectRules = %+v, want %+v", got, tc.want)
			}
		})
	}
}
