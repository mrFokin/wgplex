package router

import (
	"slices"

	"github.com/mrFokin/wgplex/internal/config"
)

// SelectRules picks a tunnel for every rule (design 6.3, 8): the first tunnel
// from via that is Up and Alive; a rule keeps its previous tunnel while that
// tunnel stays usable (no return to a higher-priority one). tunnels is keyed by
// tunnel name, a missing entry means down. prev is the previous result for the
// same cfg, nil after a config is applied (selection starts over).
//
// For each rule, in order of checks:
//   - empty via: {Tunnel: ""} (always direct);
//   - the tunnel from prev is still in via and usable: kept;
//   - otherwise the first usable tunnel from via;
//   - otherwise {Fallback: true}.
//
// The result has len(cfg.Rules) entries, index = index in cfg.Rules.
// Alive is taken as is; it does not matter when Up is false.
func SelectRules(cfg *config.Config, tunnels map[string]TunnelState, prev []RuleState) []RuleState {
	usable := func(name string) bool {
		t, ok := tunnels[name]
		return ok && t.Up && t.Alive
	}
	res := make([]RuleState, len(cfg.Rules))
	for i, r := range cfg.Rules {
		if len(r.Via) == 0 {
			continue // always direct
		}
		if i < len(prev) && prev[i].Tunnel != "" && slices.Contains(r.Via, prev[i].Tunnel) && usable(prev[i].Tunnel) {
			res[i] = RuleState{Tunnel: prev[i].Tunnel}
			continue
		}
		res[i] = RuleState{Fallback: true}
		for _, v := range r.Via {
			if usable(v) {
				res[i] = RuleState{Tunnel: v}
				break
			}
		}
	}
	return res
}
