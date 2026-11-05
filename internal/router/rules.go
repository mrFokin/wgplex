package router

import (
	"slices"

	"github.com/mrFokin/wgplex/internal/config"
)

// SelectRules picks a tunnel for every rule (design 7.3, 9): the first tunnel
// from via that is Up and Alive; a rule keeps its previous tunnel while that
// tunnel stays usable, except that it returns to a higher-priority tunnel whose
// Return is set (design 9.2). tunnels is keyed by tunnel name, a missing entry
// means down. prev is the previous result for the same cfg, nil after a config
// is applied (selection starts over).
//
// For each rule, in order of checks:
//   - empty via: {Tunnel: ""} (always direct);
//   - the tunnel from prev is still in via and usable: if some tunnel before it
//     in via is usable and has Return, the first such tunnel; otherwise kept;
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
		if i < len(prev) && prev[i].Tunnel != "" && usable(prev[i].Tunnel) {
			if k := slices.Index(r.Via, prev[i].Tunnel); k >= 0 {
				res[i] = RuleState{Tunnel: prev[i].Tunnel}
				for _, v := range r.Via[:k] {
					if usable(v) && tunnels[v].Return {
						res[i] = RuleState{Tunnel: v}
						break
					}
				}
				continue
			}
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
