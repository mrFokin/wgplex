package main

import (
	"slices"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests of the return to a higher-priority tunnel in the daemon (design 9.2):
// which rules tunnel.enable selects again and which moves are logged as
// returns. Pure logic, no system calls.

func returnCfg() *config.Config {
	return &config.Config{Rules: []config.Rule{
		{Services: []string{"a"}, Via: []string{"t1", "t2", "t3"}},
		{Services: []string{"b"}, Via: []string{"t2", "t1"}},
		{Services: []string{"c"}},
		{Services: []string{"d"}, Via: []string{"t1", "t3"}},
		{Services: []string{"e"}, Via: []string{"t3"}},
	}}
}

func TestReturnTo(t *testing.T) {
	cfg := returnCfg()
	prev := []router.RuleState{
		{Tunnel: "t2"},   // t1 before t2: from scratch
		{Tunnel: "t2"},   // t1 after t2: kept
		{},               // direct
		{Fallback: true}, // fallback: SelectRules picks the first usable anyway
		{Tunnel: "t3"},   // t1 not in via: kept
	}
	got := returnTo(cfg, prev, "t1")
	want := []router.RuleState{{}, {Tunnel: "t2"}, {}, {Fallback: true}, {Tunnel: "t3"}}
	if !slices.Equal(got, want) {
		t.Fatalf("returnTo = %v, want %v", got, want)
	}
	if prev[0].Tunnel != "t2" {
		t.Fatalf("returnTo changed prev: %v", prev)
	}

	// SelectRules on it: rule 0 goes to t1 (up, not Returnable), rule 1
	// stays on t2, rule 3 leaves fallback for t1.
	st := map[string]router.TunnelState{
		"t1": {Up: true, Alive: true},
		"t2": {Up: true, Alive: true},
		"t3": {Up: true, Alive: true},
	}
	rules := router.SelectRules(cfg, st, got)
	wantRules := []router.RuleState{{Tunnel: "t1"}, {Tunnel: "t2"}, {}, {Tunnel: "t1"}, {Tunnel: "t3"}}
	if !slices.Equal(rules, wantRules) {
		t.Fatalf("SelectRules = %v, want %v", rules, wantRules)
	}
}

func TestReturnToOtherRulesKept(t *testing.T) {
	// Enabling t3 does not return rule 0 from t2 to t1, even though t1 is
	// usable: only the rules t3 stands higher for are selected again.
	cfg := returnCfg()
	prev := []router.RuleState{{Tunnel: "t2"}, {Tunnel: "t2"}, {}, {Tunnel: "t1"}, {Tunnel: "t3"}}
	if got := returnTo(cfg, prev, "t3"); !slices.Equal(got, prev) {
		t.Fatalf("returnTo = %v, want %v", got, prev)
	}
}

func TestReturnedRules(t *testing.T) {
	cfg := returnCfg()
	before := []router.RuleState{{Tunnel: "t3"}, {Tunnel: "t1"}, {}, {Fallback: true}, {Tunnel: "t3"}}
	after := []router.RuleState{{Tunnel: "t2"}, {Tunnel: "t2"}, {}, {Tunnel: "t1"}, {Fallback: true}}
	up := map[string]router.TunnelState{"t1": {Up: true, Alive: true}, "t2": {Up: true, Alive: true}, "t3": {Up: true, Alive: true}}
	got := returnedRules(cfg, before, after, up)
	want := []ruleReturn{{index: 0, from: "t3", to: "t2"}, {index: 1, from: "t1", to: "t2"}}
	if !slices.Equal(got, want) {
		t.Fatalf("returnedRules = %v, want %v", got, want)
	}
}

func TestReturnedRulesFailover(t *testing.T) {
	// A move down the via (failover) and a shorter before are not returns.
	cfg := returnCfg()
	before := []router.RuleState{{Tunnel: "t1"}}
	after := []router.RuleState{{Tunnel: "t2"}, {Tunnel: "t1"}, {}, {Tunnel: "t1"}, {Tunnel: "t3"}}
	if got := returnedRules(cfg, before, after, nil); len(got) != 0 {
		t.Fatalf("returnedRules = %v, want none", got)
	}
}

func TestReturnedRulesDeadSource(t *testing.T) {
	// The tunnel the rule left died: a failover to a higher tunnel that was
	// not Returnable yet, not a return.
	cfg := returnCfg()
	before := []router.RuleState{{Tunnel: "t3"}}
	after := []router.RuleState{{Tunnel: "t2"}}
	st := map[string]router.TunnelState{"t2": {Up: true, Alive: true}, "t3": {Up: true}}
	if got := returnedRules(cfg, before, after, st); len(got) != 0 {
		t.Fatalf("returnedRules = %v, want none", got)
	}
}
