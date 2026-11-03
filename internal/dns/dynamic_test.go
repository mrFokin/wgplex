package dns

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

// Tests follow design 7.2 (one address of several rules), 7.4, 8 (deadline
// per name–address pair: TTL + 1 h, extended by every answer; a shared
// address lives until the latest deadline; at most 4096 pairs, the earliest
// evicted; the rule found by name at every recalculation), not the
// implementation.

var dynT0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// dynCfg: rule 0 youtube.com via nl; rule 1 =www.example.org in fallback
// default when dynRules(true); rule 2 example.org via fi; rule 3
// music.youtube.com via de.
func dynCfg() *config.Config {
	return &config.Config{
		IPv6Filter: true,
		Tunnels: []config.Tunnel{
			tunnelCfg("nl", []string{"10.0.0.2/32", "fd00::2/128"}, nil),
			tunnelCfg("de", []string{"10.1.0.2/32"}, nil),
			tunnelCfg("fi", []string{"10.2.0.2/32"}, nil),
			tunnelCfg("home", []string{"10.3.0.2/32"}, nil),
		},
		Services: map[string]config.Service{
			"yt":    {Domains: domainList("youtube.com")},
			"def":   {Domains: domainList("=www.example.org")},
			"org":   {Domains: domainList("example.org")},
			"music": {Domains: domainList("music.youtube.com")},
		},
		Rules: []config.Rule{
			{Services: []string{"yt"}, Via: []string{"nl"}, Fallback: config.FallbackDefault},
			{Services: []string{"def"}, Via: []string{"home"}, Fallback: config.FallbackDefault},
			{Services: []string{"org"}, Via: []string{"fi"}, Fallback: config.FallbackDefault},
			{Services: []string{"music"}, Via: []string{"de"}, Fallback: config.FallbackDefault},
		},
	}
}

// dynRules: home up (rule 1 on home) or down (rule 1 in fallback).
func dynRules(homeDown bool) []router.RuleState {
	r1 := router.RuleState{Tunnel: "home"}
	if homeDown {
		r1 = router.RuleState{Fallback: true}
	}
	return []router.RuleState{{Tunnel: "nl"}, r1, {Tunnel: "fi"}, {Tunnel: "de"}}
}

func dynAdd(t *testing.T, d *Dynamics, name string, addrs []netip.Addr, ttl time.Duration, now time.Time) (added bool, evicted int) {
	t.Helper()
	noPanic(t, "Add", func() { added, evicted = d.Add(name, addrs, ttl, now) })
	return
}

func dynExpire(t *testing.T, d *Dynamics, now time.Time) (removed bool) {
	t.Helper()
	noPanic(t, "Expire", func() { removed = d.Expire(now) })
	return
}

func dynList(t *testing.T, d *Dynamics, cfg *config.Config, rules []router.RuleState) []router.Dynamic {
	t.Helper()
	var out []router.Dynamic
	noPanic(t, "List", func() { out = d.List(cfg, rules) })
	return out
}

func dynamicOf(addr string, rule int) router.Dynamic {
	return router.Dynamic{Addr: netip.MustParseAddr(addr), Rule: rule}
}

func sameDyn(t *testing.T, what string, got, want []router.Dynamic) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// --- Add ---------------------------------------------------------------------

func TestDynamicsConsts(t *testing.T) {
	if dynamicKeep != time.Hour {
		t.Errorf("dynamicKeep = %v, want 1h (design 8)", dynamicKeep)
	}
	if dynamicLimit != 4096 {
		t.Errorf("dynamicLimit = %d, want 4096 (design 8)", dynamicLimit)
	}
}

// design 8 "Домены из правил": added reports a (name, address) pair that was
// not there; the name is normalized like in MatchDomain (6.4).
func TestDynamicsAdd(t *testing.T) {
	var d Dynamics // the zero value is ready
	a1, a2 := parseAddrs("192.0.2.1"), parseAddrs("192.0.2.1", "192.0.2.2")
	steps := []struct {
		why   string
		name  string
		addrs []netip.Addr
		added bool
	}{
		{"new pair", "www.youtube.com", a1, true},
		{"same pair again", "www.youtube.com", a1, false},
		{"same pair, other case and a trailing dot", "WWW.YouTube.COM.", a1, false},
		{"one new address among known ones", "www.youtube.com", a2, true},
		{"the same addresses again", "www.youtube.com", a2, false},
		{"known address for a new name", "m.youtube.com", a1, true},
		{"IPv6 address", "m.youtube.com", parseAddrs("2001:db8::1"), true},
		{"no addresses", "x.youtube.com", nil, false},
	}
	for _, s := range steps {
		added, evicted := dynAdd(t, &d, s.name, s.addrs, time.Minute, dynT0)
		if added != s.added || evicted != 0 {
			t.Errorf("%s: Add(%q, %v) = %v, %d; want %v, 0", s.why, s.name, s.addrs, added, evicted, s.added)
		}
	}
}

// --- deadlines and Expire ----------------------------------------------------

// design 8: deadline = max(old, now + TTL + 1 h); Expire drops
// pairs with deadline <= now.
func TestDynamicsDeadline(t *testing.T) {
	cfg, rules := dynCfg(), dynRules(false)
	addr := parseAddrs("192.0.2.1")
	ttl := 5 * time.Minute
	deadline := dynT0.Add(ttl + time.Hour)

	t.Run("expires exactly at now+TTL+1h", func(t *testing.T) {
		var d Dynamics
		dynAdd(t, &d, "www.youtube.com", addr, ttl, dynT0)
		if dynExpire(t, &d, deadline.Add(-time.Nanosecond)) {
			t.Error("Expire before the deadline removed something")
		}
		sameDyn(t, "List before the deadline", dynList(t, &d, cfg, rules), []router.Dynamic{dynamicOf("192.0.2.1", 0)})
		if !dynExpire(t, &d, deadline) {
			t.Error("Expire at the deadline removed nothing")
		}
		sameDyn(t, "List after the deadline", dynList(t, &d, cfg, rules), nil)
		if dynExpire(t, &d, deadline.Add(time.Hour)) {
			t.Error("second Expire removed something")
		}
	})

	t.Run("a later answer extends the deadline", func(t *testing.T) {
		var d Dynamics
		dynAdd(t, &d, "www.youtube.com", addr, ttl, dynT0)
		later := dynT0.Add(30 * time.Minute)
		if added, _ := dynAdd(t, &d, "www.youtube.com", addr, ttl, later); added {
			t.Error("extension reported as a new pair")
		}
		if dynExpire(t, &d, deadline) {
			t.Error("removed at the old deadline after an extension")
		}
		if !dynExpire(t, &d, later.Add(ttl+time.Hour)) {
			t.Error("not removed at the extended deadline")
		}
	})

	t.Run("a shorter answer does not shorten the deadline", func(t *testing.T) {
		var d Dynamics
		dynAdd(t, &d, "www.youtube.com", addr, ttl, dynT0)
		dynAdd(t, &d, "www.youtube.com", addr, 0, dynT0.Add(time.Second))
		if dynExpire(t, &d, dynT0.Add(time.Second+time.Hour)) {
			t.Error("deadline shortened by an answer with a lower TTL")
		}
		if !dynExpire(t, &d, deadline) {
			t.Error("not removed at the original deadline")
		}
	})

	t.Run("an answer with an earlier now does not shorten the deadline", func(t *testing.T) {
		var d Dynamics
		dynAdd(t, &d, "www.youtube.com", addr, ttl, dynT0)
		dynAdd(t, &d, "www.youtube.com", addr, ttl, dynT0.Add(-time.Minute))
		if dynExpire(t, &d, deadline.Add(-time.Nanosecond)) {
			t.Error("deadline shortened")
		}
	})

	t.Run("pairs of one name expire separately", func(t *testing.T) {
		var d Dynamics
		dynAdd(t, &d, "www.youtube.com", parseAddrs("192.0.2.1"), time.Minute, dynT0)
		dynAdd(t, &d, "www.youtube.com", parseAddrs("192.0.2.2"), 10*time.Minute, dynT0)
		if !dynExpire(t, &d, dynT0.Add(time.Minute+time.Hour)) {
			t.Error("first pair not removed")
		}
		sameDyn(t, "List", dynList(t, &d, cfg, rules), []router.Dynamic{dynamicOf("192.0.2.2", 0)})
	})

	t.Run("Expire on the zero value", func(t *testing.T) {
		var d Dynamics
		if dynExpire(t, &d, dynT0) {
			t.Error("Expire on an empty Dynamics removed something")
		}
	})
}

// design 8: an address shared by several names lives until the
// latest of their deadlines.
func TestDynamicsSharedAddr(t *testing.T) {
	cfg, rules := dynCfg(), dynRules(false)
	var d Dynamics
	dynAdd(t, &d, "a.youtube.com", parseAddrs("192.0.2.1"), time.Minute, dynT0)
	dynAdd(t, &d, "b.youtube.com", parseAddrs("192.0.2.1"), 10*time.Minute, dynT0)
	sameDyn(t, "List", dynList(t, &d, cfg, rules), []router.Dynamic{dynamicOf("192.0.2.1", 0)})

	first := dynT0.Add(time.Minute + time.Hour)
	dynExpire(t, &d, first)
	sameDyn(t, "List after the first deadline", dynList(t, &d, cfg, rules), []router.Dynamic{dynamicOf("192.0.2.1", 0)})

	if !dynExpire(t, &d, dynT0.Add(10*time.Minute+time.Hour)) {
		t.Error("the last pair not removed at its deadline")
	}
	sameDyn(t, "List after the last deadline", dynList(t, &d, cfg, rules), nil)
}

// --- the limit ---------------------------------------------------------------

// design 8: at most dynamicLimit pairs; a new pair over the limit
// evicts the pair with the earliest deadline.
func TestDynamicsLimit(t *testing.T) {
	cfg, rules := dynCfg(), dynRules(false)
	var d Dynamics
	addr := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	// Deadlines grow with i, except pair 7 which has the earliest one.
	for i := 0; i < dynamicLimit; i++ {
		now := dynT0.Add(time.Duration(i) * time.Second)
		if i == 7 {
			now = dynT0.Add(-time.Hour)
		}
		added, evicted := dynAdd(t, &d, fmt.Sprintf("n%d.youtube.com", i), []netip.Addr{addr(i)}, time.Minute, now)
		if !added || evicted != 0 {
			t.Fatalf("pair %d: Add = %v, %d; want true, 0", i, added, evicted)
		}
	}
	if got := len(dynList(t, &d, cfg, rules)); got != dynamicLimit {
		t.Fatalf("List has %d entries, want %d", got, dynamicLimit)
	}

	// A known pair at the limit: nothing evicted.
	if added, evicted := dynAdd(t, &d, "n100.youtube.com", []netip.Addr{addr(100)}, time.Minute, dynT0.Add(time.Hour)); added || evicted != 0 {
		t.Errorf("known pair at the limit: Add = %v, %d; want false, 0", added, evicted)
	}

	// A new pair: the earliest (7) goes.
	next := dynT0.Add(2 * time.Hour)
	added, evicted := dynAdd(t, &d, "new.youtube.com", parseAddrs("192.0.2.1"), time.Minute, next)
	if !added || evicted != 1 {
		t.Errorf("over the limit: Add = %v, %d; want true, 1", added, evicted)
	}
	list := dynList(t, &d, cfg, rules)
	if len(list) != dynamicLimit {
		t.Errorf("List has %d entries, want %d", len(list), dynamicLimit)
	}
	has := func(a netip.Addr) bool {
		return slices.ContainsFunc(list, func(x router.Dynamic) bool { return x.Addr == a })
	}
	if has(addr(7)) {
		t.Error("the pair with the earliest deadline was not evicted")
	}
	if !has(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the new pair is missing")
	}
	if !has(addr(0)) || !has(addr(8)) {
		t.Error("a pair other than the earliest was evicted")
	}

	// Two new pairs in one Add: the next two earliest (0, 1) go.
	added, evicted = dynAdd(t, &d, "two.youtube.com", parseAddrs("192.0.2.2", "192.0.2.3"), time.Minute, next)
	if !added || evicted != 2 {
		t.Errorf("two over the limit: Add = %v, %d; want true, 2", added, evicted)
	}
	list = dynList(t, &d, cfg, rules)
	if len(list) != dynamicLimit {
		t.Errorf("List has %d entries, want %d", len(list), dynamicLimit)
	}
	if has(addr(0)) || has(addr(1)) {
		t.Error("pairs 0 and 1 (the earliest) were not evicted")
	}
	if !has(addr(2)) {
		t.Error("pair 2 evicted, it is not among the earliest")
	}
}

// --- List --------------------------------------------------------------------

// design 7.2 (shared address: one entry per rule), 7.4, 8 (the rule by name
// at every recalculation): sorted by address then rule, one entry
// per (address, rule), names without a rule left out.
func TestDynamicsList(t *testing.T) {
	cfg := dynCfg()
	var d Dynamics
	add := func(name string, addrs ...string) { dynAdd(t, &d, name, parseAddrs(addrs...), time.Minute, dynT0) }
	add("www.youtube.com", "192.0.2.20", "2001:db8::1")
	add("m.youtube.com", "192.0.2.20")       // the same (addr, rule): one entry
	add("x.music.youtube.com", "192.0.2.20") // the same addr for rule 3: a second entry
	add("www.example.org", "192.0.2.5")      // rule 1, or rule 2 when home is down
	add("mail.example.org", "192.0.2.6")     // rule 2
	add("unrelated.test", "192.0.2.7")       // no rule: left out
	add("WWW.YouTube.COM.", "192.0.2.4")     // normalized: rule 0
	add("music.youtube.com", "2001:db8::1", "10.9.9.9")

	t.Run("home up", func(t *testing.T) {
		sameDyn(t, "List", dynList(t, &d, cfg, dynRules(false)), []router.Dynamic{
			dynamicOf("10.9.9.9", 3),
			dynamicOf("192.0.2.4", 0),
			dynamicOf("192.0.2.5", 1),
			dynamicOf("192.0.2.6", 2),
			dynamicOf("192.0.2.20", 0),
			dynamicOf("192.0.2.20", 3),
			dynamicOf("2001:db8::1", 0),
			dynamicOf("2001:db8::1", 3),
		})
	})
	// Rule 1 in fallback: default — its name goes to rule 2.
	t.Run("home down: the name moves to the lower rule", func(t *testing.T) {
		sameDyn(t, "List", dynList(t, &d, cfg, dynRules(true)), []router.Dynamic{
			dynamicOf("10.9.9.9", 3),
			dynamicOf("192.0.2.4", 0),
			dynamicOf("192.0.2.5", 2),
			dynamicOf("192.0.2.6", 2),
			dynamicOf("192.0.2.20", 0),
			dynamicOf("192.0.2.20", 3),
			dynamicOf("2001:db8::1", 0),
			dynamicOf("2001:db8::1", 3),
		})
	})
	// And back: nothing to clean up, the name returns to rule 1.
	t.Run("home up again", func(t *testing.T) {
		got := dynList(t, &d, cfg, dynRules(false))
		if !slices.Contains(got, dynamicOf("192.0.2.5", 1)) || slices.Contains(got, dynamicOf("192.0.2.5", 2)) {
			t.Errorf("List = %v, want 192.0.2.5 on rule 1 only", got)
		}
	})
	// A config without the rule (config.apply): the name has no rule, its
	// address is left out; the pair itself is not dropped (design 8).
	t.Run("config without the youtube rule", func(t *testing.T) {
		cfg2 := dynCfg()
		cfg2.Rules = cfg2.Rules[1:3] // def, org
		got := dynList(t, &d, cfg2, []router.RuleState{{Tunnel: "home"}, {Tunnel: "fi"}})
		sameDyn(t, "List", got, []router.Dynamic{
			dynamicOf("192.0.2.5", 0),
			dynamicOf("192.0.2.6", 1),
		})
		// The old config again: the addresses are back.
		if got := dynList(t, &d, cfg, dynRules(false)); !slices.Contains(got, dynamicOf("192.0.2.4", 0)) {
			t.Errorf("List with the old config = %v, want 192.0.2.4 on rule 0", got)
		}
	})
	t.Run("zero value", func(t *testing.T) {
		var empty Dynamics
		sameDyn(t, "List", dynList(t, &empty, cfg, dynRules(false)), nil)
	})
}
