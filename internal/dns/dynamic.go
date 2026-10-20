package dns

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
	"github.com/mrFokin/wgplex/internal/router"
)

const (
	dynamicKeep  = time.Hour // kept past the TTL: open connections (M5 decision 4)
	dynamicLimit = 4096      // (name, addr) pairs; the earliest deadline is evicted
)

// Dynamics holds the addresses from DNS answers for rule domains with their
// deadlines, per (query name, address). An address shared by several names
// lives until the latest of their deadlines. The rule is not stored: List
// finds it by name at call time, so config changes and fallback transitions
// need no cleanup. Not safe for concurrent use: Server guards it. The zero
// value is ready to use.
type Dynamics struct {
	deadline map[nameAddr]time.Time // nil until the first Add
}

// nameAddr is one pair of Dynamics: the normalized query name and an address.
type nameAddr struct {
	name string
	addr netip.Addr
}

// Add records addrs answered for name: deadline max(old, now+ttl+dynamicKeep).
// name is normalized like in MatchDomain. added: a pair that was not there;
// evicted: pairs dropped by dynamicLimit.
//
// Eviction never drops a pair of this call while other pairs remain: the new
// address must reach the table before the answer.
func (d *Dynamics) Add(name string, addrs []netip.Addr, ttl time.Duration, now time.Time) (added bool, evicted int) {
	if len(addrs) == 0 {
		return false, 0
	}
	if d.deadline == nil {
		d.deadline = map[nameAddr]time.Time{}
	}
	name = normalize(name)
	until := now.Add(ttl + dynamicKeep)
	mine := make(map[nameAddr]bool, len(addrs))
	for _, a := range addrs {
		k := nameAddr{name: name, addr: a.WithZone("")}
		mine[k] = true
		old, ok := d.deadline[k]
		if !ok {
			added = true
		}
		if !ok || until.After(old) {
			d.deadline[k] = until
		}
	}
	for len(d.deadline) > dynamicLimit {
		d.evict(mine)
		evicted++
	}
	return added, evicted
}

// Pair is a dynamic address recorded for a name, for diagnostics.
type Pair struct {
	Name     string // normalized
	Addr     netip.Addr
	Deadline time.Time
}

// Pairs returns all pairs sorted by name, then address.
func (d *Dynamics) Pairs() []Pair {
	res := make([]Pair, 0, len(d.deadline))
	for k, t := range d.deadline {
		res = append(res, Pair{Name: k.name, Addr: k.addr, Deadline: t})
	}
	slices.SortFunc(res, func(a, b Pair) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return a.Addr.Compare(b.Addr)
	})
	return res
}

// evict drops the pair with the earliest deadline, preferring pairs not in
// keep; ties go to the smaller pair, so the result does not depend on map
// order.
func (d *Dynamics) evict(keep map[nameAddr]bool) {
	var (
		victim nameAddr
		when   time.Time
		found  bool
		kept   bool // victim is in keep
	)
	for k, t := range d.deadline {
		kKept := keep[k]
		better := !found ||
			(kept && !kKept) ||
			(kept == kKept && (t.Before(when) || t.Equal(when) && lessPair(k, victim)))
		if better {
			victim, when, found, kept = k, t, true, kKept
		}
	}
	delete(d.deadline, victim)
}

// lessPair orders pairs by name, then address.
func lessPair(a, b nameAddr) bool {
	if a.name != b.name {
		return a.name < b.name
	}
	return a.addr.Less(b.addr)
}

// normalize lowercases name and drops a trailing dot, as MatchDomain does.
func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// Expire drops pairs with deadline <= now; removed: something was dropped.
func (d *Dynamics) Expire(now time.Time) (removed bool) {
	for k, t := range d.deadline {
		if !t.After(now) {
			delete(d.deadline, k)
			removed = true
		}
	}
	return removed
}

// List returns the addresses for router.Build: rule = MatchDomainFunc(name,
// useRule) at call time; names without a rule are left out. Sorted by
// address, then rule; one entry per (addr, rule).
func (d *Dynamics) List(cfg *config.Config, rules []router.RuleState) []router.Dynamic {
	use := useRule(cfg, rules)
	type match struct {
		rule int
		ok   bool
	}
	byName := map[string]match{}
	seen := map[router.Dynamic]bool{}
	var res []router.Dynamic
	for k := range d.deadline {
		m, done := byName[k.name]
		if !done {
			m.rule, m.ok = cfg.MatchDomainFunc(k.name, use)
			byName[k.name] = m
		}
		if !m.ok {
			continue
		}
		dyn := router.Dynamic{Addr: k.addr, Rule: m.rule}
		if !seen[dyn] {
			seen[dyn] = true
			res = append(res, dyn)
		}
	}
	slices.SortFunc(res, func(a, b router.Dynamic) int {
		if c := a.Addr.Compare(b.Addr); c != 0 {
			return c
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
	return res
}
