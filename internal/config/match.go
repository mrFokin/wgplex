package config

import "strings"

// MatchDomain returns the index of the rule whose domain matches name best
// (design 7.4): exact > longer suffix > shorter suffix, ties by rule order.
// A suffix pattern matches the domain itself and all its subdomains. name is
// the queried name as is (no CNAME analysis); it is compared case-insensitively
// and a trailing dot is ignored. ok is false when no rule matches.
//
// A suffix matches only on a label boundary: youtube.com matches youtube.com
// and www.youtube.com, but not notyoutube.com.
func (c *Config) MatchDomain(name string) (rule int, ok bool) {
	return c.MatchDomainFunc(name, nil)
}

// MatchDomainFunc is MatchDomain over the rules i with use(i) true; nil use
// means every rule. The best match is chosen among those rules by the same
// order (design 7.4). The DNS resolver and Dynamics skip rules in
// fallback: default (Wirefork M5 decision 1).
func (c *Config) MatchDomainFunc(name string, use func(rule int) bool) (rule int, ok bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return 0, false
	}
	// An exact match ranks above every suffix; among suffixes the longer
	// pattern wins. Only a strictly better score replaces the current best,
	// so ties go to the earlier rule.
	const exactScore = 1 << 16 // longer than any domain name
	best := -1
	for i, r := range c.Rules {
		if use != nil && !use(i) {
			continue
		}
		for _, sname := range r.Services {
			for _, d := range c.Services[sname].Domains {
				score := -1
				switch {
				case d.Exact:
					if name == d.Name {
						score = exactScore
					}
				case name == d.Name || strings.HasSuffix(name, "."+d.Name):
					score = len(d.Name)
				}
				if score > best {
					best, rule, ok = score, i, true
				}
			}
		}
	}
	return rule, ok
}
