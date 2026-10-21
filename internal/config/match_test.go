package config

import (
	"fmt"
	"testing"
)

// Tests follow docs/design.md 7.4 (domain matching), not the implementation.

// matchConfig is built as a literal so that matching is tested independently of Load.
// Rules are deliberately ordered so that precedence by specificity can't be
// confused with precedence by rule order.
func matchConfig() *Config {
	return &Config{
		Services: map[string]Service{
			"yt":      {Domains: []Domain{{Name: "youtube.com"}}},
			"g":       {Domains: []Domain{{Name: "google.com"}}},
			"gexact":  {Domains: []Domain{{Name: "google.com", Exact: true}}},
			"music":   {Domains: []Domain{{Name: "music.youtube.com"}}},
			"gem":     {Domains: []Domain{{Name: "gemini.google.com"}}},
			"dup1":    {Domains: []Domain{{Name: "example.org"}}},
			"dup2":    {Domains: []Domain{{Name: "example.org"}}},
			"ex1":     {Domains: []Domain{{Name: "exact.example", Exact: true}}},
			"ex2":     {Domains: []Domain{{Name: "exact.example", Exact: true}}},
			"multi":   {Domains: []Domain{{Name: "a.test"}, {Name: "b.test"}}},
			"cidr":    {CIDRs: pfxs("91.108.4.0/22")},
			"unused":  {Domains: []Domain{{Name: "unused.example"}}},
			"shorter": {Domains: []Domain{{Name: "deep.example"}}},
			"longer":  {Domains: []Domain{{Name: "x.y.deep.example"}}},
		},
		Rules: []Rule{
			0:  {Services: []string{"yt"}, Via: []string{"nl"}},
			1:  {Services: []string{"g"}, Via: []string{"nl"}},
			2:  {Services: []string{"gexact"}, Via: []string{"de"}}, // exact after its suffix
			3:  {Services: []string{"music"}},                       // longer suffix after shorter; empty via
			4:  {Services: []string{"gem"}, Via: []string{"de"}},
			5:  {Services: []string{"dup1"}, Via: []string{"nl"}},
			6:  {Services: []string{"dup2"}, Via: []string{"de"}},
			7:  {Services: []string{"ex1"}},
			8:  {Services: []string{"ex2"}},
			9:  {Services: []string{"cidr", "multi"}},
			10: {Services: []string{"longer"}}, // longer suffix before shorter
			11: {Services: []string{"shorter"}},
		},
	}
}

func TestMatchDomain(t *testing.T) {
	const none = -1
	cases := []struct {
		name string
		want int
		why  string
	}{
		// design 7.4: a suffix pattern matches the domain itself and every subdomain.
		{"youtube.com", 0, "suffix: the domain itself"},
		{"www.youtube.com", 0, "suffix: subdomain"},
		{"a.b.c.youtube.com", 0, "suffix: deep subdomain"},
		{"b.test", 9, "second domain of a multi-domain service"},
		{"x.a.test", 9, "suffix of a service that also has CIDRs"},

		// design 7.4: suffix matching respects label boundaries.
		{"notyoutube.com", none, "label boundary: notyoutube.com is not youtube.com"},
		{"youtube.com.evil.test", none, "pattern must be a suffix, not a prefix"},
		{"youtube.co", none, "different TLD"},
		{"tube.com", none, "shorter name"},
		{"com", none, "parent of the pattern"},
		{"notgemini.google.com", 1, "label boundary falls back to the shorter suffix"},

		// design 7.4: "=name" is an exact match only.
		{"exact.example", 7, "exact"},
		{"www.exact.example", none, "exact does not match subdomains"},

		// design 7.4: exact > longer suffix > shorter suffix, independent of rule order.
		{"google.com", 2, "exact beats suffix of the same name, though listed later"},
		{"www.google.com", 1, "exact does not apply to subdomains; suffix does"},
		{"music.youtube.com", 3, "longer suffix beats shorter, though listed later"},
		{"x.music.youtube.com", 3, "longer suffix for a subdomain"},
		{"gemini.google.com", 4, "longer suffix beats shorter suffix"},
		{"q.x.y.deep.example", 10, "longer suffix listed first still wins"},
		{"y.deep.example", 11, "only the shorter suffix matches"},

		// design 7.4: equal specificity — rule order decides.
		{"example.org", 5, "same suffix in two rules: first rule"},
		{"sub.example.org", 5, "same suffix in two rules, subdomain: first rule"},
		// ex1/ex2 both exact; rule 7 comes first (also covered above).

		// design 7.4: case-insensitive, trailing dot ignored.
		{"WWW.YouTube.com.", 0, "design example: WWW.YouTube.com. matches youtube.com"},
		{"YOUTUBE.COM", 0, "upper case"},
		{"GOOGLE.COM.", 2, "exact match, upper case with trailing dot"},
		{"Exact.Example.", 7, "exact match, mixed case with trailing dot"},
		{"Music.YouTube.Com", 3, "longer suffix, mixed case"},
		{"NotYouTube.com.", none, "label boundary after normalization"},

		// No match.
		{"unused.example", none, "service not referenced by any rule"},
		{"wikipedia.org", none, "unrelated domain"},
		{"", none, "empty name"},
		{".", none, "root only"},
	}
	cfg := matchConfig()
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q", c.name), func(t *testing.T) {
			got, ok := matchDomain(t, cfg, c.name)
			if c.want == none {
				if ok {
					t.Errorf("MatchDomain(%q) = %d, want no match (%s)", c.name, got, c.why)
				}
				return
			}
			if !ok || got != c.want {
				t.Errorf("MatchDomain(%q) = %d, %v; want %d (%s)", c.name, got, ok, c.want, c.why)
			}
		})
	}
}

// design 7.4: ties by rule order — the outcome flips when the rules are swapped.
func TestMatchDomainTieFollowsRuleOrder(t *testing.T) {
	cfg := &Config{
		Services: map[string]Service{
			"a": {Domains: []Domain{{Name: "same.example"}}},
			"b": {Domains: []Domain{{Name: "same.example"}}},
		},
		Rules: []Rule{{Services: []string{"b"}}, {Services: []string{"a"}}},
	}
	// winner returns the service of the matched rule, "" when nothing matched.
	winner := func(name string) string {
		t.Helper()
		got, ok := matchDomain(t, cfg, name)
		if !ok {
			return ""
		}
		if got < 0 || got >= len(cfg.Rules) {
			t.Fatalf("%s: rule index %d out of range", name, got)
		}
		return cfg.Rules[got].Services[0]
	}
	for _, name := range []string{"same.example", "x.same.example"} {
		if w := winner(name); w != "b" {
			t.Errorf("%s: winning rule is %q, want %q (listed first)", name, w, "b")
		}
	}
	cfg.Rules[0], cfg.Rules[1] = cfg.Rules[1], cfg.Rules[0]
	for _, name := range []string{"same.example", "x.same.example"} {
		if w := winner(name); w != "a" {
			t.Errorf("after swap, %s: winning rule is %q, want %q (listed first)", name, w, "a")
		}
	}
}

// design 7.4: a config without rules matches nothing.
func TestMatchDomainNoRules(t *testing.T) {
	cfg := &Config{Services: map[string]Service{"yt": {Domains: []Domain{{Name: "youtube.com"}}}}}
	if got, ok := matchDomain(t, cfg, "youtube.com"); ok {
		t.Errorf("got %d, want no match", got)
	}
}

// design 7.4 + 10.1: patterns normalized by Load match as written in the design.
func TestMatchDomainAfterLoad(t *testing.T) {
	yaml := `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
services:
  yt:
    domains: [YouTube.COM.]
  g:
    domains: ["=Google.Com"]
rules:
  - services: [yt]
    via: [nl]
  - services: [g]
    via: [nl]
`
	cfg, _ := mustLoad(t, filesOf(yaml, map[string]string{"nl.conf": simpleConf(t)}))
	cases := []struct {
		name string
		rule int
		ok   bool
	}{
		{"WWW.YouTube.com.", 0, true},
		{"youtube.com", 0, true},
		{"google.com.", 1, true},
		{"mail.google.com", 0, false},
	}
	for _, c := range cases {
		got, ok := matchDomain(t, cfg, c.name)
		if ok != c.ok || (ok && got != c.rule) {
			t.Errorf("MatchDomain(%q) = %d, %v; want %d, %v", c.name, got, ok, c.rule, c.ok)
		}
	}
}

// matchDomain calls MatchDomain and turns a panic into a test failure.
func matchDomain(t *testing.T, cfg *Config, name string) (rule int, ok bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MatchDomain panicked: %v", r)
		}
	}()
	return cfg.MatchDomain(name)
}

// --- MatchDomainFunc (Wirefork M5 decision 1) -----------------------------------------

// m5NoPanicMatch calls MatchDomainFunc and turns a panic into a test failure.
func m5NoPanicMatch(t *testing.T, cfg *Config, name string, use func(int) bool) (rule int, ok bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MatchDomainFunc panicked: %v", r)
		}
	}()
	return cfg.MatchDomainFunc(name, use)
}

// m5Skip returns a use func that leaves out the listed rules.
func m5Skip(skip ...int) func(int) bool {
	return func(i int) bool {
		for _, s := range skip {
			if i == s {
				return false
			}
		}
		return true
	}
}

// design 7.4, Wirefork M5 plan "Сигнатуры": a nil use means every rule, the result is
// that of MatchDomain.
func TestM5MatchDomainFuncNilIsMatchDomain(t *testing.T) {
	cfg := matchConfig()
	names := []string{
		"youtube.com", "www.youtube.com", "notyoutube.com", "google.com",
		"www.google.com", "music.youtube.com", "gemini.google.com",
		"example.org", "sub.example.org", "exact.example", "www.exact.example",
		"q.x.y.deep.example", "y.deep.example", "WWW.YouTube.com.", "GOOGLE.COM.",
		"unused.example", "wikipedia.org", "", ".",
	}
	for _, name := range names {
		wantRule, wantOK := matchDomain(t, cfg, name)
		gotRule, gotOK := m5NoPanicMatch(t, cfg, name, nil)
		if gotOK != wantOK || (wantOK && gotRule != wantRule) {
			t.Errorf("MatchDomainFunc(%q, nil) = %d, %v; MatchDomain = %d, %v", name, gotRule, gotOK, wantRule, wantOK)
		}
	}
}

// design 7.4 (fallback: default does not take part), 8 step 1, Wirefork M5 decision 1:
// a skipped rule gives the name to the next matching rule by the same order
// of specificity; among the remaining rules ties go by rule order.
func TestM5MatchDomainFunc(t *testing.T) {
	const none = -1
	cfg := &Config{
		Services: map[string]Service{
			"wwwexact": {Domains: []Domain{{Name: "www.example.org", Exact: true}}},
			"org":      {Domains: []Domain{{Name: "example.org"}}},
			"yt":       {Domains: []Domain{{Name: "youtube.com"}}},
			"music":    {Domains: []Domain{{Name: "music.youtube.com"}}},
			"yt2":      {Domains: []Domain{{Name: "youtube.com"}}},
			"yt3":      {Domains: []Domain{{Name: "youtube.com"}}},
			"only":     {Domains: []Domain{{Name: "only.example"}}},
		},
		Rules: []Rule{
			0: {Services: []string{"wwwexact"}, Via: []string{"home"}},
			1: {Services: []string{"org"}, Via: []string{"fi"}},
			2: {Services: []string{"yt"}, Via: []string{"nl"}},
			3: {Services: []string{"music"}, Via: []string{"nl"}},
			4: {Services: []string{"yt2"}, Via: []string{"de"}},
			5: {Services: []string{"yt3"}, Via: []string{"fi"}},
			6: {Services: []string{"only"}, Via: []string{"nl"}},
		},
	}
	cases := []struct {
		why  string
		name string
		skip []int
		want int
	}{
		{"nothing skipped: exact on top wins", "www.example.org", nil, 0},
		{"exact on top skipped: the suffix below gets the name", "www.example.org", []int{0}, 1},
		{"exact on top skipped, normalized name", "WWW.Example.ORG.", []int{0}, 1},
		{"skipping an unrelated rule changes nothing", "www.example.org", []int{2, 3}, 0},
		{"suffix rule skipped: name not covered by the exact one", "mail.example.org", []int{1}, none},
		{"both skipped: no match", "www.example.org", []int{0, 1}, none},
		{"longer suffix wins among the remaining", "x.music.youtube.com", []int{2}, 3},
		{"longer suffix skipped: first of the equal shorter suffixes", "x.music.youtube.com", []int{3}, 2},
		{"longer suffix and first equal skipped: next equal by rule order", "x.music.youtube.com", []int{2, 3}, 4},
		{"first two equal suffixes skipped: the third", "www.youtube.com", []int{2, 4}, 5},
		{"all equal suffixes skipped: no match", "www.youtube.com", []int{2, 4, 5}, none},
		{"the only rule skipped: no match", "only.example", []int{6}, none},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			got, ok := m5NoPanicMatch(t, cfg, c.name, m5Skip(c.skip...))
			if c.want == none {
				if ok {
					t.Errorf("MatchDomainFunc(%q, skip %v) = %d, want no match", c.name, c.skip, got)
				}
				return
			}
			if !ok || got != c.want {
				t.Errorf("MatchDomainFunc(%q, skip %v) = %d, %v; want %d", c.name, c.skip, got, ok, c.want)
			}
		})
	}

	// A use that rejects every rule: nothing matches.
	for _, name := range []string{"www.example.org", "youtube.com", "only.example"} {
		if got, ok := m5NoPanicMatch(t, cfg, name, func(int) bool { return false }); ok {
			t.Errorf("MatchDomainFunc(%q, none used) = %d, want no match", name, got)
		}
	}
}
