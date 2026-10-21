package config

import "testing"

// Tests in this file follow docs/design.md section 8 (first item: DNS capture
// condition) and Wirefork M10 plan decision 11, not the implementation. The resolver
// has work, and the system DNS is captured, only when a rule names a service
// with domains or a tunnel has dns_domains.
func TestNeedsDNS(t *testing.T) {
	// Every .conf is generated per test run (fresh keys) and has DNS, so that
	// dns_domains is valid on any tunnel (design 10.1).
	confs := func(t *testing.T) map[string]string {
		return map[string]string{
			"nl.conf":   simpleConf(t),
			"de.conf":   simpleConf(t),
			"work.conf": simpleConf(t),
		}
	}

	const tunnels = `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
  - name: de
    conf: de.conf
    routes: rules
`

	cases := []struct {
		name string
		yaml string
		want bool
	}{
		// Wirefork M10 decision 10/11: an empty config leaves the system DNS alone.
		{name: "empty yaml", yaml: "", want: false},
		// design 10.3: the template is fully commented out — an empty config.
		{name: "only comments", yaml: "# tunnels:\n#   - name: nl\n\n# rules: []\n", want: false},
		{name: "tunnels without dns_domains and rules", yaml: tunnels, want: false},
		// design 8: only domains give the resolver work; CIDRs are routes.
		{name: "rule with cidr-only service", yaml: tunnels + `
services:
  telegram:
    cidrs: [91.108.4.0/22, 149.154.160.0/20]
rules:
  - services: [telegram]
    via: [nl, de]
`, want: false},
		{name: "rule with domain service", yaml: tunnels + `
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl]
`, want: true},
		// design 7.4: "=name" is an exact domain, still a domain.
		{name: "rule with exact domain service", yaml: tunnels + `
services:
  one:
    domains: ["=api.example.com"]
rules:
  - services: [one]
    via: [nl]
`, want: true},
		// Wirefork M10 plan, decision 11: a service no rule uses needs no capture
		// (it only gives a warning, design 10.1).
		{name: "domain service without rule", yaml: tunnels + `
services:
  youtube:
    domains: [youtube.com]
`, want: false},
		{name: "unused domain service, rule with cidr-only service", yaml: tunnels + `
services:
  youtube:
    domains: [youtube.com]
  telegram:
    cidrs: [91.108.4.0/22]
rules:
  - services: [telegram]
    via: [nl]
`, want: false},
		// design 8: dns_domains of a tunnel is split DNS — resolver work.
		{name: "tunnel dns_domains without rules", yaml: `
tunnels:
  - name: work
    conf: work.conf
    routes: rules
    dns_domains: [corp.example]
`, want: true},
		// design 8: rules with an empty via keep working (system DNS upstream).
		{name: "rule with empty via and domains", yaml: tunnels + `
services:
  direct:
    domains: [bank.example]
rules:
  - services: [direct]
    via: []
`, want: true},
		{name: "rule without via field and domains", yaml: tunnels + `
services:
  direct:
    domains: [bank.example]
rules:
  - services: [direct]
`, want: true},
		// design 8: block rules answer NODATA — the resolver must see the query.
		{name: "fallback block rule with domains", yaml: tunnels + `
services:
  ai:
    domains: [openai.com]
rules:
  - services: [ai]
    via: [nl, de]
    fallback: block
`, want: true},
		{name: "rule with several services, domains in one", yaml: tunnels + `
services:
  telegram:
    cidrs: [91.108.4.0/22]
  nets:
    cidrs: [198.51.100.0/24]
  youtube:
    domains: [youtube.com]
rules:
  - services: [telegram, nets, youtube]
    via: [nl]
`, want: true},
		{name: "domains in second rule only", yaml: tunnels + `
services:
  telegram:
    cidrs: [91.108.4.0/22]
  youtube:
    domains: [youtube.com]
rules:
  - services: [telegram]
    via: [nl]
  - services: [youtube]
    via: [de]
`, want: true},
		// design 10.1 example: both dns_domains and rule domains.
		{name: "design 9.1 example", yaml: `
tunnels:
  - name: work
    conf: work.conf
    routes: rules
    dns_domains: [corp.example]
  - name: nl
    conf: nl.conf
    routes: rules
services:
  youtube:
    domains: [youtube.com]
  telegram:
    cidrs: [91.108.4.0/22]
rules:
  - services: [youtube, telegram]
    via: [nl]
`, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := Load(filesOf(tc.yaml, confs(t)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.NeedsDNS(); got != tc.want {
				t.Errorf("NeedsDNS() = %v, want %v", got, tc.want)
			}
		})
	}
}
