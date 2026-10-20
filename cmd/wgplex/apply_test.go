package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 6.3, 7, 9.3 (config.apply: autostart on the first
// apply, toggles kept on a repeated one, restart only on a changed .conf,
// the warning about a tunnel DNS server under a CIDR of a rule with
// fallback: block) and the M6 plan (decisions 1, 6, 12; planApply and
// blockedDNSWarnings), not the implementation. Configs are built with
// config.Load from YAML and .conf text; keys are generated per test.

// --- helpers ---------------------------------------------------------------

// m6Key returns the base64 of a fresh random key.
func m6Key(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// m6Conf is a .conf with fixed generated keys; Text renders it with extra
// [Interface] lines (MTU, DNS) so that a test can change one field and keep
// the keys.
type m6Conf struct {
	priv, pub string
	address   string
	endpoint  string
	allowed   string
}

func m6NewConf(t *testing.T, address, endpoint, allowed string) m6Conf {
	return m6Conf{priv: m6Key(t), pub: m6Key(t), address: address, endpoint: endpoint, allowed: allowed}
}

func (c m6Conf) Text(iface ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", c.priv, c.address)
	for _, l := range iface {
		b.WriteString(l + "\n")
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", c.pub, c.endpoint, c.allowed)
	return b.String()
}

// m6Load loads wgplex.yaml and the .conf texts; a config error fails the test.
func m6Load(t *testing.T, yaml string, confs map[string]string) *config.Config {
	t.Helper()
	files := map[string][]byte{"wgplex.yaml": []byte(yaml)}
	for name, text := range confs {
		files[name] = []byte(text)
	}
	cfg, _, err := config.Load(files)
	if err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	return cfg
}

// m6TunnelYAML renders one tunnel of wgplex.yaml; extra lines are indented.
func m6TunnelYAML(name, routes string, autostart bool, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  - name: %s\n    conf: %s.conf\n    routes: %s\n    autostart: %v\n", name, name, routes, autostart)
	for _, l := range extra {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

// m6Confs are the .conf files of the planApply fixture, one per tunnel.
type m6Confs map[string]m6Conf

func m6NewConfs(t *testing.T) m6Confs {
	return m6Confs{
		"work": m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8"),
		"home": m6NewConf(t, "10.3.0.2/32", "203.0.113.3:51820", "192.168.50.0/24"),
		"de":   m6NewConf(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),
		"fi":   m6NewConf(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),
		"nl":   m6NewConf(t, "10.5.0.2/32", "203.0.113.9:51820", "0.0.0.0/0"),
		"lab":  m6NewConf(t, "10.6.0.2/32", "203.0.113.11:51820", "172.16.0.0/12"),
	}
}

// texts renders every conf with the same [Interface] DNS line (dns_domains
// needs DNS, design 9.2); changed overrides the text of some confs.
func (cs m6Confs) texts(changed map[string]string) map[string]string {
	out := map[string]string{}
	for name, c := range cs {
		out[name+".conf"] = c.Text("DNS = 10.9.9.9")
	}
	for name, text := range changed {
		out[name+".conf"] = text
	}
	return out
}

// m6BaseYAML: work (autostart), home (no autostart), de (autostart),
// fi (autostart); a rule so that no service is unused.
func m6BaseYAML(tunnels ...string) string {
	return "tunnels:\n" + strings.Join(tunnels, "") + `services:
  s:
    domains: [example.com]
rules:
  - services: [s]
    via: []
`
}

func m6BaseTunnels() []string {
	return []string{
		m6TunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		m6TunnelYAML("home", "config", false),
		m6TunnelYAML("de", "rules", true),
		m6TunnelYAML("fi", "rules", true),
	}
}

func m6Set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// m6Trues lists the keys with a true value, sorted.
func m6Trues(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func m6Plan(t *testing.T, cur, next *config.Config, enabled, running map[string]bool) (nextEnabled map[string]bool, stop, start []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("planApply panicked: %v", r)
		}
	}()
	return planApply(cur, next, enabled, running)
}

func m6Eq(a, b []string) bool { return len(a) == 0 && len(b) == 0 || slices.Equal(a, b) }

type m6PlanWant struct {
	enabled, stop, start []string // enabled: sorted; stop, start: in order
}

func m6CheckPlan(t *testing.T, name string, cur, next *config.Config, enabled, running map[string]bool, want m6PlanWant) {
	t.Helper()
	ne, stop, start := m6Plan(t, cur, next, enabled, running)
	if got := m6Trues(ne); !m6Eq(got, want.enabled) {
		t.Errorf("%s: nextEnabled = %v, want %v", name, got, want.enabled)
	}
	if !m6Eq(stop, want.stop) {
		t.Errorf("%s: stop = %v, want %v", name, stop, want.stop)
	}
	if !m6Eq(start, want.start) {
		t.Errorf("%s: start = %v, want %v", name, start, want.start)
	}
}

// --- planApply -------------------------------------------------------------

// design 9.3, decision 1: the first apply after start enables and starts the
// autostart tunnels, in config order.
func TestM6PlanApplyFirst(t *testing.T) {
	cs := m6NewConfs(t)
	next := m6Load(t, m6BaseYAML(m6BaseTunnels()...), cs.texts(nil))
	m6CheckPlan(t, "nil maps", nil, next, nil, nil, m6PlanWant{
		enabled: []string{"de", "fi", "work"},
		start:   []string{"work", "de", "fi"},
	})
	m6CheckPlan(t, "empty maps", nil, next, map[string]bool{}, map[string]bool{}, m6PlanWant{
		enabled: []string{"de", "fi", "work"},
		start:   []string{"work", "de", "fi"},
	})
}

// design 9.3, decision 1: a repeated apply of the same config keeps the
// user's toggles (de turned off, home turned on) and changes nothing.
func TestM6PlanApplyKeepsToggles(t *testing.T) {
	cs := m6NewConfs(t)
	yaml := m6BaseYAML(m6BaseTunnels()...)
	cur := m6Load(t, yaml, cs.texts(nil))
	next := m6Load(t, yaml, cs.texts(nil))
	on := m6Set("work", "home", "fi")
	m6CheckPlan(t, "same config", cur, next, on, m6Set("work", "home", "fi"), m6PlanWant{
		enabled: []string{"fi", "home", "work"},
	})

	// Everything turned off by the user (tunnel.disableAll): autostart does
	// not bring tunnels back (decision 1, plan step 11).
	m6CheckPlan(t, "all off", cur, next, map[string]bool{}, map[string]bool{}, m6PlanWant{})
}

// design 9.3: a new tunnel is enabled by its autostart, a removed one is
// stopped and gone.
func TestM6PlanApplyAddRemove(t *testing.T) {
	cs := m6NewConfs(t)
	cur := m6Load(t, m6BaseYAML(m6BaseTunnels()...), cs.texts(nil))
	next := m6Load(t, m6BaseYAML(
		m6TunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		m6TunnelYAML("nl", "rules", true),     // new, autostart
		m6TunnelYAML("home", "config", false), // kept
		m6TunnelYAML("lab", "config", false),  // new, no autostart
		m6TunnelYAML("fi", "rules", true),     // kept
		// de removed
	), cs.texts(nil))

	on := m6Set("work", "de", "fi")
	m6CheckPlan(t, "add and remove", cur, next, on, on, m6PlanWant{
		enabled: []string{"fi", "nl", "work"},
		stop:    []string{"de"},
		start:   []string{"nl"},
	})

	// A removed tunnel that is enabled but not running (failed to start) is
	// just gone: nothing to stop.
	m6CheckPlan(t, "removed with error", cur, next, on, m6Set("work", "fi"), m6PlanWant{
		enabled: []string{"fi", "nl", "work"},
		start:   []string{"nl"},
	})
}

// design 9.3: a running tunnel whose .conf changed is restarted: stop and
// start; the others are left alone.
func TestM6PlanApplyConfChanged(t *testing.T) {
	cs := m6NewConfs(t)
	yaml := m6BaseYAML(m6BaseTunnels()...)
	cur := m6Load(t, yaml, cs.texts(nil))
	next := m6Load(t, yaml, cs.texts(map[string]string{
		"fi": cs["fi"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := m6Set("work", "de", "fi")
	m6CheckPlan(t, "MTU of fi", cur, next, on, on, m6PlanWant{
		enabled: []string{"de", "fi", "work"},
		stop:    []string{"fi"},
		start:   []string{"fi"},
	})

	// A changed peer (AllowedIPs) is a changed .conf too.
	changed := cs["work"]
	changed.allowed = "10.0.0.0/8, 172.20.0.0/16"
	next2 := m6Load(t, yaml, cs.texts(map[string]string{"work": changed.Text("DNS = 10.9.9.9")}))
	m6CheckPlan(t, "AllowedIPs of work", cur, next2, on, on, m6PlanWant{
		enabled: []string{"de", "fi", "work"},
		stop:    []string{"work"},
		start:   []string{"work"},
	})
}

// design 9.3: changes of wgplex.yaml alone (routes, dns_domains, check,
// services, rules) do not restart running tunnels.
func TestM6PlanApplyYAMLOnly(t *testing.T) {
	cs := m6NewConfs(t)
	cur := m6Load(t, m6BaseYAML(m6BaseTunnels()...), cs.texts(nil))
	next := m6Load(t, "tunnels:\n"+strings.Join([]string{
		m6TunnelYAML("work", "rules", true, "dns_domains: [corp.example, lab.example]", "check: 10.0.0.1"),
		m6TunnelYAML("home", "config", false, "dns_domains: [home.example]"),
		m6TunnelYAML("de", "rules", true, "check: 1.1.1.1"),
		m6TunnelYAML("fi", "rules", true),
	}, "")+`services:
  s:
    domains: [example.com, example.net]
  t:
    cidrs: [91.108.4.0/22]
rules:
  - services: [t]
    via: [de, fi]
    fallback: block
  - services: [s]
    via: [fi]
`, cs.texts(nil))
	on := m6Set("work", "de", "fi")
	m6CheckPlan(t, "YAML only", cur, next, on, on, m6PlanWant{
		enabled: []string{"de", "fi", "work"},
	})
}

// Decision 6: an enabled tunnel that failed to start (enabled, not running)
// is started again by config.apply; its changed .conf does not matter.
func TestM6PlanApplyRetryFailed(t *testing.T) {
	cs := m6NewConfs(t)
	yaml := m6BaseYAML(m6BaseTunnels()...)
	cur := m6Load(t, yaml, cs.texts(nil))
	next := m6Load(t, yaml, cs.texts(map[string]string{
		"de": cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := m6Set("work", "de", "fi")
	running := m6Set("work", "fi")
	for name, n := range map[string]*config.Config{"same": cur, "de changed": next} {
		m6CheckPlan(t, name, cur, n, on, running, m6PlanWant{
			enabled: []string{"de", "fi", "work"},
			start:   []string{"de"},
		})
	}
}

// A tunnel turned off by the user whose .conf changed stays off: nothing to
// stop or start.
func TestM6PlanApplyDisabledChanged(t *testing.T) {
	cs := m6NewConfs(t)
	yaml := m6BaseYAML(m6BaseTunnels()...)
	cur := m6Load(t, yaml, cs.texts(nil))
	next := m6Load(t, yaml, cs.texts(map[string]string{
		"de":   cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"home": cs["home"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := m6Set("work", "fi")
	m6CheckPlan(t, "disabled, changed", cur, next, on, on, m6PlanWant{
		enabled: []string{"fi", "work"},
	})
}

// M6 plan: stop in cur's tunnel order, start in next's tunnel order.
func TestM6PlanApplyOrder(t *testing.T) {
	cs := m6NewConfs(t)
	cur := m6Load(t, m6BaseYAML(m6BaseTunnels()...), cs.texts(nil))
	// next: tunnels reordered fi, de, work, home; plus new nl, lab with
	// autostart; all three running ones changed.
	nextConfs := cs.texts(map[string]string{
		"work": cs["work"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"de":   cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"fi":   cs["fi"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	})
	next := m6Load(t, m6BaseYAML(
		m6TunnelYAML("lab", "config", true),
		m6TunnelYAML("fi", "rules", true),
		m6TunnelYAML("de", "rules", true),
		m6TunnelYAML("nl", "rules", true),
		m6TunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		m6TunnelYAML("home", "config", false),
	), nextConfs)
	on := m6Set("work", "de", "fi")
	m6CheckPlan(t, "order", cur, next, on, on, m6PlanWant{
		enabled: []string{"de", "fi", "lab", "nl", "work"},
		stop:    []string{"work", "de", "fi"},
		start:   []string{"lab", "fi", "de", "nl", "work"},
	})
}

// --- blockedDNSWarnings -----------------------------------------------------

func m6Blocked(t *testing.T, cfg *config.Config) (got []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("blockedDNSWarnings panicked: %v", r)
		}
	}()
	return blockedDNSWarnings(cfg)
}

// design 9.3, decision 12: a DNS server of a tunnel (its .conf DNS, else
// 1.1.1.1, design 7) inside a CIDR of a service of a rule with fallback:
// block gets a warning naming the server and the tunnel; fallback: default
// and an empty via do not.
func TestM6BlockedDNSWarnings(t *testing.T) {
	dnsde := m6NewConf(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0")
	nodns := m6NewConf(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0")
	corp := m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8")
	confs := map[string]string{
		"dnsde.conf": dnsde.Text("DNS = 1.0.0.1"),
		"nodns.conf": nodns.Text(),
		"corp.conf":  corp.Text("DNS = 10.0.0.53"),
	}
	tunnels := "tunnels:\n" +
		m6TunnelYAML("dnsde", "rules", true) +
		m6TunnelYAML("nodns", "rules", true) +
		m6TunnelYAML("corp", "config", true)

	cases := []struct {
		name  string
		rules string     // services and rules of the YAML
		want  [][]string // per warning: substrings it must hold
	}{
		{
			name: ".conf DNS under block CIDR",
			rules: `services:
  cf:
    cidrs: [1.0.0.0/24]
rules:
  - services: [cf]
    via: [dnsde, nodns]
    fallback: block
`,
			want: [][]string{{"1.0.0.1", "dnsde"}},
		},
		{
			name: "default 1.1.1.1 under block CIDR",
			rules: `services:
  cf:
    cidrs: [1.1.1.0/24]
rules:
  - services: [cf]
    via: [dnsde]
    fallback: block
`,
			want: [][]string{{"1.1.1.1", "nodns"}},
		},
		{
			name: "both, a second service of the rule",
			rules: `services:
  web:
    domains: [example.com]
  cf:
    cidrs: [1.0.0.0/24, 1.1.1.0/24]
rules:
  - services: [web, cf]
    via: [corp]
    fallback: block
`,
			want: [][]string{{"1.0.0.1", "dnsde"}, {"1.1.1.1", "nodns"}},
		},
		{
			name: "corp DNS under a wide block CIDR",
			rules: `services:
  ten:
    cidrs: [10.0.0.0/16]
rules:
  - services: [ten]
    via: [dnsde]
    fallback: block
`,
			want: [][]string{{"10.0.0.53", "corp"}},
		},
		{
			name: "fallback default",
			rules: `services:
  cf:
    cidrs: [1.0.0.0/24, 1.1.1.0/24]
rules:
  - services: [cf]
    via: [dnsde, nodns]
    fallback: default
`,
		},
		{
			name: "empty via",
			rules: `services:
  cf:
    cidrs: [1.0.0.0/24, 1.1.1.0/24]
rules:
  - services: [cf]
    via: []
`,
		},
		{
			name: "block CIDR not covering any DNS",
			rules: `services:
  tg:
    cidrs: [91.108.4.0/22, 1.0.1.0/24]
  cf:
    domains: [one.one.one.one]
rules:
  - services: [tg, cf]
    via: [dnsde]
    fallback: block
`,
		},
	}
	for _, c := range cases {
		cfg := m6Load(t, tunnels+c.rules, confs)
		got := m6Blocked(t, cfg)
		if len(got) != len(c.want) {
			t.Errorf("%s: warnings = %q, want %d", c.name, got, len(c.want))
			continue
		}
		for _, subs := range c.want {
			found := false
			for _, w := range got {
				ok := true
				for _, s := range subs {
					ok = ok && strings.Contains(w, s)
				}
				found = found || ok
			}
			if !found {
				t.Errorf("%s: no warning with %q in %q", c.name, subs, got)
			}
		}
	}
}

// design 9.4: warnings carry no key.
func TestM6BlockedDNSWarningsNoKeys(t *testing.T) {
	c := m6NewConf(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0")
	cfg := m6Load(t, "tunnels:\n"+m6TunnelYAML("de", "rules", true)+`services:
  cf:
    cidrs: [1.0.0.0/24]
rules:
  - services: [cf]
    via: [de]
    fallback: block
`, map[string]string{"de.conf": c.Text("DNS = 1.0.0.1")})
	got := strings.Join(m6Blocked(t, cfg), "\n")
	if got == "" {
		t.Fatal("no warning for 1.0.0.1 under a block CIDR")
	}
	for _, k := range []string{c.priv, c.pub} {
		if strings.Contains(got, k) {
			t.Errorf("warning contains a key: %q", got)
		}
	}
}

// --- checkWarnings (M7) -----------------------------------------------------

// Tests below follow design 8 "Ping" and the M7 plan (decision 7): a check
// of a family the tunnel has no Address of is not pinged; config.apply warns
// about it, the config stays valid.

func m7CheckWarnings(t *testing.T, cfg *config.Config) (got []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("checkWarnings panicked: %v", r)
		}
	}()
	return checkWarnings(cfg)
}

func TestM7CheckWarnings(t *testing.T) {
	confs := map[string]m6Conf{
		"alpha": m6NewConf(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),              // IPv4, IPv6 check: warn
		"fi":    m6NewConf(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),              // IPv4, IPv4 check
		"work":  m6NewConf(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8"),             // no check
		"nl":    m6NewConf(t, "10.5.0.2/32, fd00::5/128", "203.0.113.9:51820", "0.0.0.0/0"), // dual, IPv4 check
		"lab":   m6NewConf(t, "10.6.0.2/32, fd00::6/128", "203.0.113.11:51820", "::/0"),     // dual, IPv6 check
		"omega": m6NewConf(t, "fd00::7/128", "203.0.113.13:51820", "::/0"),                  // IPv6 only, IPv4 check: warn
		"v6ok":  m6NewConf(t, "fd00::8/128", "203.0.113.15:51820", "::/0"),                  // IPv6 only, IPv6 check
	}
	texts := map[string]string{}
	for name, c := range confs {
		texts[name+".conf"] = c.Text()
	}
	yaml := m6BaseYAML(
		m6TunnelYAML("alpha", "rules", true, "check: 2606:4700:4700::1111"),
		m6TunnelYAML("fi", "rules", true, "check: 1.1.1.1"),
		m6TunnelYAML("work", "config", true),
		m6TunnelYAML("nl", "rules", true, "check: 1.1.1.1"),
		m6TunnelYAML("lab", "rules", true, "check: 2001:4860:4860::8888"),
		m6TunnelYAML("omega", "rules", true, "check: 9.9.9.9"),
		m6TunnelYAML("v6ok", "rules", true, "check: 2620:fe::fe"),
	)
	cfg := m6Load(t, yaml, texts)
	got := m7CheckWarnings(t, cfg)
	if len(got) != 2 {
		t.Fatalf("checkWarnings = %q, want 2 warnings (alpha, omega)", got)
	}
	// Config order; each names the tunnel and the check address.
	for i, w := range []struct{ tunnel, addr string }{{"alpha", "2606:4700:4700::1111"}, {"omega", "9.9.9.9"}} {
		if !strings.Contains(got[i], w.tunnel) || !strings.Contains(got[i], w.addr) {
			t.Errorf("warning %d = %q, want it to name %s and %s", i, got[i], w.tunnel, w.addr)
		}
	}
	for _, w := range got {
		for _, c := range confs {
			if strings.Contains(w, c.priv) || strings.Contains(w, c.pub) {
				t.Errorf("warning contains a key: %q", w)
			}
		}
	}

	// No tunnel with a check: no warnings.
	cfg = m6Load(t, m6BaseYAML(m6TunnelYAML("work", "config", true)),
		map[string]string{"work.conf": confs["work"].Text()})
	if got := m7CheckWarnings(t, cfg); len(got) != 0 {
		t.Errorf("no check: warnings %q, want none", got)
	}
}
