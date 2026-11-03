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

// Tests follow design 7.3, 8, 10.2 (config.reload: autostart on the first
// apply, toggles kept on a repeated one, restart only on a changed .conf,
// the warning about a tunnel DNS server under a CIDR of a rule with
// fallback: block; planApply and blockedDNSWarnings), not the
// implementation. Configs are built with
// config.Load from YAML and .conf text; keys are generated per test.

// --- helpers ---------------------------------------------------------------

// genKey returns the base64 of a fresh random key.
func genKey(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// confFile is a .conf with fixed generated keys; Text renders it with extra
// [Interface] lines (MTU, DNS) so that a test can change one field and keep
// the keys.
type confFile struct {
	priv, pub string
	address   string
	endpoint  string
	allowed   string
}

func newConfFile(t *testing.T, address, endpoint, allowed string) confFile {
	return confFile{priv: genKey(t), pub: genKey(t), address: address, endpoint: endpoint, allowed: allowed}
}

func (c confFile) Text(iface ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", c.priv, c.address)
	for _, l := range iface {
		b.WriteString(l + "\n")
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", c.pub, c.endpoint, c.allowed)
	return b.String()
}

// loadConfig loads wgplex.yaml and the .conf texts; a config error fails the test.
func loadConfig(t *testing.T, yaml string, confs map[string]string) *config.Config {
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

// tunnelYAML renders one tunnel of wgplex.yaml; extra lines are indented.
func tunnelYAML(name, routes string, autostart bool, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  - name: %s\n    conf: %s.conf\n    routes: %s\n    autostart: %v\n", name, name, routes, autostart)
	for _, l := range extra {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

// confFiles are the .conf files of the planApply fixture, one per tunnel.
type confFiles map[string]confFile

func newConfFiles(t *testing.T) confFiles {
	return confFiles{
		"work": newConfFile(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8"),
		"home": newConfFile(t, "10.3.0.2/32", "203.0.113.3:51820", "192.168.50.0/24"),
		"de":   newConfFile(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),
		"fi":   newConfFile(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),
		"nl":   newConfFile(t, "10.5.0.2/32", "203.0.113.9:51820", "0.0.0.0/0"),
		"lab":  newConfFile(t, "10.6.0.2/32", "203.0.113.11:51820", "172.16.0.0/12"),
	}
}

// texts renders every conf with the same [Interface] DNS line (dns_domains
// needs DNS, design 10.1); changed overrides the text of some confs.
func (cs confFiles) texts(changed map[string]string) map[string]string {
	out := map[string]string{}
	for name, c := range cs {
		out[name+".conf"] = c.Text("DNS = 10.9.9.9")
	}
	for name, text := range changed {
		out[name+".conf"] = text
	}
	return out
}

// baseYAML: work (autostart), home (no autostart), de (autostart),
// fi (autostart); a rule so that no service is unused.
func baseYAML(tunnels ...string) string {
	return "tunnels:\n" + strings.Join(tunnels, "") + `services:
  s:
    domains: [example.com]
rules:
  - services: [s]
    via: []
`
}

func baseTunnels() []string {
	return []string{
		tunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		tunnelYAML("home", "config", false),
		tunnelYAML("de", "rules", true),
		tunnelYAML("fi", "rules", true),
	}
}

func boolSet(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// trueKeys lists the keys with a true value, sorted.
func trueKeys(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func planApplyOf(t *testing.T, cur, next *config.Config, switches, running map[string]bool) (nextEnabled map[string]bool, stop, start []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("planApply panicked: %v", r)
		}
	}()
	return planApply(cur, next, switches, running)
}

func sameStrings(a, b []string) bool { return len(a) == 0 && len(b) == 0 || slices.Equal(a, b) }

type planWant struct {
	enabled, stop, start []string // enabled: sorted; stop, start: in order
}

func checkPlan(t *testing.T, name string, cur, next *config.Config, switches, running map[string]bool, want planWant) {
	t.Helper()
	ne, stop, start := planApplyOf(t, cur, next, switches, running)
	if got := trueKeys(ne); !sameStrings(got, want.enabled) {
		t.Errorf("%s: nextEnabled = %v, want %v", name, got, want.enabled)
	}
	if !sameStrings(stop, want.stop) {
		t.Errorf("%s: stop = %v, want %v", name, stop, want.stop)
	}
	if !sameStrings(start, want.start) {
		t.Errorf("%s: start = %v, want %v", name, start, want.start)
	}
}

// --- planApply -------------------------------------------------------------

// design 10.2: the first apply after start enables and starts the
// autostart tunnels, in config order.
func TestPlanApplyFirst(t *testing.T) {
	cs := newConfFiles(t)
	next := loadConfig(t, baseYAML(baseTunnels()...), cs.texts(nil))
	checkPlan(t, "nil maps", nil, next, nil, nil, planWant{
		enabled: []string{"de", "fi", "work"},
		start:   []string{"work", "de", "fi"},
	})
	checkPlan(t, "empty maps", nil, next, map[string]bool{}, map[string]bool{}, planWant{
		enabled: []string{"de", "fi", "work"},
		start:   []string{"work", "de", "fi"},
	})
}

// design 10.2, 11: a repeated apply of the same config keeps the
// user's explicit toggles (de turned off, home turned on) and changes nothing.
func TestPlanApplyKeepsToggles(t *testing.T) {
	cs := newConfFiles(t)
	yaml := baseYAML(baseTunnels()...)
	cur := loadConfig(t, yaml, cs.texts(nil))
	next := loadConfig(t, yaml, cs.texts(nil))
	switches := map[string]bool{"work": true, "home": true, "fi": true, "de": false}
	checkPlan(t, "same config", cur, next, switches, boolSet("work", "home", "fi"), planWant{
		enabled: []string{"fi", "home", "work"},
	})

	// Everything turned off by the user (tunnel.disableAll writes false for
	// every tunnel): autostart does not bring tunnels back.
	off := map[string]bool{"work": false, "home": false, "de": false, "fi": false}
	checkPlan(t, "all off", cur, next, off, map[string]bool{}, planWant{})
}

// design 10.2: a new tunnel is enabled by its autostart, a removed one is
// stopped and gone.
func TestPlanApplyAddRemove(t *testing.T) {
	cs := newConfFiles(t)
	cur := loadConfig(t, baseYAML(baseTunnels()...), cs.texts(nil))
	next := loadConfig(t, baseYAML(
		tunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		tunnelYAML("nl", "rules", true),     // new, autostart
		tunnelYAML("home", "config", false), // kept
		tunnelYAML("lab", "config", false),  // new, no autostart
		tunnelYAML("fi", "rules", true),     // kept
		// de removed
	), cs.texts(nil))

	on := boolSet("work", "de", "fi")
	checkPlan(t, "add and remove", cur, next, on, on, planWant{
		enabled: []string{"fi", "nl", "work"},
		stop:    []string{"de"},
		start:   []string{"nl"},
	})

	// A removed tunnel that is enabled but not running (failed to start) is
	// just gone: nothing to stop.
	checkPlan(t, "removed with error", cur, next, on, boolSet("work", "fi"), planWant{
		enabled: []string{"fi", "nl", "work"},
		start:   []string{"nl"},
	})
}

// design 10.2: a running tunnel whose .conf changed is restarted: stop and
// start; the others are left alone.
func TestPlanApplyConfChanged(t *testing.T) {
	cs := newConfFiles(t)
	yaml := baseYAML(baseTunnels()...)
	cur := loadConfig(t, yaml, cs.texts(nil))
	next := loadConfig(t, yaml, cs.texts(map[string]string{
		"fi": cs["fi"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := boolSet("work", "de", "fi")
	checkPlan(t, "MTU of fi", cur, next, on, on, planWant{
		enabled: []string{"de", "fi", "work"},
		stop:    []string{"fi"},
		start:   []string{"fi"},
	})

	// A changed peer (AllowedIPs) is a changed .conf too.
	changed := cs["work"]
	changed.allowed = "10.0.0.0/8, 172.20.0.0/16"
	next2 := loadConfig(t, yaml, cs.texts(map[string]string{"work": changed.Text("DNS = 10.9.9.9")}))
	checkPlan(t, "AllowedIPs of work", cur, next2, on, on, planWant{
		enabled: []string{"de", "fi", "work"},
		stop:    []string{"work"},
		start:   []string{"work"},
	})
}

// design 10.2: changes of wgplex.yaml alone (routes, dns_domains, check,
// services, rules) do not restart running tunnels.
func TestPlanApplyYAMLOnly(t *testing.T) {
	cs := newConfFiles(t)
	cur := loadConfig(t, baseYAML(baseTunnels()...), cs.texts(nil))
	next := loadConfig(t, "tunnels:\n"+strings.Join([]string{
		tunnelYAML("work", "rules", true, "dns_domains: [corp.example, lab.example]", "check: 10.0.0.1"),
		tunnelYAML("home", "config", false, "dns_domains: [home.example]"),
		tunnelYAML("de", "rules", true, "check: 1.1.1.1"),
		tunnelYAML("fi", "rules", true),
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
	on := boolSet("work", "de", "fi")
	checkPlan(t, "YAML only", cur, next, on, on, planWant{
		enabled: []string{"de", "fi", "work"},
	})
}

// An enabled tunnel that failed to start (enabled, not running)
// is started again by config.reload; its changed .conf does not matter.
func TestPlanApplyRetryFailed(t *testing.T) {
	cs := newConfFiles(t)
	yaml := baseYAML(baseTunnels()...)
	cur := loadConfig(t, yaml, cs.texts(nil))
	next := loadConfig(t, yaml, cs.texts(map[string]string{
		"de": cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := boolSet("work", "de", "fi")
	running := boolSet("work", "fi")
	for name, n := range map[string]*config.Config{"same": cur, "de changed": next} {
		checkPlan(t, name, cur, n, on, running, planWant{
			enabled: []string{"de", "fi", "work"},
			start:   []string{"de"},
		})
	}
}

// A tunnel turned off by the user whose .conf changed stays off: nothing to
// stop or start.
func TestPlanApplyDisabledChanged(t *testing.T) {
	cs := newConfFiles(t)
	yaml := baseYAML(baseTunnels()...)
	cur := loadConfig(t, yaml, cs.texts(nil))
	next := loadConfig(t, yaml, cs.texts(map[string]string{
		"de":   cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"home": cs["home"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	}))
	on := boolSet("work", "fi")
	// A tunnel turned off by the user has an entry; home has none and
	// autostart false (design 11).
	switches := map[string]bool{"work": true, "fi": true, "de": false}
	checkPlan(t, "disabled, changed", cur, next, switches, on, planWant{
		enabled: []string{"fi", "work"},
	})
}

// Stop in cur's tunnel order, start in next's tunnel order.
func TestPlanApplyOrder(t *testing.T) {
	cs := newConfFiles(t)
	cur := loadConfig(t, baseYAML(baseTunnels()...), cs.texts(nil))
	// next: tunnels reordered fi, de, work, home; plus new nl, lab with
	// autostart; all three running ones changed.
	nextConfs := cs.texts(map[string]string{
		"work": cs["work"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"de":   cs["de"].Text("DNS = 10.9.9.9", "MTU = 1380"),
		"fi":   cs["fi"].Text("DNS = 10.9.9.9", "MTU = 1380"),
	})
	next := loadConfig(t, baseYAML(
		tunnelYAML("lab", "config", true),
		tunnelYAML("fi", "rules", true),
		tunnelYAML("de", "rules", true),
		tunnelYAML("nl", "rules", true),
		tunnelYAML("work", "config", true, "dns_domains: [corp.example]"),
		tunnelYAML("home", "config", false),
	), nextConfs)
	on := boolSet("work", "de", "fi")
	checkPlan(t, "order", cur, next, on, on, planWant{
		enabled: []string{"de", "fi", "lab", "nl", "work"},
		stop:    []string{"work", "de", "fi"},
		start:   []string{"lab", "fi", "de", "nl", "work"},
	})
}

// --- blockedDNSWarnings -----------------------------------------------------

func blockedWarnings(t *testing.T, cfg *config.Config) (got []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("blockedDNSWarnings panicked: %v", r)
		}
	}()
	return blockedDNSWarnings(cfg)
}

// design 10.2: a DNS server of a tunnel (its .conf DNS, else
// 1.1.1.1, design 8) inside a CIDR of a service of a rule with fallback:
// block gets a warning naming the server and the tunnel; fallback: default
// and an empty via do not.
func TestBlockedDNSWarnings(t *testing.T) {
	dnsde := newConfFile(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0")
	nodns := newConfFile(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0")
	corp := newConfFile(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8")
	confs := map[string]string{
		"dnsde.conf": dnsde.Text("DNS = 1.0.0.1"),
		"nodns.conf": nodns.Text(),
		"corp.conf":  corp.Text("DNS = 10.0.0.53"),
	}
	tunnels := "tunnels:\n" +
		tunnelYAML("dnsde", "rules", true) +
		tunnelYAML("nodns", "rules", true) +
		tunnelYAML("corp", "config", true)

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
		cfg := loadConfig(t, tunnels+c.rules, confs)
		got := blockedWarnings(t, cfg)
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

// design 10.1 Keys: warnings carry no key.
func TestBlockedDNSWarningsNoKeys(t *testing.T) {
	c := newConfFile(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0")
	cfg := loadConfig(t, "tunnels:\n"+tunnelYAML("de", "rules", true)+`services:
  cf:
    cidrs: [1.0.0.0/24]
rules:
  - services: [cf]
    via: [de]
    fallback: block
`, map[string]string{"de.conf": c.Text("DNS = 1.0.0.1")})
	got := strings.Join(blockedWarnings(t, cfg), "\n")
	if got == "" {
		t.Fatal("no warning for 1.0.0.1 under a block CIDR")
	}
	for _, k := range []string{c.priv, c.pub} {
		if strings.Contains(got, k) {
			t.Errorf("warning contains a key: %q", got)
		}
	}
}

// --- checkWarnings -----------------------------------------------------

// Tests below follow design 9 "Ping": a check
// of a family the tunnel has no Address of is not pinged; config.reload warns
// about it, the config stays valid.

func checkWarningsOf(t *testing.T, cfg *config.Config) (got []string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("checkWarnings panicked: %v", r)
		}
	}()
	return checkWarnings(cfg)
}

func TestCheckWarnings(t *testing.T) {
	confs := map[string]confFile{
		"alpha": newConfFile(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),              // IPv4, IPv6 check: warn
		"fi":    newConfFile(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),              // IPv4, IPv4 check
		"work":  newConfFile(t, "10.0.0.2/32", "203.0.113.1:51820", "10.0.0.0/8"),             // no check
		"nl":    newConfFile(t, "10.5.0.2/32, fd00::5/128", "203.0.113.9:51820", "0.0.0.0/0"), // dual, IPv4 check
		"lab":   newConfFile(t, "10.6.0.2/32, fd00::6/128", "203.0.113.11:51820", "::/0"),     // dual, IPv6 check
		"omega": newConfFile(t, "fd00::7/128", "203.0.113.13:51820", "::/0"),                  // IPv6 only, IPv4 check: warn
		"v6ok":  newConfFile(t, "fd00::8/128", "203.0.113.15:51820", "::/0"),                  // IPv6 only, IPv6 check
	}
	texts := map[string]string{}
	for name, c := range confs {
		texts[name+".conf"] = c.Text()
	}
	yaml := baseYAML(
		tunnelYAML("alpha", "rules", true, "check: 2606:4700:4700::1111"),
		tunnelYAML("fi", "rules", true, "check: 1.1.1.1"),
		tunnelYAML("work", "config", true),
		tunnelYAML("nl", "rules", true, "check: 1.1.1.1"),
		tunnelYAML("lab", "rules", true, "check: 2001:4860:4860::8888"),
		tunnelYAML("omega", "rules", true, "check: 9.9.9.9"),
		tunnelYAML("v6ok", "rules", true, "check: 2620:fe::fe"),
	)
	cfg := loadConfig(t, yaml, texts)
	got := checkWarningsOf(t, cfg)
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
	cfg = loadConfig(t, baseYAML(tunnelYAML("work", "config", true)),
		map[string]string{"work.conf": confs["work"].Text()})
	if got := checkWarningsOf(t, cfg); len(got) != 0 {
		t.Errorf("no check: warnings %q, want none", got)
	}
}
