package main

import (
	"strings"
	"testing"
)

// Tests follow design 10.2, 11, not the implementation. Fixtures reuse the
// m6 helpers of apply_test.go (generated keys).

// design 10.2: a repeated apply keeps the current toggles; a new tunnel gets
// its autostart (tunnel toggles live in memory).
func TestPlanApplyRepeatedNewTunnels(t *testing.T) {
	cs := newConfFiles(t)
	yaml := baseYAML(baseTunnels()...)
	cur := loadConfig(t, yaml, cs.texts(nil))
	next := loadConfig(t, yaml, cs.texts(nil))
	on := boolSet("work", "home", "fi")
	checkPlan(t, "same config", cur, next, on, on, planWant{
		enabled: []string{"fi", "home", "work"},
	})

	next2 := loadConfig(t, baseYAML(append(baseTunnels(),
		tunnelYAML("nl", "rules", true),
		tunnelYAML("lab", "config", false))...), cs.texts(nil))
	checkPlan(t, "new tunnels", cur, next2, on, on, planWant{
		enabled: []string{"fi", "home", "nl", "work"},
		start:   []string{"nl"},
	})
}

// --- checkWarnings with a check URL -----------------------------------

// design 9 "HTTP", 9.3: an IP literal in a check URL of a family the tunnel
// has no Address of is not checked: config.apply warns, one warning per
// tunnel in config order, naming the tunnel and the address. A URL with a
// host name gives no warning when the tunnel has a DNS server of a family
// present in its Address (the default 1.1.1.1 serves an IPv4 tunnel); v6name
// — IPv6 only, no DNS in .conf — is not checked and warned about (design 9
// "HTTP"). dualname — dual stack, default IPv4 DNS — is checked.
func TestCheckWarningsURL(t *testing.T) {
	confs := map[string]confFile{
		"v4url6":   newConfFile(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),
		"v4url4":   newConfFile(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),
		"v4name":   newConfFile(t, "10.3.0.2/32", "203.0.113.9:51820", "0.0.0.0/0"),
		"dual6":    newConfFile(t, "10.4.0.2/32, fd00::4/128", "203.0.113.11:51820", "0.0.0.0/0"),
		"v6url4":   newConfFile(t, "fd00::5/128", "203.0.113.13:51820", "::/0"),
		"v6name":   newConfFile(t, "fd00::6/128", "203.0.113.15:51820", "::/0"),
		"v6url6":   newConfFile(t, "fd00::7/128", "203.0.113.17:51820", "::/0"),
		"v4ping6":  newConfFile(t, "10.8.0.2/32", "203.0.113.19:51820", "0.0.0.0/0"),
		"dualname": newConfFile(t, "10.9.0.2/32, fd00::9/128", "203.0.113.21:51820", "0.0.0.0/0"),
	}
	texts := map[string]string{}
	for name, c := range confs {
		texts[name+".conf"] = c.Text()
	}
	yaml := baseYAML(
		tunnelYAML("v4url6", "rules", true, `check: "https://[2606:4700:4700::1111]/"`),
		tunnelYAML("v4url4", "rules", true, `check: "https://1.1.1.1/"`),
		tunnelYAML("v4name", "rules", true, `check: "https://example.com/health"`),
		tunnelYAML("dual6", "rules", true, `check: "http://[2001:4860:4860::8888]:8080/x"`),
		tunnelYAML("v6url4", "rules", true, `check: "http://9.9.9.9:8080/x?y=1"`),
		tunnelYAML("v6name", "rules", true, `check: "http://example.net/"`),
		tunnelYAML("v6url6", "rules", true, `check: "https://[2620:fe::fe]/"`),
		tunnelYAML("v4ping6", "rules", true, "check: 2620:fe::9"),
		tunnelYAML("dualname", "rules", true, `check: "https://example.org/"`),
	)
	cfg := loadConfig(t, yaml, texts)
	got := checkWarningsOf(t, cfg)
	want := []struct{ tunnel, addr string }{
		{"v4url6", "2606:4700:4700::1111"},
		{"v6url4", "9.9.9.9"},
		{"v6name", "http://example.net/"},
		{"v4ping6", "2620:fe::9"},
	}
	if len(got) != len(want) {
		t.Fatalf("checkWarnings = %q, want %d warnings (v4url6, v6url4, v6name, v4ping6)", got, len(want))
	}
	for i, w := range want {
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
}
