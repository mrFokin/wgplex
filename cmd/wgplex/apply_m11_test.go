package main

import (
	"strings"
	"testing"
)

// Tests follow design 10.2, 11 and the Wirefork M11 plan ("Модель → Переключатели",
// "Сигнатуры → cmd/wgplex"), not the implementation. Fixtures reuse the
// m6 helpers of apply_test.go (generated keys).

// design 10.2: a repeated apply keeps the current toggles (without a record
// in state.json the tunnels cur kept keep being enabled); a new tunnel gets
// its autostart.
func TestM11PlanApplyRepeatedNewTunnels(t *testing.T) {
	cs := m6NewConfs(t)
	yaml := m6BaseYAML(m6BaseTunnels()...)
	cur := m6Load(t, yaml, cs.texts(nil))
	next := m6Load(t, yaml, cs.texts(nil))
	on := m6Set("work", "home", "fi")
	m6CheckPlan(t, "same config", cur, next, nil, on, on, m6PlanWant{
		enabled: []string{"fi", "home", "work"},
	})

	next2 := m6Load(t, m6BaseYAML(append(m6BaseTunnels(),
		m6TunnelYAML("nl", "rules", true),
		m6TunnelYAML("lab", "config", false))...), cs.texts(nil))
	m6CheckPlan(t, "new tunnels", cur, next2, nil, on, on, m6PlanWant{
		enabled: []string{"fi", "home", "nl", "work"},
		start:   []string{"nl"},
	})
}

// --- checkWarnings with a check URL (M11) -----------------------------------

// design 9 "HTTP", 10.2: an IP literal in a check URL of a family the tunnel
// has no Address of is not checked: a config load warns, one warning per
// tunnel in config order, naming the tunnel and the address. A URL with a
// host name gives no warning when the tunnel has a DNS server of a family
// present in its Address (the default 1.1.1.1 serves an IPv4 tunnel); v6name
// — IPv6 only, no DNS in .conf — is not checked and warned about (design 9
// "HTTP", decision 6). dualname — dual stack, default IPv4 DNS — is checked.
func TestM11CheckWarningsURL(t *testing.T) {
	confs := map[string]m6Conf{
		"v4url6":   m6NewConf(t, "10.1.0.2/32", "203.0.113.5:51820", "0.0.0.0/0"),
		"v4url4":   m6NewConf(t, "10.2.0.2/32", "203.0.113.7:51820", "0.0.0.0/0"),
		"v4name":   m6NewConf(t, "10.3.0.2/32", "203.0.113.9:51820", "0.0.0.0/0"),
		"dual6":    m6NewConf(t, "10.4.0.2/32, fd00::4/128", "203.0.113.11:51820", "0.0.0.0/0"),
		"v6url4":   m6NewConf(t, "fd00::5/128", "203.0.113.13:51820", "::/0"),
		"v6name":   m6NewConf(t, "fd00::6/128", "203.0.113.15:51820", "::/0"),
		"v6url6":   m6NewConf(t, "fd00::7/128", "203.0.113.17:51820", "::/0"),
		"v4ping6":  m6NewConf(t, "10.8.0.2/32", "203.0.113.19:51820", "0.0.0.0/0"),
		"dualname": m6NewConf(t, "10.9.0.2/32, fd00::9/128", "203.0.113.21:51820", "0.0.0.0/0"),
	}
	texts := map[string]string{}
	for name, c := range confs {
		texts[name+".conf"] = c.Text()
	}
	yaml := m6BaseYAML(
		m6TunnelYAML("v4url6", "rules", true, `check: "https://[2606:4700:4700::1111]/"`),
		m6TunnelYAML("v4url4", "rules", true, `check: "https://1.1.1.1/"`),
		m6TunnelYAML("v4name", "rules", true, `check: "https://example.com/health"`),
		m6TunnelYAML("dual6", "rules", true, `check: "http://[2001:4860:4860::8888]:8080/x"`),
		m6TunnelYAML("v6url4", "rules", true, `check: "http://9.9.9.9:8080/x?y=1"`),
		m6TunnelYAML("v6name", "rules", true, `check: "http://example.net/"`),
		m6TunnelYAML("v6url6", "rules", true, `check: "https://[2620:fe::fe]/"`),
		m6TunnelYAML("v4ping6", "rules", true, "check: 2620:fe::9"),
		m6TunnelYAML("dualname", "rules", true, `check: "https://example.org/"`),
	)
	cfg := m6Load(t, yaml, texts)
	got := m7CheckWarnings(t, cfg)
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
