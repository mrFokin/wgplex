package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 8 (tunnel DNS: DNS of .conf, else 1.1.1.1), 9 "HTTP"
// and the Wirefork M11 plan (decision 6, refined in bbc553e): an HTTP check by host
// name is resolved through the tunnel DNS; without a DNS server reachable
// through the tunnel — of a family present in Address — the check is not
// made and config.apply warns. The server family and the query type are
// independent: a dual-stack tunnel with only an IPv6 DNS server is checked.
// Fixtures reuse the m6 helpers (generated keys).

// m11Tunnel is one tunnel of the m11 fixture: Address, the [Interface] DNS
// line ("" — none) and the check value ("" — none).
type m11Tunnel struct {
	name, address, dns, check string
}

// m11LoadChecks loads the tunnels in order; it returns the config and the
// confs (for the key leak check).
func m11LoadChecks(t *testing.T, tunnels []m11Tunnel) (*config.Config, []m6Conf) {
	t.Helper()
	var ys []string
	var confs []m6Conf
	texts := map[string]string{}
	for i, tn := range tunnels {
		allowed := "0.0.0.0/0"
		if !strings.Contains(tn.address, ".") {
			allowed = "::/0"
		}
		c := m6NewConf(t, tn.address, fmt.Sprintf("203.0.113.%d:51820", i+1), allowed)
		confs = append(confs, c)
		var iface []string
		if tn.dns != "" {
			iface = append(iface, "DNS = "+tn.dns)
		}
		texts[tn.name+".conf"] = c.Text(iface...)
		var extra []string
		if tn.check != "" {
			extra = append(extra, "check: "+tn.check)
		}
		ys = append(ys, m6TunnelYAML(tn.name, "rules", true, extra...))
	}
	return m6Load(t, m6BaseYAML(ys...), texts), confs
}

// design 9 "HTTP", 8, Wirefork M11 decision 6: a check URL with a host name warns
// exactly when the tunnel has no DNS server of a family present in Address.
func TestM11CheckWarningsHostNoDNS(t *testing.T) {
	cases := []struct {
		name string
		tn   m11Tunnel
		warn bool
	}{
		// design 9: IPv6 only, no DNS in .conf — the default 1.1.1.1 is IPv4.
		{"v6 only, no DNS", m11Tunnel{"v6nodns", "fd00::2/128", "", `"https://example.com/health"`}, true},
		{"v6 only, IPv4 DNS only", m11Tunnel{"v6dns4", "fd00::3/128", "10.9.9.9", `"https://example.com/"`}, true},
		{"v6 only, IPv6 DNS", m11Tunnel{"v6dns6", "fd00::4/128", "fd00::53", `"https://example.com/"`}, false},
		{"v6 only, both DNS", m11Tunnel{"v6both", "fd00::5/128", "10.9.9.9, fd00::53", `"http://example.com:8080/x"`}, false},
		// design 8: an IPv4 tunnel without DNS uses 1.1.1.1 — IPv4, fine.
		{"v4 only, no DNS", m11Tunnel{"v4nodns", "10.1.0.2/32", "", `"https://example.com/"`}, false},
		{"v4 only, IPv4 DNS", m11Tunnel{"v4dns4", "10.2.0.2/32", "10.9.9.9", `"https://example.com/"`}, false},
		// IPv4 only Address: an IPv6 DNS server is not reachable through the tunnel.
		{"v4 only, IPv6 DNS only", m11Tunnel{"v4dns6", "10.3.0.2/32", "fd00::53", `"https://example.com/"`}, true},
		{"dual, no DNS", m11Tunnel{"dualnodns", "10.4.0.2/32, fd00::6/128", "", `"https://example.com/"`}, false},
		// bbc553e: the server family and the query type are independent — an
		// IPv6 server reachable through a dual-stack tunnel answers A queries.
		{"dual, IPv6 DNS only", m11Tunnel{"dualdns6", "10.5.0.2/32, fd00::7/128", "fd00::53", `"https://example.com/"`}, false},
		{"dual, IPv4 DNS only", m11Tunnel{"dualdns4", "10.6.0.2/32, fd00::a/128", "10.9.9.9", `"https://example.com/"`}, false},
		{"dual, both DNS", m11Tunnel{"dualboth", "10.7.0.2/32, fd00::b/128", "10.9.9.9, fd00::53", `"https://example.com/"`}, false},
		// An IP literal host needs no DNS.
		{"v6 only, IPv6 literal, no DNS", m11Tunnel{"v6lit", "fd00::8/128", "", `"https://[2620:fe::fe]/"`}, false},
		// A ping check needs no DNS either.
		{"v6 only, IPv6 ping, no DNS", m11Tunnel{"v6ping", "fd00::9/128", "", "2620:fe::fe"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, confs := m11LoadChecks(t, []m11Tunnel{c.tn})
			got := m7CheckWarnings(t, cfg)
			if !c.warn {
				if len(got) != 0 {
					t.Errorf("checkWarnings = %q, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("checkWarnings = %q, want one warning", got)
			}
			for _, sub := range []string{c.tn.name, cfg.Tunnels[0].CheckURL, "not checked"} {
				if !strings.Contains(got[0], sub) {
					t.Errorf("warning %q does not contain %q", got[0], sub)
				}
			}
			for _, k := range confs {
				if strings.Contains(got[0], k.priv) || strings.Contains(got[0], k.pub) {
					t.Errorf("warning contains a key: %q", got[0])
				}
			}
		})
	}
}

// design 9: one warning per tunnel in config order, the DNS case mixed with
// the IP literal family case.
func TestM11CheckWarningsHostNoDNSOrder(t *testing.T) {
	cfg, _ := m11LoadChecks(t, []m11Tunnel{
		{"alpha", "fd00::2/128", "", `"https://a.example/"`},                     // warn: no IPv6 DNS
		{"bravo", "10.1.0.2/32", "", `"https://[2620:fe::fe]/"`},                 // warn: literal family
		{"charlie", "fd00::3/128", "fd00::53", `"https://c.example/"`},           // ok
		{"delta", "10.2.0.2/32", "fd00::53", `"https://d.example/x"`},            // warn: no IPv4 DNS
		{"echo", "10.3.0.2/32, fd00::4/128", "fd00::53", `"https://e.example/"`}, // ok: IPv6 DNS on dual stack
	})
	got := m7CheckWarnings(t, cfg)
	want := []struct{ tunnel, what string }{
		{"alpha", "https://a.example/"},
		{"bravo", "2620:fe::fe"},
		{"delta", "https://d.example/x"},
	}
	if len(got) != len(want) {
		t.Fatalf("checkWarnings = %q, want warnings for alpha, bravo, delta (not charlie, echo)", got)
	}
	for i, w := range want {
		if !strings.Contains(got[i], w.tunnel) || !strings.Contains(got[i], w.what) {
			t.Errorf("warning %d = %q, want it to name %s and %s", i, got[i], w.tunnel, w.what)
		}
	}
}

// --- activeCheck (M11) -------------------------------------------------------

func m11ActiveCheck(t *testing.T, tn *config.Tunnel) (got string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("activeCheck panicked: %v", r)
		}
	}()
	return activeCheck(tn)
}

// design 9, Wirefork M7 decision 7, Wirefork M11 decision 6: the check that is made is the
// check address or the check URL; none without a check, for an address (IP
// literal host) of a family the tunnel has no Address of, and for a host
// name without a tunnel DNS server of a family present in Address.
func TestM11ActiveCheck(t *testing.T) {
	cases := []struct {
		name string
		tn   m11Tunnel
		want string // "url" — the CheckURL of the tunnel
	}{
		{"no check", m11Tunnel{"none", "10.1.0.2/32", "", ""}, ""},
		{"IPv4 ping on IPv4", m11Tunnel{"p44", "10.1.0.2/32", "", "1.1.1.1"}, "1.1.1.1"},
		{"IPv6 ping on IPv6", m11Tunnel{"p66", "fd00::2/128", "", "2620:fe::fe"}, "2620:fe::fe"},
		{"IPv6 ping on IPv4", m11Tunnel{"p64", "10.1.0.2/32", "", "2620:fe::fe"}, ""},
		{"IPv4 ping on IPv6", m11Tunnel{"p46", "fd00::2/128", "", "9.9.9.9"}, ""},
		{"IPv6 ping on dual", m11Tunnel{"p6d", "10.1.0.2/32, fd00::2/128", "", "2620:fe::fe"}, "2620:fe::fe"},
		{"IPv4 literal URL on IPv4", m11Tunnel{"u44", "10.1.0.2/32", "", `"http://10.0.0.1:8080/x"`}, "url"},
		{"IPv6 literal URL on IPv4", m11Tunnel{"u64", "10.1.0.2/32", "", `"https://[2620:fe::fe]/"`}, ""},
		{"IPv4 literal URL on IPv6", m11Tunnel{"u46", "fd00::2/128", "", `"http://9.9.9.9/"`}, ""},
		{"IPv6 literal URL on IPv6", m11Tunnel{"u66", "fd00::2/128", "", `"https://[2620:fe::fe]/"`}, "url"},
		{"name on IPv4, default DNS", m11Tunnel{"n4", "10.1.0.2/32", "", `"https://example.com/h?x=1"`}, "url"},
		{"name on dual, default DNS", m11Tunnel{"nd", "10.1.0.2/32, fd00::2/128", "", `"https://example.com/"`}, "url"},
		{"name on IPv6, no DNS", m11Tunnel{"n6", "fd00::2/128", "", `"https://example.com/"`}, ""},
		{"name on IPv6, IPv4 DNS only", m11Tunnel{"n6d4", "fd00::2/128", "10.9.9.9", `"https://example.com/"`}, ""},
		{"name on IPv6, IPv6 DNS", m11Tunnel{"n6d6", "fd00::2/128", "fd00::53", `"https://example.com/"`}, "url"},
		{"name on IPv4, IPv6 DNS only", m11Tunnel{"n4d6", "10.1.0.2/32", "fd00::53", `"https://example.com/"`}, ""},
		// bbc553e: dual stack with only an IPv6 DNS server is checked.
		{"name on dual, IPv6 DNS only", m11Tunnel{"ndd6", "10.1.0.2/32, fd00::2/128", "fd00::53", `"https://example.com/"`}, "url"},
		{"name on dual, IPv4 DNS only", m11Tunnel{"ndd4", "10.1.0.2/32, fd00::2/128", "10.9.9.9", `"https://example.com/"`}, "url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := m11LoadChecks(t, []m11Tunnel{c.tn})
			tn := &cfg.Tunnels[0]
			want := c.want
			if want == "url" {
				want = tn.CheckURL
				if want == "" {
					t.Fatalf("fixture: CheckURL is empty for %s", c.tn.check)
				}
			}
			if got := m11ActiveCheck(t, tn); got != want {
				t.Errorf("activeCheck = %q, want %q", got, want)
			}
		})
	}
}
