package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 8 (tunnel DNS: DNS of .conf, else 1.1.1.1), 9 "HTTP":
// an HTTP check by host
// name is resolved through the tunnel DNS; without a DNS server reachable
// through the tunnel — of a family present in Address — the check is not
// made and config.apply warns. The server family and the query type are
// independent: a dual-stack tunnel with only an IPv6 DNS server is checked.
// Fixtures reuse the m6 helpers (generated keys).

// checkTunnel is one tunnel of the m11 fixture: Address, the [Interface] DNS
// line ("" — none) and the check value ("" — none).
type checkTunnel struct {
	name, address, dns, check string
}

// loadChecks loads the tunnels in order; it returns the config and the
// confs (for the key leak check).
func loadChecks(t *testing.T, tunnels []checkTunnel) (*config.Config, []confFile) {
	t.Helper()
	var ys []string
	var confs []confFile
	texts := map[string]string{}
	for i, tn := range tunnels {
		allowed := "0.0.0.0/0"
		if !strings.Contains(tn.address, ".") {
			allowed = "::/0"
		}
		c := newConfFile(t, tn.address, fmt.Sprintf("203.0.113.%d:51820", i+1), allowed)
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
		ys = append(ys, tunnelYAML(tn.name, "rules", true, extra...))
	}
	return loadConfig(t, baseYAML(ys...), texts), confs
}

// design 9 "HTTP", 7: a check URL with a host name warns
// exactly when the tunnel has no DNS server of a family present in Address.
func TestCheckWarningsHostNoDNS(t *testing.T) {
	cases := []struct {
		name string
		tn   checkTunnel
		warn bool
	}{
		// design 9: IPv6 only, no DNS in .conf — the default 1.1.1.1 is IPv4.
		{"v6 only, no DNS", checkTunnel{"v6nodns", "fd00::2/128", "", `"https://example.com/health"`}, true},
		{"v6 only, IPv4 DNS only", checkTunnel{"v6dns4", "fd00::3/128", "10.9.9.9", `"https://example.com/"`}, true},
		{"v6 only, IPv6 DNS", checkTunnel{"v6dns6", "fd00::4/128", "fd00::53", `"https://example.com/"`}, false},
		{"v6 only, both DNS", checkTunnel{"v6both", "fd00::5/128", "10.9.9.9, fd00::53", `"http://example.com:8080/x"`}, false},
		// design 8: an IPv4 tunnel without DNS uses 1.1.1.1 — IPv4, fine.
		{"v4 only, no DNS", checkTunnel{"v4nodns", "10.1.0.2/32", "", `"https://example.com/"`}, false},
		{"v4 only, IPv4 DNS", checkTunnel{"v4dns4", "10.2.0.2/32", "10.9.9.9", `"https://example.com/"`}, false},
		// IPv4 only Address: an IPv6 DNS server is not reachable through the tunnel.
		{"v4 only, IPv6 DNS only", checkTunnel{"v4dns6", "10.3.0.2/32", "fd00::53", `"https://example.com/"`}, true},
		{"dual, no DNS", checkTunnel{"dualnodns", "10.4.0.2/32, fd00::6/128", "", `"https://example.com/"`}, false},
		// The server family and the query type are independent — an
		// IPv6 server reachable through a dual-stack tunnel answers A queries.
		{"dual, IPv6 DNS only", checkTunnel{"dualdns6", "10.5.0.2/32, fd00::7/128", "fd00::53", `"https://example.com/"`}, false},
		{"dual, IPv4 DNS only", checkTunnel{"dualdns4", "10.6.0.2/32, fd00::a/128", "10.9.9.9", `"https://example.com/"`}, false},
		{"dual, both DNS", checkTunnel{"dualboth", "10.7.0.2/32, fd00::b/128", "10.9.9.9, fd00::53", `"https://example.com/"`}, false},
		// An IP literal host needs no DNS.
		{"v6 only, IPv6 literal, no DNS", checkTunnel{"v6lit", "fd00::8/128", "", `"https://[2620:fe::fe]/"`}, false},
		// A ping check needs no DNS either.
		{"v6 only, IPv6 ping, no DNS", checkTunnel{"v6ping", "fd00::9/128", "", "2620:fe::fe"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, confs := loadChecks(t, []checkTunnel{c.tn})
			got := checkWarningsOf(t, cfg)
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
func TestCheckWarningsHostNoDNSOrder(t *testing.T) {
	cfg, _ := loadChecks(t, []checkTunnel{
		{"alpha", "fd00::2/128", "", `"https://a.example/"`},                     // warn: no IPv6 DNS
		{"bravo", "10.1.0.2/32", "", `"https://[2620:fe::fe]/"`},                 // warn: literal family
		{"charlie", "fd00::3/128", "fd00::53", `"https://c.example/"`},           // ok
		{"delta", "10.2.0.2/32", "fd00::53", `"https://d.example/x"`},            // warn: no IPv4 DNS
		{"echo", "10.3.0.2/32, fd00::4/128", "fd00::53", `"https://e.example/"`}, // ok: IPv6 DNS on dual stack
	})
	got := checkWarningsOf(t, cfg)
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

// --- activeCheck -------------------------------------------------------

func activeCheckOf(t *testing.T, tn *config.Tunnel) (got string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("activeCheck panicked: %v", r)
		}
	}()
	return activeCheck(tn)
}

// design 9: the check that is made is the
// check address or the check URL; none without a check, for an address (IP
// literal host) of a family the tunnel has no Address of, and for a host
// name without a tunnel DNS server of a family present in Address.
func TestActiveCheck(t *testing.T) {
	cases := []struct {
		name string
		tn   checkTunnel
		want string // "url" — the CheckURL of the tunnel
	}{
		{"no check", checkTunnel{"none", "10.1.0.2/32", "", ""}, ""},
		{"IPv4 ping on IPv4", checkTunnel{"p44", "10.1.0.2/32", "", "1.1.1.1"}, "1.1.1.1"},
		{"IPv6 ping on IPv6", checkTunnel{"p66", "fd00::2/128", "", "2620:fe::fe"}, "2620:fe::fe"},
		{"IPv6 ping on IPv4", checkTunnel{"p64", "10.1.0.2/32", "", "2620:fe::fe"}, ""},
		{"IPv4 ping on IPv6", checkTunnel{"p46", "fd00::2/128", "", "9.9.9.9"}, ""},
		{"IPv6 ping on dual", checkTunnel{"p6d", "10.1.0.2/32, fd00::2/128", "", "2620:fe::fe"}, "2620:fe::fe"},
		{"IPv4 literal URL on IPv4", checkTunnel{"u44", "10.1.0.2/32", "", `"http://10.0.0.1:8080/x"`}, "url"},
		{"IPv6 literal URL on IPv4", checkTunnel{"u64", "10.1.0.2/32", "", `"https://[2620:fe::fe]/"`}, ""},
		{"IPv4 literal URL on IPv6", checkTunnel{"u46", "fd00::2/128", "", `"http://9.9.9.9/"`}, ""},
		{"IPv6 literal URL on IPv6", checkTunnel{"u66", "fd00::2/128", "", `"https://[2620:fe::fe]/"`}, "url"},
		{"name on IPv4, default DNS", checkTunnel{"n4", "10.1.0.2/32", "", `"https://example.com/h?x=1"`}, "url"},
		{"name on dual, default DNS", checkTunnel{"nd", "10.1.0.2/32, fd00::2/128", "", `"https://example.com/"`}, "url"},
		{"name on IPv6, no DNS", checkTunnel{"n6", "fd00::2/128", "", `"https://example.com/"`}, ""},
		{"name on IPv6, IPv4 DNS only", checkTunnel{"n6d4", "fd00::2/128", "10.9.9.9", `"https://example.com/"`}, ""},
		{"name on IPv6, IPv6 DNS", checkTunnel{"n6d6", "fd00::2/128", "fd00::53", `"https://example.com/"`}, "url"},
		{"name on IPv4, IPv6 DNS only", checkTunnel{"n4d6", "10.1.0.2/32", "fd00::53", `"https://example.com/"`}, ""},
		// Dual stack with only an IPv6 DNS server is checked.
		{"name on dual, IPv6 DNS only", checkTunnel{"ndd6", "10.1.0.2/32, fd00::2/128", "fd00::53", `"https://example.com/"`}, "url"},
		{"name on dual, IPv4 DNS only", checkTunnel{"ndd4", "10.1.0.2/32, fd00::2/128", "10.9.9.9", `"https://example.com/"`}, "url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := loadChecks(t, []checkTunnel{c.tn})
			tn := &cfg.Tunnels[0]
			want := c.want
			if want == "url" {
				want = tn.CheckURL
				if want == "" {
					t.Fatalf("fixture: CheckURL is empty for %s", c.tn.check)
				}
			}
			if got := activeCheckOf(t, tn); got != want {
				t.Errorf("activeCheck = %q, want %q", got, want)
			}
		})
	}
}
