package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mrFokin/jrpc/v2"

	"github.com/mrFokin/wgplex/internal/rpc"
)

// Tests follow design 11, 12 and the M6 plan ("Вывод wf", decisions 4, 9,
// 10), not the implementation. Lines are compared by fields
// (strings.Fields), never by spacing: columns come from text/tabwriter.

var m6Now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// m6Out runs print and returns its output; a panic fails the test.
func m6Out(t *testing.T, what string, print func(w io.Writer)) string {
	t.Helper()
	var b bytes.Buffer
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s panicked: %v", what, r)
			}
		}()
		print(&b)
	}()
	return b.String()
}

// m6Rows splits out into lines, each as its fields; blank lines are dropped.
func m6Rows(out string) [][]string {
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			rows = append(rows, f)
		}
	}
	return rows
}

// m6F is the fields of a line as written in the plan.
func m6F(line string) []string { return strings.Fields(line) }

// m6HasRow reports whether out has a line with exactly these fields.
func m6HasRow(out string, want []string) bool {
	for _, r := range m6Rows(out) {
		if slices.Equal(r, want) {
			return true
		}
	}
	return false
}

// m6RowAt is the line whose first field is first; nil: none.
func m6RowAt(out, first string) []string {
	for _, r := range m6Rows(out) {
		if r[0] == first {
			return r
		}
	}
	return nil
}

// m6IndexOf is the index among m6Rows(out) of the line with exactly these
// fields; -1: none.
func m6IndexOf(out string, want []string) int {
	for i, r := range m6Rows(out) {
		if slices.Equal(r, want) {
			return i
		}
	}
	return -1
}

func m6WantRow(t *testing.T, what, out, line string) {
	t.Helper()
	if !m6HasRow(out, m6F(line)) {
		t.Errorf("%s: no line %q in\n%s", what, line, out)
	}
}

// m6Cat joins field lists.
func m6Cat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- formatBytes, formatAgo -------------------------------------------------

func TestM6FormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{1258291, "1.2 MiB"}, // 1.2 MiB of the plan sample
		{3355443, "3.2 MiB"},
		{1 << 30, "1.0 GiB"},
		{3 << 29, "1.5 GiB"},
	}
	for _, c := range cases {
		var got string
		m6Out(t, "formatBytes", func(io.Writer) { got = formatBytes(c.n) })
		if got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestM6FormatAgo(t *testing.T) {
	cases := []struct {
		ago  time.Duration
		want string
	}{
		{5 * time.Second, "5s ago"},
		{12 * time.Second, "12s ago"},
		{59 * time.Second, "59s ago"},
		{time.Minute, "1m 0s ago"},
		{3*time.Minute + 10*time.Second, "3m 10s ago"},
		{59*time.Minute + 59*time.Second, "59m 59s ago"},
		{time.Hour, "1h 0m ago"},
		{2*time.Hour + 5*time.Minute, "2h 5m ago"},
		{2*time.Hour + 5*time.Minute + 30*time.Second, "2h 5m ago"},
	}
	for _, c := range cases {
		var got string
		m6Out(t, "formatAgo", func(io.Writer) { got = formatAgo(m6Now.Add(-c.ago), m6Now) })
		if got != c.want {
			t.Errorf("formatAgo(now-%v) = %q, want %q", c.ago, got, c.want)
		}
	}
	var got string
	m6Out(t, "formatAgo", func(io.Writer) { got = formatAgo(time.Time{}, m6Now) })
	if got != "never" {
		t.Errorf("formatAgo(zero) = %q, want never", got)
	}

	// formatAgo doc: zero elapsed is "0s ago"; a t after now (clock skew)
	// counts as "0s ago".
	for _, d := range []time.Duration{0, time.Nanosecond, 3 * time.Second, 2 * time.Hour} {
		m6Out(t, "formatAgo", func(io.Writer) { got = formatAgo(m6Now.Add(d), m6Now) })
		if got != "0s ago" {
			t.Errorf("formatAgo(now+%v) = %q, want \"0s ago\"", d, got)
		}
	}
}

// --- printStatus --------------------------------------------------------------

// m6Status is the "wgplex status" sample of the M6 plan.
func m6Status() rpc.Status {
	return rpc.Status{
		Configured:   true,
		Icon:         "warn",
		ConfigErrors: []string{`tunnel "x": conf "x.conf" not found`},
		Warnings:     []string{`service "tg" is not used by any rule`},
		Tunnels: []rpc.TunnelStatus{
			{
				Name: "work", Enabled: true, State: "up", Interface: "utun5",
				Addresses: []string{"10.0.0.2/32"}, Routes: "config", RouteCount: 214,
				Peers: []rpc.PeerStatus{{
					Endpoint: "203.0.113.1:51820", Resolved: "203.0.113.1:51820",
					LastHandshake: m6Now.Add(-12 * time.Second), RxBytes: 1258291, TxBytes: 307200,
				}},
			},
			{Name: "home", Routes: "config", State: "off"},
			{
				Name: "de", Enabled: true, State: "up", Interface: "utun6", Routes: "rules", RouteCount: 3,
				Peers: []rpc.PeerStatus{{Endpoint: "vpn.example.net:51820", Resolved: "203.0.113.5:51820", TxBytes: 92}},
			},
			{
				Name: "bad", Enabled: true, State: "error", Routes: "config", RouteCount: 1,
				Error: "resolve endpoints: lookup bad.invalid: no such host",
			},
		},
		Rules: []rpc.RuleStatus{
			{Index: 0, Services: []string{"youtube", "telegram"}, Via: []string{"nl", "de"}, Fallback: "default", Tunnel: "de", Degraded: true},
			{Index: 1, Services: []string{"ai"}, Via: []string{"nl", "de"}, Fallback: "block", InFallback: true},
			{Index: 2, Services: []string{"corp"}, Fallback: "default"},
			{Index: 3, Services: []string{"tg"}, Via: []string{"nl", "de"}, Fallback: "default", Tunnel: "nl"},
			{Index: 4, Services: []string{"misc"}, Via: []string{"home"}, Fallback: "default", InFallback: true},
		},
	}
}

func TestM6PrintStatus(t *testing.T) {
	out := m6Out(t, "printStatus", func(w io.Writer) { printStatus(w, m6Status(), m6Now) })

	m6WantRow(t, "icon", out, "icon: warn")

	// The config error block: a "config error:" line, then the error.
	i := m6IndexOf(out, m6F("config error:"))
	rows := m6Rows(out)
	if i < 0 || i+1 >= len(rows) || !slices.Equal(rows[i+1], m6F(`tunnel "x": conf "x.conf" not found`)) {
		t.Errorf("no config error block in\n%s", out)
	}
	m6WantRow(t, "warning", out, `warning: service "tg" is not used by any rule`)

	m6WantRow(t, "tunnel header", out, "TUNNEL STATE IFACE HANDSHAKE CHECK RX TX ROUTES") // M11: CHECK (was PING in M7)
	m6WantRow(t, "work", out, "work up utun5 12s ago - "+formatBytes(1258291)+" "+formatBytes(307200)+" 214")
	m7WantOff(t, out, "home")
	m6WantRow(t, "de", out, "de up utun6 never - 0 B 92 B 3")

	// bad: state error, route count 1 and the error text last.
	bad := m6RowAt(out, "bad")
	errText := m6F("resolve endpoints: lookup bad.invalid: no such host")
	if len(bad) < 3+len(errText) || bad[1] != "error" || !slices.Contains(bad, "1") ||
		!slices.Equal(bad[len(bad)-len(errText):], errText) {
		t.Errorf("bad: line %q, want state error, routes 1 and the error at the end", bad)
	}

	m6WantRow(t, "rule header", out, "RULE SERVICES VIA →")
	m6WantRow(t, "rule 1", out, "#1 youtube,telegram nl,de de (degraded)")
	m6WantRow(t, "rule 2", out, "#2 ai nl,de block (fallback)")
	m6WantRow(t, "rule 3", out, "#3 corp - direct")
	m6WantRow(t, "rule 4", out, "#4 tg nl,de nl")
	m6WantRow(t, "rule 5", out, "#5 misc home default (fallback)")

	// Tunnels and rules keep the reply order.
	order := []string{"work", "home", "de", "bad", "#1", "#2", "#3", "#4", "#5"}
	last := -1
	for _, name := range order {
		idx := -1
		for j, r := range m6Rows(out) {
			if r[0] == name {
				idx = j
				break
			}
		}
		if idx <= last {
			t.Errorf("%s is out of order in\n%s", name, out)
		}
		last = idx
	}
}

// M6 plan: with several peers, HANDSHAKE is the latest handshake and RX, TX
// are the sums.
func TestM6PrintStatusSeveralPeers(t *testing.T) {
	s := rpc.Status{
		Configured: true,
		Icon:       "on",
		Tunnels: []rpc.TunnelStatus{{
			Name: "multi", Enabled: true, State: "up", Interface: "utun9", Routes: "config", RouteCount: 7,
			Peers: []rpc.PeerStatus{
				{Endpoint: "203.0.113.1:51820", LastHandshake: m6Now.Add(-3 * time.Minute), RxBytes: 1024, TxBytes: 100},
				{Endpoint: "203.0.113.2:51820", LastHandshake: m6Now.Add(-5 * time.Second), RxBytes: 512, TxBytes: 400},
				{Endpoint: ""}, // never, nothing
			},
		}},
		Rules: []rpc.RuleStatus{},
	}
	out := m6Out(t, "printStatus", func(w io.Writer) { printStatus(w, s, m6Now) })
	m6WantRow(t, "multi", out, "multi up utun9 5s ago - 1.5 KiB 500 B 7")
	m6WantRow(t, "icon", out, "icon: on")
	if strings.Contains(out, "config error") {
		t.Errorf("config error shown without errors:\n%s", out)
	}
	if strings.Contains(out, "warning:") {
		t.Errorf("warning shown without warnings:\n%s", out)
	}
}

// All peers never had a handshake: "never".
func TestM6PrintStatusNoHandshake(t *testing.T) {
	s := rpc.Status{
		Configured: true,
		Icon:       "on",
		Tunnels: []rpc.TunnelStatus{{
			Name: "fresh", Enabled: true, State: "up", Interface: "utun3", Routes: "rules",
			Peers: []rpc.PeerStatus{{Endpoint: "203.0.113.1:51820"}, {Endpoint: "203.0.113.2:51820"}},
		}},
	}
	out := m6Out(t, "printStatus", func(w io.Writer) { printStatus(w, s, m6Now) })
	m6WantRow(t, "fresh", out, "fresh up utun3 never - 0 B 0 B 0")
}

// M6 plan: without a config, "icon: off" and a hint; no tables.
func TestM6PrintStatusNoConfig(t *testing.T) {
	out := m6Out(t, "printStatus", func(w io.Writer) {
		printStatus(w, rpc.Status{Configured: false, Icon: "off"}, m6Now)
	})
	m6WantRow(t, "icon", out, "icon: off")
	m6WantRow(t, "hint", out, "no config applied (wgplex reload)")
	if strings.Contains(out, "config error") {
		t.Errorf("config error shown without errors:\n%s", out)
	}
}

// The first apply failed: no config, but the errors are shown (icon warn).
func TestM6PrintStatusNoConfigWithErrors(t *testing.T) {
	out := m6Out(t, "printStatus", func(w io.Writer) {
		printStatus(w, rpc.Status{Icon: "warn", ConfigErrors: []string{"wgplex.yaml: unknown key \"x\"", "second problem"}}, m6Now)
	})
	m6WantRow(t, "icon", out, "icon: warn")
	m6WantRow(t, "header", out, "config error:")
	m6WantRow(t, "error 1", out, `wgplex.yaml: unknown key "x"`)
	m6WantRow(t, "error 2", out, "second problem")
}

// --- printExplain -------------------------------------------------------------

func m6Rule(index int, services, via []string, tunnel string) *rpc.RuleStatus {
	return &rpc.RuleStatus{Index: index, Services: services, Via: via, Fallback: "default", Tunnel: tunnel}
}

func TestM6PrintExplainDomain(t *testing.T) {
	e := rpc.Explanation{
		Query: "ifconfig.me", Kind: "domain",
		Rule:     m6Rule(0, []string{"t-tun"}, []string{"de", "fi"}, "de"),
		Upstream: "de", Servers: []string{"1.0.0.1"}, DropAAAA: true,
		Addrs: []string{"34.160.111.145"},
	}
	out := m6Out(t, "printExplain", func(w io.Writer) { printExplain(w, e) })
	want := []string{
		"ifconfig.me: domain",
		"rule #1 [t-tun] via de,fi → de",
		"dns: tunnel de (1.0.0.1)",
		"aaaa: filtered",
		"addresses: 34.160.111.145",
	}
	rows := m6Rows(out)
	if len(rows) != len(want) {
		t.Errorf("printExplain = \n%s\nwant %d lines", out, len(want))
	}
	for i, l := range want {
		if i >= len(rows) || !slices.Equal(rows[i], m6F(l)) {
			t.Errorf("line %d: %q, want %q\n%s", i, rows, l, out)
			break
		}
	}
}

func TestM6PrintExplainDomainVariants(t *testing.T) {
	cases := []struct {
		name string
		e    rpc.Explanation
		want []string // lines that must be there
		not  []string // first fields of lines that must not be there
	}{
		{
			name: "system, no rule",
			e:    rpc.Explanation{Query: "example.net", Kind: "domain", Upstream: "system"},
			want: []string{"example.net: domain", "no rule", "dns: system"},
			not:  []string{"aaaa:", "skipped:", "rule"},
		},
		{
			name: "block",
			e: rpc.Explanation{
				Query: "chat.openai.com", Kind: "domain", Upstream: "block",
				Rule: &rpc.RuleStatus{Index: 1, Services: []string{"ai"}, Via: []string{"nl"}, Fallback: "block", InFallback: true},
			},
			want: []string{"chat.openai.com: domain", "dns: block (NODATA)"},
			not:  []string{"aaaa:", "no"},
		},
		{
			name: "dns_domains zone",
			e: rpc.Explanation{
				Query: "vault.corp.example", Kind: "domain", Upstream: "work",
				Zone: "corp.example", Servers: []string{"1.2.3.4"},
			},
			want: []string{"vault.corp.example: domain", "no rule", "dns: tunnel work (1.2.3.4), zone corp.example"},
		},
		{
			name: "skipped rule in fallback: default",
			e: rpc.Explanation{
				Query: "www.example.org", Kind: "domain", Upstream: "fi", Servers: []string{"1.1.1.1"},
				Rule:    m6Rule(4, []string{"org"}, []string{"fi"}, "fi"),
				Skipped: &rpc.RuleStatus{Index: 2, Services: []string{"x"}, Via: []string{"home"}, Fallback: "default", InFallback: true},
			},
			want: []string{
				"www.example.org: domain",
				"rule #5 [org] via fi → fi",
				"skipped: rule #3 [x] is in fallback: default",
				"dns: tunnel fi (1.1.1.1)",
			},
			not: []string{"aaaa:"},
		},
	}
	for _, c := range cases {
		out := m6Out(t, "printExplain", func(w io.Writer) { printExplain(w, c.e) })
		for _, l := range c.want {
			m6WantRow(t, c.name, out, l)
		}
		for _, first := range c.not {
			if r := m6RowAt(out, first); r != nil {
				t.Errorf("%s: unexpected line %q in\n%s", c.name, r, out)
			}
		}
	}
}

func TestM6PrintExplainIP(t *testing.T) {
	// The plan sample: a dynamic route of a rule.
	e := rpc.Explanation{
		Query: "34.160.111.145", Kind: "ip",
		Rule: m6Rule(0, []string{"t-tun"}, []string{"de", "fi"}, "de"),
		Route: &rpc.RouteInfo{
			Prefix: "34.160.111.145/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: 0,
			Names: []string{"ifconfig.me"},
		},
	}
	out := m6Out(t, "printExplain", func(w io.Writer) { printExplain(w, e) })
	m6WantRow(t, "dynamic", out, "34.160.111.145: ip")
	m6WantRow(t, "dynamic", out, "route 34.160.111.145/32 → tunnel de (dynamic, rule #1 [t-tun]); names: ifconfig.me")

	// No route: the system default route.
	out = m6Out(t, "printExplain", func(w io.Writer) {
		printExplain(w, rpc.Explanation{Query: "8.8.8.8", Kind: "ip"})
	})
	m6WantRow(t, "no route", out, "8.8.8.8: ip")
	m6WantRow(t, "no route", out, "no route: system default route")

	// A route not in the kernel: "; not in kernel: <reason>" at the end.
	reason := "a route not added by wgplex exists"
	out = m6Out(t, "printExplain", func(w io.Writer) {
		printExplain(w, rpc.Explanation{
			Query: "192.168.1.10", Kind: "ip",
			Rule:  &rpc.RuleStatus{Index: 2, Services: []string{"corp"}, Fallback: "default"},
			Route: &rpc.RouteInfo{Prefix: "192.168.1.0/24", Target: "direct", Source: "rule-cidr", Rule: 2, Skipped: reason},
		})
	})
	r := m6RowAt(out, "route")
	if r == nil || r[1] != "192.168.1.0/24" || !slices.Contains(r, "direct") ||
		!strings.HasSuffix(strings.Join(r, " "), "; not in kernel: "+reason) {
		t.Errorf("skipped route: line %q, want route 192.168.1.0/24 → direct … ; not in kernel: %s", r, reason)
	}

	// A route of AllowedIPs: no rule.
	out = m6Out(t, "printExplain", func(w io.Writer) {
		printExplain(w, rpc.Explanation{
			Query: "10.2.3.4", Kind: "ip",
			Route: &rpc.RouteInfo{Prefix: "10.0.0.0/8", Target: "tunnel", Tunnel: "work", Source: "allowed-ips", Rule: -1},
		})
	})
	r = m6RowAt(out, "route")
	line := strings.Join(r, " ")
	if r == nil || r[1] != "10.0.0.0/8" || !strings.Contains(line, "tunnel work") || !strings.Contains(line, "allowed-ips") ||
		strings.Contains(line, "rule #") || strings.Contains(line, "#0") || strings.Contains(line, "not in kernel") {
		t.Errorf("allowed-ips route: line %q", r)
	}
}

// --- printRoutes ----------------------------------------------------------------

func TestM6PrintRoutes(t *testing.T) {
	r := rpc.Routes{Routes: []rpc.RouteInfo{
		{Prefix: "10.0.0.0/8", Target: "tunnel", Tunnel: "work", Source: "allowed-ips", Rule: -1},
		{Prefix: "34.160.111.145/32", Target: "tunnel", Tunnel: "de", Source: "dynamic", Rule: 0, Names: []string{"ifconfig.me"}},
		{Prefix: "198.51.100.0/24", Target: "reject", Source: "rule-cidr", Rule: 1},
		{Prefix: "192.168.1.0/24", Target: "direct", Source: "rule-cidr", Rule: 2, Skipped: "a route not added by wgplex exists"},
		{Prefix: "203.0.113.5/32", Target: "direct", Source: "endpoint", Rule: -1},
	}}
	out := m6Out(t, "printRoutes", func(w io.Writer) { printRoutes(w, r) })
	want := []string{
		"PREFIX TARGET TUNNEL SOURCE RULE NOTE",
		"10.0.0.0/8 tunnel work allowed-ips -",
		"34.160.111.145/32 tunnel de dynamic #1 ifconfig.me",
		"198.51.100.0/24 reject - rule-cidr #2",
		"192.168.1.0/24 direct - rule-cidr #3 skipped: a route not added by wgplex exists",
		"203.0.113.5/32 direct - endpoint -",
	}
	rows := m6Rows(out)
	if len(rows) != len(want) {
		t.Errorf("printRoutes: %d lines, want %d:\n%s", len(rows), len(want), out)
	}
	for i, l := range want {
		if i >= len(rows) {
			t.Errorf("line %d missing, want %q", i, l)
		} else if !slices.Equal(rows[i], m6F(l)) {
			t.Errorf("line %d: %q, want %q", i, rows[i], l)
		}
	}
	if strings.Contains(out, "sync error") {
		t.Errorf("sync error shown without one:\n%s", out)
	}

	r.SyncError = "route add 10.0.0.0/8: file exists"
	out = m6Out(t, "printRoutes", func(w io.Writer) { printRoutes(w, r) })
	rows = m6Rows(out)
	if len(rows) == 0 || !slices.Equal(rows[len(rows)-1], m6F("sync error: route add 10.0.0.0/8: file exists")) {
		t.Errorf("no sync error line at the end:\n%s", out)
	}
}

// --- printApply -----------------------------------------------------------------

func TestM6PrintApply(t *testing.T) {
	out := m6Out(t, "printApply", func(w io.Writer) {
		printApply(w, rpc.ApplyResult{
			Warnings: []string{`service "tg" is not used by any rule`, "tunnel de: DNS 1.0.0.1 is inside 1.0.0.0/24 of rule #1 with fallback: block"},
			Tunnels:  []rpc.TunnelError{{Name: "bad", Error: "resolve endpoints: lookup bad.invalid: no such host"}},
		})
	})
	rows := m6Rows(out)
	want := []string{
		`warning: service "tg" is not used by any rule`,
		"warning: tunnel de: DNS 1.0.0.1 is inside 1.0.0.0/24 of rule #1 with fallback: block",
		"tunnel bad: resolve endpoints: lookup bad.invalid: no such host",
		"config applied",
	}
	if len(rows) != len(want) {
		t.Fatalf("printApply:\n%s\nwant %d lines", out, len(want))
	}
	for i, l := range want {
		if !slices.Equal(rows[i], m6F(l)) {
			t.Errorf("line %d: %q, want %q", i, rows[i], l)
		}
	}

	out = m6Out(t, "printApply", func(w io.Writer) { printApply(w, rpc.ApplyResult{}) })
	if rows := m6Rows(out); len(rows) != 1 || !slices.Equal(rows[0], m6F("config applied")) {
		t.Errorf("clean apply: %q, want only \"config applied\"", out)
	}
}

// --- printError -----------------------------------------------------------------

// m6WireError is a JSON-RPC error as the client decodes it from the wire:
// data is generic JSON.
func m6WireError(t *testing.T, code int, message string, data any) *jrpc.JRPCError {
	t.Helper()
	js, err := json.Marshal(jrpc.JRPCError{Code: code, Message: message, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	var e jrpc.JRPCError
	if err := json.Unmarshal(js, &e); err != nil {
		t.Fatal(err)
	}
	return &e
}

// design 12, M6 plan: config errors one per line under "config error:",
// then the warnings.
func TestM6PrintErrorConfigInvalid(t *testing.T) {
	e := m6WireError(t, rpc.CodeConfigInvalid, "config is invalid", rpc.ConfigErrorData{
		Errors:   []string{`tunnel "x": conf "x.conf" not found`, `wgplex.yaml: unknown key "foo"`},
		Warnings: []string{`service "tg" is not used by any rule`},
	})
	for _, err := range []error{e, fmt.Errorf("config.apply: %w", e)} {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, err) })
		hdr := m6IndexOf(out, m6F("config error:"))
		e1 := m6IndexOf(out, m6F(`tunnel "x": conf "x.conf" not found`))
		e2 := m6IndexOf(out, m6F(`wgplex.yaml: unknown key "foo"`))
		if hdr < 0 || e1 <= hdr || e2 <= hdr {
			t.Errorf("printError(%v): want \"config error:\" and each error on its own line after it:\n%s", err, out)
		}
		if !strings.Contains(out, `service "tg" is not used by any rule`) {
			t.Errorf("printError: warning missing:\n%s", out)
		}
	}
}

// Other daemon errors: the message (and, for Internal error, its data with
// the error text) is shown.
func TestM6PrintErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{m6WireError(t, rpc.CodeNoConfig, "no config applied", nil), "no config applied"},
		{m6WireError(t, rpc.CodeUnknownTunnel, "unknown tunnel \"nosuch\"", nil), "unknown tunnel"},
		{m6WireError(t, rpc.CodeTunnelStart, "resolve endpoints: lookup bad.invalid: no such host", nil), "resolve endpoints: lookup bad.invalid: no such host"},
		{m6WireError(t, -32602, "Invalid params", nil), "Invalid params"},
		{m6WireError(t, -32603, "Internal error", "sync: boom"), "sync: boom"},
		{errors.New("something else"), "something else"},
	}
	for _, c := range cases {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, c.err) })
		if !strings.Contains(out, c.want) {
			t.Errorf("printError(%v) = %q, want it to contain %q", c.err, out, c.want)
		}
	}
}

// design 13, M6 plan: HTTP 403 is "permission denied: ...".
func TestM6PrintErrorForbidden(t *testing.T) {
	for _, err := range []error{
		&httpError{Code: http.StatusForbidden, Body: "forbidden"},
		fmt.Errorf("status.get: %w", &httpError{Code: http.StatusForbidden, Body: "forbidden"}),
	} {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, err) })
		if !strings.HasPrefix(strings.TrimSpace(out), "permission denied") {
			t.Errorf("printError(403) = %q, want \"permission denied: ...\"", out)
		}
	}
	out := m6Out(t, "printError", func(w io.Writer) {
		printError(w, &httpError{Code: http.StatusRequestEntityTooLarge, Body: "Request Entity Too Large"})
	})
	if strings.TrimSpace(out) == "" || strings.HasPrefix(strings.TrimSpace(out), "permission denied") {
		t.Errorf("printError(413) = %q", out)
	}
}

// M6 plan: no socket file is "wgplex daemon is not running": the bare dial error
// and the same error through an HTTP client over the unix socket.
func TestM6PrintErrorNotRunning(t *testing.T) {
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "none.sock")

	_, dialErr := net.Dial("unix", sock)
	if dialErr == nil {
		t.Fatal("dial of a missing socket succeeded")
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	_, httpErr := client.Post("http://wgplex"+rpc.Path, "application/json", strings.NewReader("{}"))
	if httpErr == nil {
		t.Fatal("POST to a missing socket succeeded")
	}
	for _, err := range []error{dialErr, httpErr, fmt.Errorf("status.get: %w", httpErr)} {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, err) })
		if !strings.Contains(out, "wgplex daemon is not running") {
			t.Errorf("printError(%v) = %q, want \"wgplex daemon is not running\"", err, out)
		}
	}
}

// M6 plan (printError): a socket file nobody listens on (stale after a
// crash) gives ECONNREFUSED on dial: "wgplex daemon is not running" too.
func TestM6PrintErrorConnRefused(t *testing.T) {
	dir, err := os.MkdirTemp("", "wgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "stale.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()

	_, dialErr := net.Dial("unix", sock)
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		t.Fatalf("dial of a stale socket: %v, want ECONNREFUSED", dialErr)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	_, httpErr := client.Post("http://wgplex"+rpc.Path, "application/json", strings.NewReader("{}"))
	if httpErr == nil {
		t.Fatal("POST to a stale socket succeeded")
	}
	for _, err := range []error{dialErr, httpErr, fmt.Errorf("status.get: %w", httpErr)} {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, err) })
		if !strings.Contains(out, "wgplex daemon is not running") {
			t.Errorf("printError(%v) = %q, want \"wgplex daemon is not running\"", err, out)
		}
	}
}

// M6 plan (printError, review step 3): "wgplex daemon is not running" is only
// for the socket. ENOENT of something else (wgplex -config /nonexistent reload)
// prints the error itself.
func TestM6PrintErrorNotSocketENOENT(t *testing.T) {
	errs := []error{
		fmt.Errorf("read config: %w", &fs.PathError{Op: "open", Path: "/nonexistent", Err: fs.ErrNotExist}),
		fmt.Errorf("read config: %w", &fs.PathError{Op: "open", Path: "/nonexistent", Err: syscall.ENOENT}),
	}
	for _, err := range errs {
		out := m6Out(t, "printError", func(w io.Writer) { printError(w, err) })
		if strings.Contains(out, "not running") {
			t.Errorf("printError(%v) = %q, want the error, not \"not running\"", err, out)
		}
		if !strings.Contains(out, "/nonexistent") {
			t.Errorf("printError(%v) = %q, want it to contain the path", err, out)
		}
	}
}

// --- M7: PING, dead -------------------------------------------------------------

// Tests below follow design 11, 12 and the M7 plan ("Статус", "cmd/wf",
// decision 10): the PING (CHECK since M11) column between HANDSHAKE and RX, state "dead" with
// its reason at the end of the line, as the error of "error".

// m7WantOff checks the line of an off tunnel: its name, "off", and no data
// (a PING "-" for a tunnel without a check result is allowed).
func m7WantOff(t *testing.T, out, name string) {
	t.Helper()
	r := m6RowAt(out, name)
	if len(r) < 2 || r[1] != "off" {
		t.Errorf("%s: line %q, want \"%s off\"", name, r, name)
		return
	}
	for _, f := range r[2:] {
		if f != "-" {
			t.Errorf("%s: line %q, want only the name and off", name, r)
			return
		}
	}
}

// m7Status is the "wgplex status" sample of the M7 plan and the other PING
// forms: "-" without check, "<RTT>ms" with Fails 0 and a LastOK, "fail N"
// with Fails > 0, "?" before the first ping.
func m7Status() rpc.Status {
	return rpc.Status{
		Configured: true,
		Icon:       "warn",
		Tunnels: []rpc.TunnelStatus{
			{
				Name: "work", Enabled: true, State: "up", Interface: "utun5", Routes: "config", RouteCount: 214,
				Peers: []rpc.PeerStatus{{LastHandshake: m6Now.Add(-12 * time.Second), RxBytes: 1258291, TxBytes: 307200}},
			},
			{
				Name: "de", Enabled: true, State: "dead", Interface: "utun6", Routes: "rules", RouteCount: 3,
				Reason: "ping 1.1.1.1: 3 failures",
				Check:  &rpc.CheckStatus{Addr: "1.1.1.1", LastOK: m6Now.Add(-5 * time.Minute), RTTMs: 20, Fails: 3},
				Peers:  []rpc.PeerStatus{{LastHandshake: m6Now.Add(-(4*time.Minute + 2*time.Second)), TxBytes: 92}},
			},
			{
				Name: "fi", Enabled: true, State: "up", Interface: "utun7", Routes: "rules", RouteCount: 3,
				Check: &rpc.CheckStatus{Addr: "1.1.1.1", LastOK: m6Now.Add(-3 * time.Second), RTTMs: 34},
				Peers: []rpc.PeerStatus{{LastHandshake: m6Now.Add(-8 * time.Second), RxBytes: 5120, TxBytes: 2048}},
			},
			{
				Name: "flaky", Enabled: true, State: "up", Interface: "utun8", Routes: "rules", RouteCount: 1,
				Check: &rpc.CheckStatus{Addr: "10.0.0.1", LastOK: m6Now.Add(-30 * time.Second), RTTMs: 15, Fails: 2},
				Peers: []rpc.PeerStatus{{LastHandshake: m6Now.Add(-time.Minute), RxBytes: 1, TxBytes: 2}},
			},
			{
				Name: "new", Enabled: true, State: "up", Interface: "utun9", Routes: "rules", RouteCount: 0,
				Check: &rpc.CheckStatus{Addr: "10.0.0.1"},
				Peers: []rpc.PeerStatus{{}},
			},
			{
				Name: "dead6", Enabled: true, State: "dead", Interface: "utun10", Routes: "rules", RouteCount: 0,
				Reason: "no handshake for 3m10s while sending",
				Peers:  []rpc.PeerStatus{{TxBytes: 1480}},
			},
			{Name: "home", Routes: "config", State: "off"},
		},
		Rules: []rpc.RuleStatus{
			{Index: 0, Services: []string{"t-tun"}, Via: []string{"de", "fi"}, Fallback: "default", Tunnel: "fi", Degraded: true},
		},
	}
}

func TestM7PrintStatusPing(t *testing.T) {
	out := m6Out(t, "printStatus", func(w io.Writer) { printStatus(w, m7Status(), m6Now) })

	m6WantRow(t, "tunnel header", out, "TUNNEL STATE IFACE HANDSHAKE CHECK RX TX ROUTES")
	// The plan sample.
	m6WantRow(t, "work", out, "work up utun5 12s ago - 1.2 MiB 300.0 KiB 214")
	m6WantRow(t, "de", out, "de dead utun6 4m 2s ago fail 3 0 B 92 B 3 ping 1.1.1.1: 3 failures")
	m6WantRow(t, "fi", out, "fi up utun7 8s ago 34ms 5.0 KiB 2.0 KiB 3")
	// Fails > 0 wins over an earlier success.
	m6WantRow(t, "flaky", out, "flaky up utun8 1m 0s ago fail 2 1 B 2 B 1")
	// A check without any ping yet.
	m6WantRow(t, "new", out, "new up utun9 never ? 0 B 0 B 0")
	// Dead by the passive check, no check address: "-" and the reason.
	m6WantRow(t, "dead6", out, "dead6 dead utun10 never - 0 B "+formatBytes(1480)+" 0 no handshake for 3m10s while sending")
	m7WantOff(t, out, "home")
	m6WantRow(t, "icon", out, "icon: warn")
	m6WantRow(t, "rule", out, "#1 t-tun de,fi fi (degraded)")
}

// --- M11: CHECK with a URL ---------------------------------------------------

// design 12, M11 plan ("internal/rpc, cmd/wf"): the column is CHECK, its
// values are as of PING (RTT, "fail N", "?", "-") also for an HTTP check;
// CheckStatus.Addr (here a URL) is not in the column; the reason of a dead
// HTTP check is at the end of the line.
func TestM11PrintStatusCheckURL(t *testing.T) {
	st := rpc.Status{
		Configured: true,
		Icon:       "warn",
		Tunnels: []rpc.TunnelStatus{
			{
				Name: "fi", Enabled: true, State: "dead", Interface: "utun7", Routes: "rules", RouteCount: 3,
				Reason: "http https://10.255.255.1/: 3 failures (context deadline exceeded)",
				Check:  &rpc.CheckStatus{Addr: "https://10.255.255.1/", Fails: 3},
				Peers:  []rpc.PeerStatus{{LastHandshake: m6Now.Add(-8 * time.Second), RxBytes: 5120, TxBytes: 2048}},
			},
			{
				Name: "nl", Enabled: true, State: "up", Interface: "utun8", Routes: "rules", RouteCount: 2,
				Check: &rpc.CheckStatus{Addr: "https://cloudflare.com/", LastOK: m6Now.Add(-3 * time.Second), RTTMs: 87},
				Peers: []rpc.PeerStatus{{LastHandshake: m6Now.Add(-8 * time.Second), RxBytes: 1, TxBytes: 2}},
			},
			{
				Name: "de", Enabled: true, State: "up", Interface: "utun9", Routes: "rules", RouteCount: 0,
				Check: &rpc.CheckStatus{Addr: "http://example.com/health"},
				Peers: []rpc.PeerStatus{{}},
			},
		},
	}
	out := m6Out(t, "printStatus", func(w io.Writer) { printStatus(w, st, m6Now) })

	m6WantRow(t, "tunnel header", out, "TUNNEL STATE IFACE HANDSHAKE CHECK RX TX ROUTES")
	m6WantRow(t, "fi", out, "fi dead utun7 8s ago fail 3 5.0 KiB 2.0 KiB 3 http https://10.255.255.1/: 3 failures (context deadline exceeded)")
	m6WantRow(t, "nl", out, "nl up utun8 8s ago 87ms 1 B 2 B 2")
	m6WantRow(t, "de", out, "de up utun9 never ? 0 B 0 B 0")
	if strings.Contains(out, "PING") {
		t.Errorf("output still has PING:\n%s", out)
	}
	for _, u := range []string{"https://cloudflare.com/", "http://example.com/health"} {
		if strings.Contains(out, u) {
			t.Errorf("CHECK column shows the URL %s, want only RTT/fail/?:\n%s", u, out)
		}
	}
}
