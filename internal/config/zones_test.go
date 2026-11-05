package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Tests follow docs/design.md section 8 ("Точечный захват") and the M4 plan
// (decisions 2 and 3), not the implementation: Zones lists the domains of the
// services named by rules and the dns_domains of tunnels; MaxZones bounds it.

func dom(name string, exact bool) Domain { return Domain{Name: name, Exact: exact} }

func TestZones(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want []string
	}{
		{name: "nil config", cfg: nil, want: nil},
		{name: "empty config", cfg: &Config{}, want: nil},
		{
			// design 8: "=example.com" gives the zone example.com
			name: "exact and suffix give the same zone",
			cfg: &Config{
				Services: map[string]Service{
					"a": {Domains: []Domain{dom("example.com", true)}},
					"b": {Domains: []Domain{dom("example.com", false)}},
				},
				Rules: []Rule{{Services: []string{"a"}}, {Services: []string{"b"}}},
			},
			want: []string{"example.com"},
		},
		{
			name: "exact only",
			cfg: &Config{
				Services: map[string]Service{"a": {Domains: []Domain{dom("api.example.com", true)}}},
				Rules:    []Rule{{Services: []string{"a"}}},
			},
			want: []string{"api.example.com"},
		},
		{
			// design 8: a service no rule names does not count
			name: "service without rule",
			cfg: &Config{
				Services: map[string]Service{"a": {Domains: []Domain{dom("example.com", false)}}},
			},
			want: nil,
		},
		{
			name: "cidr-only service in a rule",
			cfg: &Config{
				Services: map[string]Service{"a": {}},
				Rules:    []Rule{{Services: []string{"a"}}},
			},
			want: nil,
		},
		{
			// design 8: dns_domains of tunnels are zones
			name: "tunnel dns_domains",
			cfg: &Config{
				Tunnels: []Tunnel{{Name: "work", DNSDomains: []Domain{dom("corp.example", false)}}},
			},
			want: []string{"corp.example"},
		},
		{
			name: "rules and dns_domains merged and sorted",
			cfg: &Config{
				Tunnels: []Tunnel{{Name: "work", DNSDomains: []Domain{dom("zzz.corp", false), dom("aaa.corp", false)}}},
				Services: map[string]Service{
					"s": {Domains: []Domain{dom("mmm.com", false), dom("bbb.com", true)}},
				},
				Rules: []Rule{{Services: []string{"s"}}},
			},
			want: []string{"aaa.corp", "bbb.com", "mmm.com", "zzz.corp"},
		},
		{
			name: "duplicates across services, rules and tunnels",
			cfg: &Config{
				Tunnels: []Tunnel{
					{Name: "a", DNSDomains: []Domain{dom("corp.example", false)}},
					{Name: "b", DNSDomains: []Domain{dom("corp.example", false)}},
				},
				Services: map[string]Service{
					"s1": {Domains: []Domain{dom("corp.example", true), dom("x.com", false)}},
					"s2": {Domains: []Domain{dom("x.com", false)}},
				},
				Rules: []Rule{{Services: []string{"s1", "s2"}}, {Services: []string{"s1"}}},
			},
			want: []string{"corp.example", "x.com"},
		},
		{
			// design 8: lowercase, no trailing dot
			name: "case and trailing dot normalized",
			cfg: &Config{
				Tunnels: []Tunnel{{Name: "a", DNSDomains: []Domain{dom("Corp.Example.", false)}}},
				Services: map[string]Service{
					"s": {Domains: []Domain{dom("EXAMPLE.com", false), dom("example.com.", true)}},
				},
				Rules: []Rule{{Services: []string{"s"}}},
			},
			want: []string{"corp.example", "example.com"},
		},
		{
			// a longer name is a different zone, not folded into a suffix
			name: "suffix and subdomain stay separate",
			cfg: &Config{
				Services: map[string]Service{"s": {Domains: []Domain{dom("example.com", false), dom("www.example.com", false)}}},
				Rules:    []Rule{{Services: []string{"s"}}},
			},
			want: []string{"example.com", "www.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Zones()
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Zones() = %v, want %v", got, tc.want)
			}
		})
	}
}

// design 8 / M4 decision 2: NeedsDNS is exactly "there are zones".
func TestNeedsDNSMatchesZones(t *testing.T) {
	cfgs := []*Config{
		nil,
		{},
		{Tunnels: []Tunnel{{Name: "a", DNSDomains: []Domain{dom("x.corp", false)}}}},
		{
			Services: map[string]Service{"s": {Domains: []Domain{dom("x.com", false)}}},
			Rules:    []Rule{{Services: []string{"s"}}},
		},
		{Services: map[string]Service{"s": {Domains: []Domain{dom("x.com", false)}}}},
	}
	for i, c := range cfgs {
		if got, want := c.NeedsDNS(), len(c.Zones()) > 0; got != want {
			t.Errorf("config %d: NeedsDNS() = %v, len(Zones()) > 0 = %v", i, got, want)
		}
	}
}

// design 8: zones come from the parsed YAML the same way.
func TestZonesFromLoad(t *testing.T) {
	const yaml = `
tunnels:
  - name: work
    conf: work.conf
    routes: rules
    dns_domains: [Corp.Example]
services:
  yt:
    domains: [YouTube.com, "=api.youtube.com"]
  unused:
    domains: [unused.example]
rules:
  - services: [yt]
    via: [work]
`
	cfg, _, err := Load(map[string][]byte{
		mainFile:    []byte(yaml),
		"work.conf": []byte(simpleConf(t)),
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"api.youtube.com", "corp.example", "youtube.com"}
	if got := cfg.Zones(); !reflect.DeepEqual(got, want) {
		t.Errorf("Zones() = %v, want %v", got, want)
	}
}

func TestMaxZonesValue(t *testing.T) {
	// design 8: the limit is 1000 zones
	if MaxZones != 1000 {
		t.Errorf("MaxZones = %d, want 1000", MaxZones)
	}
}

// zonesYAML is a config whose rule names a service with the given domains.
func zonesYAML(domains []string) string {
	var b strings.Builder
	b.WriteString("tunnels:\n  - name: work\n    conf: work.conf\n    routes: rules\n")
	b.WriteString("services:\n  big:\n    domains:\n")
	for _, d := range domains {
		fmt.Fprintf(&b, "      - %q\n", d)
	}
	b.WriteString("rules:\n  - services: [big]\n    via: [work]\n")
	return b.String()
}

func nDomains(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("z%04d.example.test", i)
	}
	return out
}

// design 8, 10.1: more than 1000 zones is a config error (LoadDir); 1000 is fine.
func TestLoadDirZoneLimit(t *testing.T) {
	stubGroups(t, "admin")
	for _, tc := range []struct {
		name    string
		n       int
		wantErr bool
	}{
		{"1000 zones", MaxZones, false},
		{"1001 zones", MaxZones + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeDir(t, map[string]string{
				mainFile:    zonesYAML(nDomains(tc.n)),
				"work.conf": simpleConf(t),
			}, nil)
			cfg, _, err := LoadDir(dir)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("LoadDir: unexpected error: %v", err)
				}
				if got := len(cfg.Zones()); got != tc.n {
					t.Errorf("len(Zones()) = %d, want %d", got, tc.n)
				}
				return
			}
			if err == nil {
				t.Fatal("LoadDir: expected an error for 1001 zones, got nil")
			}
			if cfg != nil {
				t.Error("LoadDir: cfg must be nil on error")
			}
			// M4 decision 3: the message gives the number of zones
			if !strings.Contains(err.Error(), fmt.Sprint(tc.n)) {
				t.Errorf("error should mention %d zones, got: %v", tc.n, err)
			}
		})
	}
}

// Duplicates do not count towards the limit: 1001 names, 1000 distinct zones.
func TestLoadDirZoneLimitCountsDistinct(t *testing.T) {
	stubGroups(t, "admin")
	domains := append(nDomains(MaxZones), "=z0000.example.test")
	dir := writeDir(t, map[string]string{
		mainFile:    zonesYAML(domains),
		"work.conf": simpleConf(t),
	}, nil)
	if _, _, err := LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: 1000 distinct zones with one duplicate name must pass: %v", err)
	}
}
