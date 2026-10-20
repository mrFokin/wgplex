package config

import (
	"net/url"
	"strings"
	"testing"
)

// Tests follow design 8 "HTTP", 9.2 and the M11 plan ("Модель → HTTP-проверка",
// "Сигнатуры → internal/config"), not the implementation: check is an IP
// address (Check) or an http/https URL with a host, without userinfo and
// fragment (CheckURL = url.Parse(..).String() with scheme and host lower-cased); at most one of them is set.

// m11CheckYAML is a one-tunnel config with the given check line value.
func m11CheckYAML(check string) string {
	return `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    check: ` + check + `
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl]
`
}

func m11Confs(t *testing.T) map[string]string {
	return map[string]string{"nl.conf": simpleConf(t)}
}

// design 9.2: valid check values.
func TestM11CheckValid(t *testing.T) {
	cases := []struct {
		name string
		yaml string // the YAML value
		ip   string // want Check; "" — zero
		url  string // want CheckURL = url.Parse(url).String(); "" — none
	}{
		{name: "IPv4", yaml: "1.1.1.1", ip: "1.1.1.1"},
		{name: "IPv6", yaml: `"2606:4700:4700::1111"`, ip: "2606:4700:4700::1111"},
		{name: "http IP", yaml: `"http://10.0.0.1/"`, url: "http://10.0.0.1/"},
		{name: "https name", yaml: `"https://example.com/"`, url: "https://example.com/"},
		{name: "no path", yaml: `"https://example.com"`, url: "https://example.com"},
		{name: "path, port, query", yaml: `"https://example.com:8443/health/x?a=1&b=2"`, url: "https://example.com:8443/health/x?a=1&b=2"},
		{name: "http port", yaml: `"http://192.0.2.10:8080/ping"`, url: "http://192.0.2.10:8080/ping"},
		{name: "IPv6 literal", yaml: `"https://[2001:db8::1]/"`, url: "https://[2001:db8::1]/"},
		{name: "IPv6 literal with port", yaml: `"http://[2001:db8::1]:8080/"`, url: "http://[2001:db8::1]:8080/"},
		// Scheme and host are case-insensitive; the stored form is URL.String().
		{name: "upper case scheme and host", yaml: `"HTTPS://Example.COM/Path"`, url: "https://example.com/Path"}, // scheme and host lower-cased (plan: case-insensitive)
		{name: "Http", yaml: `"Http://example.com/"`, url: "Http://example.com/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := mustLoad(t, filesOf(m11CheckYAML(c.yaml), m11Confs(t)))
			tn := tunnelByName(t, cfg, "nl")
			if c.ip != "" {
				if tn.Check != addr(c.ip) {
					t.Errorf("Check = %v, want %s", tn.Check, c.ip)
				}
			} else if tn.Check.IsValid() {
				t.Errorf("Check = %v, want zero with a URL", tn.Check)
			}
			want := ""
			if c.url != "" {
				u, err := url.Parse(c.url)
				if err != nil {
					t.Fatalf("fixture URL: %v", err)
				}
				want = u.String()
			}
			if tn.CheckURL != want {
				t.Errorf("CheckURL = %q, want %q", tn.CheckURL, want)
			}
		})
	}
}

// design 9.2: a tunnel without check has neither Check nor CheckURL.
func TestM11CheckNone(t *testing.T) {
	cfg, _ := mustLoad(t, filesOf(baseYAML, baseConfs(t)))
	for _, tn := range cfg.Tunnels {
		if tn.Check.IsValid() || tn.CheckURL != "" {
			t.Errorf("%s: Check %v CheckURL %q, want none", tn.Name, tn.Check, tn.CheckURL)
		}
	}
}

// design 9.2, M11 plan: a URL check must be http/https with a host, without
// userinfo or fragment; anything else is a config error mentioning check and
// the value (`<where>: check: invalid URL %q: <reason>`).
func TestM11CheckInvalid(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // substrings of the error text
	}{
		{name: "ftp scheme", yaml: `"ftp://example.com/"`, want: []string{"check", "ftp://example.com/"}},
		{name: "ws scheme", yaml: `"ws://example.com/"`, want: []string{"check", "ws://example.com/"}},
		{name: "no host", yaml: `"https://"`, want: []string{"check", "https://"}},
		{name: "no host, path", yaml: `"http:///health"`, want: []string{"check", "http:///health"}},
		{name: "userinfo", yaml: `"https://user@example.com/"`, want: []string{"check", "example.com"}},
		{name: "userinfo with password", yaml: `"https://user:secret@example.com/"`, want: []string{"check", "example.com"}},
		{name: "fragment", yaml: `"https://example.com/#top"`, want: []string{"check", "example.com"}},
		{name: "space in host", yaml: `"https://exa mple.com/"`, want: []string{"check", "exa mple.com"}},
		{name: "unclosed IPv6 bracket", yaml: `"http://[2001:db8::1/"`, want: []string{"check", "2001:db8::1"}},
		{name: "bad port", yaml: `"https://example.com:http/"`, want: []string{"check", "example.com"}},
		{name: "empty scheme", yaml: `"://example.com/"`, want: []string{"check", "example.com"}},
		// Without "://" the value is an IP address, and it is not one.
		{name: "bare host name", yaml: "example.com", want: []string{"check", "example.com"}},
		{name: "host:port", yaml: `"example.com:443"`, want: []string{"check", "example.com:443"}},
		{name: "mailto", yaml: `"mailto:a@example.com"`, want: []string{"check", "mailto:a@example.com"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := mustFail(t, filesOf(m11CheckYAML(c.yaml), m11Confs(t)))
			if missing := errorsMention(errs, c.want...); len(missing) > 0 {
				t.Errorf("error text does not mention %q:\n%v", missing, errs)
			}
			if !strings.Contains(errs.Error(), "nl") {
				t.Errorf("error text does not name the tunnel nl:\n%v", errs)
			}
		})
	}
}

// design 9.2: errors are collected; a bad check URL in one tunnel and a bad
// check IP in another are both reported.
func TestM11CheckInvalidCollected(t *testing.T) {
	yaml := `
tunnels:
  - name: nl
    conf: nl.conf
    routes: rules
    check: "ftp://example.com/"
  - name: de
    conf: de.conf
    routes: rules
    check: gateway.local
services:
  youtube:
    domains: [youtube.com]
rules:
  - services: [youtube]
    via: [nl, de]
`
	errs := mustFail(t, filesOf(yaml, baseConfs(t)))
	if missing := errorsMention(errs, "ftp://example.com/", "gateway.local"); len(missing) > 0 {
		t.Errorf("error text does not mention %q:\n%v", missing, errs)
	}
}
