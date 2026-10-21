package config

import (
	"strings"
	"testing"
)

// Tests follow design 9 "HTTP", 10.1 and the Wirefork M11 review (step 4, items 5, 6):
// a check URL with userinfo is a config error whose text does not reveal the
// password, also when the rest of the URL does not parse; a host with an
// IPv6 zone is a config error.

// design 10.1, review item 5: the password of a check URL never appears in
// the error text.
func TestM11CheckURLPasswordHidden(t *testing.T) {
	const secret = "s3cr3tPassw0rd"
	cases := []struct {
		name string
		yaml string
	}{
		{"parsable", `"https://u:` + secret + `@example.com/"`},
		{"unparsable escape", `"https://u:` + secret + `@example.com/%zz"`},
		{"unparsable port", `"https://u:` + secret + `@example.com:bad/"`},
		{"http, no path", `"http://u:` + secret + `@10.0.0.1"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := mustFail(t, filesOf(m11CheckYAML(c.yaml), m11Confs(t)))
			text := errs.Error()
			if strings.Contains(text, secret) {
				t.Errorf("error text reveals the password:\n%v", text)
			}
			if missing := errorsMention(errs, "check"); len(missing) > 0 {
				t.Errorf("error text does not mention check:\n%v", text)
			}
			if !strings.Contains(text, "nl") {
				t.Errorf("error text does not name the tunnel nl:\n%v", text)
			}
		})
	}
}

// design 9 "HTTP", review item 6: a zone in the IPv6 literal host of a check
// URL is a config error (the check goes through the utun, not a link).
func TestM11CheckURLIPv6Zone(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"http zone", `"http://[fe80::1%25en0]/"`},
		{"https zone, port", `"https://[fe80::1%25en0]:8443/x"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := mustFail(t, filesOf(m11CheckYAML(c.yaml), m11Confs(t)))
			if missing := errorsMention(errs, "check", "nl"); len(missing) > 0 {
				t.Errorf("error text does not mention %q:\n%v", missing, errs)
			}
		})
	}
}

// design 10.1, review item 5 (plan step 6 (b)): a password containing '/',
// '?' or '#' makes the URL split inside the userinfo; neither the whole
// password nor its distinctive leading part appears in the error text.
func TestM11CheckURLPasswordWithDelimiters(t *testing.T) {
	cases := []struct {
		name, head, sep, tail, rest string
	}{
		{"slash", "Qh7s3cr", "/", "Zk9tail", "@example.com/"},
		{"slash, path and query", "Wm4s3cr", "/", "Yp2tail", "@example.com/health?x=1"},
		{"question", "Rt5s3cr", "?", "Xv8tail", "@example.com/"},
		{"hash", "Jn6s3cr", "#", "Lb3tail", "@example.com/"},
		{"slash and hash, IP host", "Kd2s3cr", "/", "Fg5ta#il", "@10.0.0.1:8080/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret := c.head + c.sep + c.tail
			yaml := `"https://u:` + secret + c.rest + `"`
			errs := mustFail(t, filesOf(m11CheckYAML(yaml), m11Confs(t)))
			text := errs.Error()
			for _, s := range []string{secret, c.head} {
				if strings.Contains(text, s) {
					t.Errorf("error text reveals the password part %q:\n%v", s, text)
				}
			}
			if missing := errorsMention(errs, "check", "nl"); len(missing) > 0 {
				t.Errorf("error text does not mention %q:\n%v", missing, text)
			}
		})
	}
}
