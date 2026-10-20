package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// build validates raw against the parsed .conf files and produces the final
// Config (design 9.2): unique tunnel and service names, existing conf files,
// rule references to existing services and tunnels, valid domains and CIDRs,
// DNS present in .conf for tunnels with dns_domains, no "=" in dns_domains,
// one .conf per tunnel, required routes, no /0 in AllowedIPs with routes: config,
// defaults (ipv6_filter: true, autostart: false, fallback: default). Every error is collected rather than
// stopping at the first one.
//
// Beyond design 9.2: a tunnel name must be non-empty, check must be an IP
// address or an http(s) URL (parseCheckURL), a rule must list at least one service. Errors and warnings are
// prefixed with their location ("tunnel work: ...", "work.conf: line 3: ...").
// Service uniqueness is enforced by the YAML decoder (duplicate mapping keys).
// conf must be a bare file name (design 9.3). A .conf file referenced by several
// tunnels is an error for every tunnel after the first and is parsed only for
// the first one, so its own errors are not repeated.
func build(raw *rawConfig, files map[string][]byte) (cfg *Config, warnings []string, errs []error) {
	errf := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	cfg = &Config{IPv6Filter: true, Services: map[string]Service{}}
	if raw.IPv6Filter != nil {
		cfg.IPv6Filter = *raw.IPv6Filter
	}

	tunnels := map[string]bool{}
	confOwner := map[string]string{} // conf file -> where of the first tunnel using it
	for i, rt := range raw.Tunnels {
		where := fmt.Sprintf("tunnel %q", rt.Name)
		if rt.Name == "" {
			where = fmt.Sprintf("tunnel #%d", i+1)
			errf("%s: name is required", where)
		} else if tunnels[rt.Name] {
			errf("%s: duplicate tunnel name", where)
		}
		tunnels[rt.Name] = true

		t := Tunnel{Name: rt.Name, Routes: RouteMode(rt.Routes)}
		switch t.Routes {
		case RoutesConfig, RoutesRules:
		case "":
			errf("%s: routes is required (config or rules)", where)
		default:
			errf("%s: invalid routes %q (want config or rules)", where, rt.Routes)
		}
		if rt.Autostart != nil {
			t.Autostart = *rt.Autostart
		}
		for _, s := range rt.DNSDomains {
			if strings.HasPrefix(s, "=") {
				errf("%s: dns_domains: %q: exact names are not allowed, dns_domains are zones", where, s)
				continue
			}
			d, err := parseDomain(s)
			if err != nil {
				errf("%s: dns_domains: %v", where, err)
				continue
			}
			t.DNSDomains = append(t.DNSDomains, d)
		}
		switch {
		case rt.Check == "":
		case strings.Contains(rt.Check, "://"):
			u, err := parseCheckURL(rt.Check)
			if err != nil {
				errf("%s: check: invalid URL %q: %v", where, redactURL(rt.Check), err)
			} else {
				t.CheckURL = u
			}
		default:
			a, err := netip.ParseAddr(rt.Check)
			if err != nil || a.Zone() != "" {
				errf("%s: check: invalid IP address %q", where, rt.Check)
			} else {
				t.Check = a
			}
		}

		switch data, ok := files[rt.Conf]; {
		case rt.Conf == "":
			errf("%s: conf is required", where)
		case strings.Contains(rt.Conf, "/"):
			errf("%s: conf %q: conf must be a file name without a path", where, rt.Conf)
		case confOwner[rt.Conf] != "":
			errf("%s: conf file %q is already used by %s", where, rt.Conf, confOwner[rt.Conf])
		case !ok:
			errf("%s: conf file %q not found", where, rt.Conf)
		default:
			confOwner[rt.Conf] = where
			wg, ws, es := parseWGConf(data)
			for _, w := range ws {
				warnings = append(warnings, rt.Conf+": "+w)
			}
			for _, e := range es {
				errf("%s: %v", rt.Conf, e)
			}
			t.WG = wg
			if t.Routes == RoutesConfig {
				for _, p := range defaultRoutes(wg) {
					errf("%s: routes: config with %s in AllowedIPs of %s conflicts with the system default route, use routes: rules", where, p, rt.Conf)
				}
			}
			if len(rt.DNSDomains) > 0 && len(wg.DNS) == 0 {
				errf("%s: dns_domains requires DNS in %s", where, rt.Conf)
			}
		}
		cfg.Tunnels = append(cfg.Tunnels, t)
	}

	// Sorted for deterministic error and warning order.
	names := make([]string, 0, len(raw.Services))
	for name := range raw.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rs := raw.Services[name]
		where := fmt.Sprintf("service %q", name)
		if name == "" {
			errf("service with empty name")
		}
		var svc Service
		for _, s := range rs.Domains {
			d, err := parseDomain(s)
			if err != nil {
				errf("%s: domains: %v", where, err)
				continue
			}
			svc.Domains = append(svc.Domains, d)
		}
		for _, s := range rs.CIDRs {
			p, canonical, err := parsePrefix(s)
			if err != nil {
				errf("%s: cidrs: %v", where, err)
				continue
			}
			if !canonical {
				warnings = append(warnings, fmt.Sprintf("%s: cidrs: %s canonicalized to %s", where, s, p))
			}
			svc.CIDRs = append(svc.CIDRs, p)
		}
		cfg.Services[name] = svc
	}

	used := map[string]bool{}
	for i, rr := range raw.Rules {
		where := fmt.Sprintf("rule #%d", i+1)
		r := Rule{Services: rr.Services, Via: rr.Via, Fallback: Fallback(rr.Fallback)}
		if len(rr.Services) == 0 {
			errf("%s: services is required", where)
		}
		for _, s := range rr.Services {
			used[s] = true
			if _, ok := raw.Services[s]; !ok {
				errf("%s: unknown service %q", where, s)
			}
		}
		for _, v := range rr.Via {
			if !tunnels[v] || v == "" {
				errf("%s: unknown tunnel %q in via", where, v)
			}
		}
		switch r.Fallback {
		case "":
			r.Fallback = FallbackDefault
		case FallbackDefault, FallbackBlock:
		default:
			errf("%s: invalid fallback %q (want default or block)", where, rr.Fallback)
		}
		cfg.Rules = append(cfg.Rules, r)
	}
	for _, name := range names {
		if !used[name] {
			warnings = append(warnings, fmt.Sprintf("service %q is not used by any rule", name))
		}
	}

	if len(errs) > 0 {
		return nil, warnings, errs
	}
	return cfg, warnings, nil
}

// parseDomain normalizes a domain pattern from YAML (design 6.4):
// "=name" is exact, otherwise a suffix; lowercase, trailing dot removed.
//
// The name must be a valid hostname: labels of 1..63 letters, digits, "-" or
// "_", not starting or ending with "-", at most 253 characters in total. A single
// label ("corp") is allowed. Wildcards are rejected (design 6.4: no masks).
func parseDomain(s string) (Domain, error) {
	var d Domain
	name := s
	if strings.HasPrefix(name, "=") {
		d.Exact = true
		name = name[1:]
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return d, fmt.Errorf("invalid domain %q: empty", s)
	}
	if len(name) > 253 {
		return d, fmt.Errorf("invalid domain %q: too long", s)
	}
	for _, label := range strings.Split(name, ".") {
		if err := checkLabel(label); err != nil {
			return d, fmt.Errorf("invalid domain %q: %v", s, err)
		}
	}
	d.Name = name
	return d, nil
}

func checkLabel(l string) error {
	if l == "" {
		return errors.New("empty label")
	}
	if len(l) > 63 {
		return errors.New("label longer than 63 characters")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return errors.New("label starts or ends with '-'")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("invalid character %q", c)
		}
	}
	return nil
}

// parsePrefix parses a CIDR or a bare address (as /32 or /128). canonical is
// false when the input had non-zero host bits and was masked (design 9.2).
// Zoned addresses are rejected.
func parsePrefix(s string) (p netip.Prefix, canonical bool, err error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false, fmt.Errorf("invalid address %q", s)
		}
		return netip.PrefixFrom(a, a.BitLen()), true, nil
	}
	p, err = netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("invalid CIDR %q", s)
	}
	m := p.Masked()
	return m, m == p, nil
}

// defaultRoutes returns the /0 prefixes (0.0.0.0/0, ::/0) found in AllowedIPs
// of any peer, each once, in order of appearance. They are not allowed for a
// tunnel with routes: config (design 9.2).
func defaultRoutes(wg WGConfig) []netip.Prefix {
	var res []netip.Prefix
	for _, peer := range wg.Peers {
		for _, p := range peer.AllowedIPs {
			if p.Bits() == 0 && !slices.Contains(res, p) {
				res = append(res, p)
			}
		}
	}
	return res
}

// redactURL returns the check URL s for an error without its password: a
// parsed URL with userinfo as URL.Redacted, an unparsable one with "@" with
// everything from "://" to the last "@" of s cut out (where the authority
// ends is unknown then, so the password may contain "/", "?" or "#").
func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil {
		if u.User != nil {
			return u.Redacted()
		}
		return s
	}
	i := strings.Index(s, "://")
	at := strings.LastIndex(s, "@")
	if i < 0 || at < i+len("://") {
		return s
	}
	return s[:i+len("://")] + s[at+1:]
}

// parseCheckURL parses the URL of an HTTP check (design 8, 9.2): the scheme
// http or https, a host without an IPv6 zone, no userinfo or fragment; path, port and query are
// free. The scheme and the host are lowercased (compared without case); the
// result is URL.String().
func parseCheckURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		if strings.Contains(s, "@") {
			// The url.Parse error may quote a part of the password
			// (invalid port ":pa"): give a general reason.
			return "", errors.New("malformed URL")
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the caller quotes the URL already
		}
		return "", err
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", errors.New("scheme must be http or https")
	case u.Opaque != "" || u.Hostname() == "":
		return "", errors.New("host is required")
	case u.User != nil:
		return "", errors.New("userinfo is not allowed")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return "", errors.New("fragment is not allowed")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && a.Zone() != "" {
		return "", errors.New("IPv6 zone is not allowed")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return "", fmt.Errorf("invalid port %q", p)
		}
	}
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}
