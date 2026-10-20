package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Key is a WireGuard key (base64 of 32 bytes in .conf). Every formatting
// path (String, GoString, Format, MarshalText) prints "(redacted)", so keys
// never leak into logs or RPC (design 9.4); the bytes are reachable only by
// indexing or slicing.
//
// Do not keep a Key in an unexported struct field that may reach fmt (logs,
// %v of the struct): fmt cannot call methods through unexported fields and
// prints such a Key as a plain byte array. Keep it in an exported field, or
// give the enclosing type its own redacting String/GoString/Format/LogValue.
type Key [32]byte

// String returns "(redacted)" so keys never leak into logs or RPC (design 9.4).
func (k Key) String() string { return "(redacted)" }

// GoString returns "(redacted)" so %#v does not print the key bytes (design 9.4).
func (k Key) GoString() string { return "(redacted)" }

// Format writes "(redacted)" for every verb, including %d, %x and %v: without
// it fmt would print the array elements for verbs other than %v and %s.
func (k Key) Format(f fmt.State, verb rune) { io.WriteString(f, "(redacted)") }

// MarshalText returns "(redacted)" so JSON and other text encodings do not
// expose the key (design 9.4).
func (k Key) MarshalText() ([]byte, error) { return []byte("(redacted)"), nil }

// wgQuickFields are wg-quick specific keys of [Interface] that wgplex ignores
// with a warning (design 5). FwMark is a wg(8) key but has no meaning on macOS.
var wgQuickFields = map[string]bool{
	"table":      true,
	"preup":      true,
	"postup":     true,
	"predown":    true,
	"postdown":   true,
	"saveconfig": true,
	"fwmark":     true,
}

// parseWGConf parses a .conf file (design 5, 9.2, 9.3). Line length is unbounded;
// wg-quick fields (PreUp, PostUp, Table, SaveConfig, ...) and non-IP DNS values
// are ignored with a warning; addresses without a prefix become /32 or /128;
// non-canonical AllowedIPs are canonicalized with a warning; duplicates in Address,
// AllowedIPs and DNS are dropped. All errors in the file are returned.
//
// Format details (following wg(8)/wg-quick(8)): section and key names are
// case-insensitive; "#" starts a comment anywhere in a line; list keys (Address,
// DNS, AllowedIPs) are comma-separated, may be repeated within a section and
// accumulate, empty list elements are skipped; any other key repeated within a
// section is an error, as are unknown keys and sections, keys outside a section,
// a missing or repeated [Interface], a missing PrivateKey or PublicKey, and a
// file without [Peer]. PersistentKeepalive accepts "off". Address keeps the
// prefix length as written (10.0.0.2/24 is an interface address, design 9.2).
//
// Error and warning messages carry the line number and never include key
// values (design 9.4): section and key names must be identifiers ([A-Za-z]+),
// otherwise the line is reported as malformed without its content, since a
// mistyped "PrivateKey <key>" would otherwise end up in the message. Keys of
// an unknown section are skipped silently: one error per section.
func parseWGConf(data []byte) (wg WGConfig, warnings []string, errs []error) {
	const (
		secNone = iota
		secInterface
		secPeer
		secUnknown // after an unknown section: its keys are skipped
	)
	sec := secNone
	interfaces := 0
	var seen map[string]bool // scalar keys already set in the current section
	var peer *Peer
	hasPrivateKey := false
	var peerLines []int // header line of each peer, for "missing PublicKey"
	var peerHasKey []bool

	errf := func(line int, format string, args ...any) {
		errs = append(errs, fmt.Errorf("line %d: "+format, append([]any{line}, args...)...))
	}
	warnf := func(line int, format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf("line %d: "+format, append([]any{line}, args...)...))
	}

	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = line[:c]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name := strings.TrimSpace(strings.TrimSuffix(line[1:], "]"))
			if !strings.HasSuffix(line, "]") || !isIdent(name) {
				errf(n, "malformed section header")
				sec = secUnknown
				continue
			}
			seen = map[string]bool{}
			switch strings.ToLower(name) {
			case "interface":
				sec = secInterface
				interfaces++
				if interfaces > 1 {
					errf(n, "repeated [Interface] section")
				}
			case "peer":
				sec = secPeer
				wg.Peers = append(wg.Peers, Peer{})
				peer = &wg.Peers[len(wg.Peers)-1]
				peerLines = append(peerLines, n)
				peerHasKey = append(peerHasKey, false)
			default:
				errf(n, "unknown section [%s]", name)
				sec = secUnknown
			}
			continue
		}

		// The line content is never printed: it may hold a key (design 9.4).
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			errf(n, "malformed line")
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		lkey := strings.ToLower(key)
		if !isIdent(key) {
			errf(n, "malformed line")
			continue
		}

		if sec == secUnknown {
			continue
		}
		if sec == secNone {
			errf(n, "key %s outside of a section", key)
			continue
		}
		isList := lkey == "address" || lkey == "dns" || lkey == "allowedips"
		if !isList {
			if seen[lkey] {
				errf(n, "repeated key %s", key)
				continue
			}
			seen[lkey] = true
		}

		if sec == secInterface {
			switch lkey {
			case "privatekey":
				k, err := parseKey(val)
				if err != nil {
					errf(n, "PrivateKey: %v", err)
					continue
				}
				wg.PrivateKey = k
				hasPrivateKey = true
			case "address":
				wg.Addresses = appendAddresses(wg.Addresses, val, n, errf)
			case "dns":
				for _, s := range splitList(val) {
					a, err := netip.ParseAddr(s)
					if err != nil || a.Zone() != "" {
						warnf(n, "DNS: ignoring non-IP value %q (use dns_domains)", s)
						continue
					}
					if !containsAddr(wg.DNS, a) {
						wg.DNS = append(wg.DNS, a)
					}
				}
			case "mtu":
				v, err := parseInt(val, 1, 65535)
				if err != nil {
					errf(n, "MTU: %v", err)
					continue
				}
				wg.MTU = v
			case "listenport":
				v, err := parseInt(val, 0, 65535)
				if err != nil {
					errf(n, "ListenPort: %v", err)
					continue
				}
				wg.ListenPort = v
			default:
				if wgQuickFields[lkey] {
					warnf(n, "ignoring %s (not supported by wgplex)", key)
					continue
				}
				errf(n, "unknown key %s in [Interface]", key)
			}
			continue
		}

		// [Peer]
		switch lkey {
		case "publickey":
			k, err := parseKey(val)
			if err != nil {
				errf(n, "PublicKey: %v", err)
				continue
			}
			peer.PublicKey = k
			peerHasKey[len(peerHasKey)-1] = true
		case "presharedkey":
			k, err := parseKey(val)
			if err != nil {
				errf(n, "PresharedKey: %v", err)
				continue
			}
			peer.PresharedKey = k
		case "endpoint":
			if err := checkEndpoint(val); err != nil {
				errf(n, "Endpoint: %v", err)
				continue
			}
			peer.Endpoint = val
		case "allowedips":
			peer.AllowedIPs = appendPrefixes(peer.AllowedIPs, val, n, "AllowedIPs", errf, warnf)
		case "persistentkeepalive":
			if strings.EqualFold(val, "off") {
				peer.PersistentKeepalive = 0
				continue
			}
			v, err := parseInt(val, 0, 65535)
			if err != nil {
				errf(n, "PersistentKeepalive: %v", err)
				continue
			}
			peer.PersistentKeepalive = v
		default:
			errf(n, "unknown key %s in [Peer]", key)
		}
	}

	if interfaces == 0 {
		errs = append(errs, errors.New("missing [Interface] section"))
	} else if !hasPrivateKey {
		errs = append(errs, errors.New("[Interface]: missing PrivateKey"))
	}
	if len(wg.Peers) == 0 {
		errs = append(errs, errors.New("no [Peer] section"))
	}
	for i, ok := range peerHasKey {
		if !ok {
			errs = append(errs, fmt.Errorf("line %d: [Peer]: missing PublicKey", peerLines[i]))
		}
	}
	return wg, warnings, errs
}

// parseKey decodes a base64 WireGuard key of exactly 32 bytes. The error never
// contains the input, which may be a private key.
func parseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, errors.New("invalid key: not valid base64")
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("invalid key: %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// isIdent reports whether s is a non-empty run of ASCII letters, the shape of
// every .conf section and key name.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// splitList splits a comma-separated .conf value, trimming spaces and
// skipping empty elements.
func splitList(val string) []string {
	var out []string
	for _, s := range strings.Split(val, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// appendPrefixes parses a comma-separated list of CIDRs or bare addresses and
// appends the new ones to dst, dropping duplicates (design 9.2).
func appendPrefixes(dst []netip.Prefix, val string, line int, field string,
	errf func(int, string, ...any), warnf func(int, string, ...any)) []netip.Prefix {
	for _, s := range splitList(val) {
		p, canonical, err := parsePrefix(s)
		if err != nil {
			errf(line, "%s: %v", field, err)
			continue
		}
		if !canonical {
			warnf(line, "%s: %s canonicalized to %s", field, s, p)
		}
		if !containsPrefix(dst, p) {
			dst = append(dst, p)
		}
	}
	return dst
}

// appendAddresses parses a comma-separated Address list and appends the new
// entries to dst. Unlike AllowedIPs, an interface address keeps its host bits
// (10.0.0.2/24); a bare address becomes /32 or /128; exact duplicates (including
// x and x/32) are dropped (design 9.2).
func appendAddresses(dst []netip.Prefix, val string, line int, errf func(int, string, ...any)) []netip.Prefix {
	for _, s := range splitList(val) {
		var p netip.Prefix
		if strings.Contains(s, "/") {
			q, err := netip.ParsePrefix(s)
			if err != nil {
				errf(line, "Address: invalid CIDR %q", s)
				continue
			}
			p = q
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" {
				errf(line, "Address: invalid address %q", s)
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !containsPrefix(dst, p) {
			dst = append(dst, p)
		}
	}
	return dst
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// parseInt parses a decimal integer in [min, max].
func parseInt(s string, min, max int) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%d out of range %d..%d", v, min, max)
	}
	return v, nil
}

// checkEndpoint checks that s is host:port with a non-empty host and a port
// in 1..65535. The host is not resolved here (design 5).
func checkEndpoint(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid host:port %q", s)
	}
	if host == "" {
		return fmt.Errorf("empty host in %q", s)
	}
	if _, err := parseInt(port, 1, 65535); err != nil {
		return fmt.Errorf("port: %v", err)
	}
	return nil
}
