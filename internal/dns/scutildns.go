package dns

import (
	"fmt"
	"strconv"
	"strings"
)

// resolverBlock is one "resolver #N" block of `scutil --dns` output: the
// fields VerifyZones needs.
type resolverBlock struct {
	domain     string // "domain : x"; "" when the block has none
	nameserver string // "nameserver[0] : x"; "" when absent
	port       int    // "port : N"; 0 when absent (the default, 53)
}

// parseScutilDNS parses the output of `scutil --dns` (design 8): every
// "resolver #N" block of the "DNS configuration" section, in the order
// printed, with its domain, nameserver[0] and port; the blocks of "DNS
// configuration (for scoped queries)" are skipped (supplemental domains are
// not scoped). Lines it does not know are
// skipped; output without blocks gives none. Pure: no system calls.
//
// Values are kept as printed, only trimmed; a port that is not a number is 0.
func parseScutilDNS(out string) []resolverBlock {
	var (
		res       []resolverBlock
		inSection bool // inside the unscoped "DNS configuration" section
		cur       = -1 // index of the current block in res; -1: none
	)
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "DNS configuration"):
			inSection = t == "DNS configuration"
			cur = -1
			continue
		case !inSection:
			continue
		case strings.HasPrefix(t, "resolver #"):
			res = append(res, resolverBlock{})
			cur = len(res) - 1
			continue
		case cur < 0:
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		b := &res[cur]
		switch k {
		case "domain":
			b.domain = v
		case "nameserver[0]":
			b.nameserver = v
		case "port":
			b.port, _ = strconv.Atoi(v)
		}
	}
	return res
}

// missingZones returns the zones (in their order) that no block sends to our
// resolver: a block whose domain is the zone (case and a final dot ignored),
// nameserver[0] 127.0.0.1 and port Port. Pure.
func missingZones(blocks []resolverBlock, zones []string) []string {
	ours := map[string]bool{}
	for _, b := range blocks {
		if b.nameserver == "127.0.0.1" && b.port == Port {
			ours[normZone(b.domain)] = true
		}
	}
	var res []string
	for _, z := range zones {
		if !ours[normZone(z)] {
			res = append(res, z)
		}
	}
	return res
}

func normZone(z string) string {
	return strings.ToLower(strings.TrimSuffix(z, "."))
}

// maxNamed bounds the zones named in the error of VerifyZones: up to 1000
// may be missing at once.
const maxNamed = 10

// missingError is the error of VerifyZones for the zones missing; nil when
// none is.
func missingError(missing []string, total int) error {
	if len(missing) == 0 {
		return nil
	}
	named := missing
	more := ""
	if len(named) > maxNamed {
		named = named[:maxNamed]
		more = fmt.Sprintf(" and %d more", len(missing)-maxNamed)
	}
	return fmt.Errorf("system DNS has no resolver 127.0.0.1:%d for %d of %d zones: %s%s",
		Port, len(missing), total, strings.Join(named, ", "), more)
}
