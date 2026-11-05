package dns

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
func parseScutilDNS(out string) []resolverBlock {
	panic("not implemented")
}
