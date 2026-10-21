package dns

import (
	"net/netip"
	"slices"
	"time"

	"github.com/miekg/dns"
)

// noDataTTL is the TTL of the synthetic SOA in a NODATA reply: short, so that
// a blocked name comes back soon after its tunnel recovers.
const noDataTTL = 30 * time.Second

// Filter edits an upstream answer for c in place: with c.DropAAAA it removes
// AAAA records and their RRSIGs; for a rule domain (c.Rule >= 0) it removes
// ipv4hint and ipv6hint from HTTPS and SVCB records (Wirefork M5 decision 8). Other
// records and SVCB keys (alpn, …) are kept. All three sections are edited.
func Filter(m *dns.Msg, c Choice) {
	for _, sec := range []*[]dns.RR{&m.Answer, &m.Ns, &m.Extra} {
		if c.DropAAAA {
			*sec = slices.DeleteFunc(*sec, isAAAA)
		}
		if c.Rule >= 0 {
			for _, rr := range *sec {
				switch rr := rr.(type) {
				case *dns.SVCB:
					rr.Value = dropHints(rr.Value)
				case *dns.HTTPS:
					rr.Value = dropHints(rr.Value)
				}
			}
		}
	}
}

// isAAAA reports whether rr is an AAAA record or an RRSIG over AAAA.
func isAAAA(rr dns.RR) bool {
	switch rr := rr.(type) {
	case *dns.AAAA:
		return true
	case *dns.RRSIG:
		return rr.TypeCovered == dns.TypeAAAA
	}
	return false
}

// dropHints returns kv without ipv4hint and ipv6hint.
func dropHints(kv []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	return slices.DeleteFunc(kv, func(v dns.SVCBKeyValue) bool {
		k := v.Key()
		return k == dns.SVCB_IPV4HINT || k == dns.SVCB_IPV6HINT
	})
}

// Addrs returns the A and AAAA addresses of m's answer section (any owner
// name of the CNAME chain) and their minimal TTL; no addresses: nil, 0.
// An address listed twice is returned once.
func Addrs(m *dns.Msg) ([]netip.Addr, time.Duration) {
	var (
		addrs []netip.Addr
		ttl   uint32
	)
	for _, rr := range m.Answer {
		var a netip.Addr
		switch rr := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(rr.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(rr.AAAA.To16())
		default:
			continue
		}
		if !a.IsValid() {
			continue
		}
		if t := rr.Header().Ttl; len(addrs) == 0 || t < ttl {
			ttl = t
		}
		if !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, 0
	}
	return addrs, time.Duration(ttl) * time.Second
}

// NoData returns the NODATA reply to req: NOERROR, empty answer and a
// synthetic SOA in authority with noDataTTL (30 s), so that the name comes
// back soon after its tunnel recovers. The id and question are those of req.
// The SOA is owned by the queried name; with EDNS0 in req the reply has an
// OPT record too.
func NoData(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	owner := "."
	if len(req.Question) > 0 {
		owner = req.Question[0].Name
	}
	ttl := uint32(noDataTTL / time.Second)
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "wgplex.invalid.",
		Mbox:    "hostmaster.wgplex.invalid.",
		Serial:  1,
		Refresh: ttl,
		Retry:   ttl,
		Expire:  ttl,
		Minttl:  ttl,
	}}
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}
	return m
}
