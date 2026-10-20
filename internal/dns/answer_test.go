package dns

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Tests follow design 6.3 (NODATA), 7 (IPv6 filter, HTTPS/SVCB hints) and the
// M5 plan ("Модель" query steps 4, 5; decision 8), not the implementation.

// --- helpers ---------------------------------------------------------------

func m5Hdr(name string, typ uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: typ, Class: dns.ClassINET, Ttl: ttl}
}

func m5A(name, addr string, ttl uint32) *dns.A {
	return &dns.A{Hdr: m5Hdr(name, dns.TypeA, ttl), A: net.ParseIP(addr).To4()}
}

func m5AAAA(name, addr string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{Hdr: m5Hdr(name, dns.TypeAAAA, ttl), AAAA: net.ParseIP(addr)}
}

func m5CNAME(name, target string, ttl uint32) *dns.CNAME {
	return &dns.CNAME{Hdr: m5Hdr(name, dns.TypeCNAME, ttl), Target: dns.Fqdn(target)}
}

func m5RRSIG(name string, covered uint16) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: m5Hdr(name, dns.TypeRRSIG, 300), TypeCovered: covered, Algorithm: dns.ECDSAP256SHA256,
		Labels: 2, OrigTtl: 300, Expiration: 2000000000, Inception: 1700000000, KeyTag: 1,
		SignerName: dns.Fqdn(name), Signature: "AAAA",
	}
}

// m5SVCBValue is an alpn plus both hints.
func m5SVCBValue() []dns.SVCBKeyValue {
	return []dns.SVCBKeyValue{
		&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.1").To4()}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2001:db8::1")}},
	}
}

func m5HTTPS(name string) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{Hdr: m5Hdr(name, dns.TypeHTTPS, 300), Priority: 1, Target: ".", Value: m5SVCBValue()}}
}

func m5SVCB(name string) *dns.SVCB {
	return &dns.SVCB{Hdr: m5Hdr(name, dns.TypeSVCB, 300), Priority: 1, Target: ".", Value: m5SVCBValue()}
}

// m5Reply is a reply to name/qtype with answer.
func m5Reply(name string, qtype uint16, answer ...dns.RR) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = answer
	return m
}

// m5Types lists the types of rrs; RRSIG as "RRSIG(<covered>)".
func m5Types(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			out = append(out, "RRSIG("+dns.TypeToString[sig.TypeCovered]+")")
			continue
		}
		out = append(out, dns.TypeToString[rr.Header().Rrtype])
	}
	return out
}

// m5SVCBKeys lists the keys of an HTTPS or SVCB record.
func m5SVCBKeys(rr dns.RR) []string {
	var v []dns.SVCBKeyValue
	switch r := rr.(type) {
	case *dns.HTTPS:
		v = r.Value
	case *dns.SVCB:
		v = r.Value
	}
	var out []string
	for _, kv := range v {
		out = append(out, kv.Key().String())
	}
	return out
}

func m5Filter(t *testing.T, m *dns.Msg, c Choice) {
	t.Helper()
	m5NoPanic(t, "Filter", func() { Filter(m, c) })
}

// --- Filter ------------------------------------------------------------------

// design 7 "IPv6", M5 "Модель" query step 4: with DropAAAA the AAAA records
// and their RRSIGs go; A, CNAME and other RRSIGs stay.
func TestM5FilterDropAAAA(t *testing.T) {
	answer := func() []dns.RR {
		return []dns.RR{
			m5CNAME("www.example.net", "cdn.example.net", 300),
			m5RRSIG("www.example.net", dns.TypeCNAME),
			m5A("cdn.example.net", "192.0.2.1", 60),
			m5RRSIG("cdn.example.net", dns.TypeA),
			m5AAAA("cdn.example.net", "2001:db8::1", 60),
			m5AAAA("cdn.example.net", "2001:db8::2", 60),
			m5RRSIG("cdn.example.net", dns.TypeAAAA),
		}
	}
	cases := []struct {
		why  string
		c    Choice
		want []string
	}{
		{"DropAAAA for a rule domain", Choice{Rule: 0, Tunnel: "de", DropAAAA: true},
			[]string{"CNAME", "RRSIG(CNAME)", "A", "RRSIG(A)"}},
		{"no DropAAAA: nothing removed", Choice{Rule: 0, Tunnel: "v6"},
			[]string{"CNAME", "RRSIG(CNAME)", "A", "RRSIG(A)", "AAAA", "AAAA", "RRSIG(AAAA)"}},
		{"system upstream: nothing removed", Choice{Rule: -1},
			[]string{"CNAME", "RRSIG(CNAME)", "A", "RRSIG(A)", "AAAA", "AAAA", "RRSIG(AAAA)"}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m := m5Reply("www.example.net", dns.TypeA, answer()...)
			m5Filter(t, m, c.c)
			if got := m5Types(m.Answer); !slices.Equal(got, c.want) {
				t.Errorf("answer = %v, want %v", got, c.want)
			}
		})
	}

	// An AAAA query answered only with AAAA: the answer ends up empty, the
	// reply stays NOERROR (NODATA, not an error).
	t.Run("AAAA only", func(t *testing.T) {
		m := m5Reply("ifconfig.me", dns.TypeAAAA, m5AAAA("ifconfig.me", "2001:db8::3", 60))
		m5Filter(t, m, Choice{Rule: 0, Tunnel: "de", DropAAAA: true})
		if len(m.Answer) != 0 {
			t.Errorf("answer = %v, want empty", m5Types(m.Answer))
		}
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
		}
	})
}

// M5 decision 8: ipv4hint and ipv6hint are removed from HTTPS and SVCB for a
// rule domain only; alpn stays.
func TestM5FilterHints(t *testing.T) {
	cases := []struct {
		why  string
		rr   func() dns.RR
		c    Choice
		want []string
	}{
		{"HTTPS, rule domain", func() dns.RR { return m5HTTPS("ifconfig.me") }, Choice{Rule: 0, Tunnel: "de"}, []string{"alpn"}},
		{"SVCB, rule domain", func() dns.RR { return m5SVCB("_dns.ifconfig.me") }, Choice{Rule: 0, Tunnel: "de"}, []string{"alpn"}},
		{"HTTPS, direct rule domain", func() dns.RR { return m5HTTPS("icanhazip.com") }, Choice{Rule: 1}, []string{"alpn"}},
		{"HTTPS, rule domain with DropAAAA", func() dns.RR { return m5HTTPS("ifconfig.me") }, Choice{Rule: 0, Tunnel: "de", DropAAAA: true}, []string{"alpn"}},
		{"HTTPS, not a rule domain", func() dns.RR { return m5HTTPS("apple.com") }, Choice{Rule: -1}, []string{"alpn", "ipv4hint", "ipv6hint"}},
		{"HTTPS, dns_domains", func() dns.RR { return m5HTTPS("vault.corp.example") }, Choice{Rule: -1, Tunnel: "work"}, []string{"alpn", "ipv4hint", "ipv6hint"}},
		{"SVCB, not a rule domain", func() dns.RR { return m5SVCB("_dns.apple.com") }, Choice{Rule: -1}, []string{"alpn", "ipv4hint", "ipv6hint"}},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			rr := c.rr()
			m := m5Reply(rr.Header().Name, rr.Header().Rrtype, rr, m5A(rr.Header().Name, "192.0.2.9", 60))
			m5Filter(t, m, c.c)
			if got := m5Types(m.Answer); len(got) != 2 {
				t.Fatalf("answer = %v, want the record and the A", got)
			}
			if got := m5SVCBKeys(m.Answer[0]); !slices.Equal(got, c.want) {
				t.Errorf("keys = %v, want %v", got, c.want)
			}
		})
	}
}

// --- Addrs -------------------------------------------------------------------

// M5 "Модель" query step 5: the A and AAAA of the answer, whatever owner of
// the CNAME chain, with their minimal TTL.
func TestM5Addrs(t *testing.T) {
	cases := []struct {
		why    string
		answer []dns.RR
		want   []string
		ttl    time.Duration
	}{
		{"single A", []dns.RR{m5A("ifconfig.me", "192.0.2.1", 300)}, []string{"192.0.2.1"}, 300 * time.Second},
		{"A and AAAA, minimal TTL",
			[]dns.RR{m5A("ifconfig.me", "192.0.2.1", 300), m5AAAA("ifconfig.me", "2001:db8::1", 120)},
			[]string{"192.0.2.1", "2001:db8::1"}, 120 * time.Second},
		// The CNAMEs have a lower TTL than the addresses: only the A/AAAA
		// TTLs count ("their minimal TTL").
		{"CNAME chain: addresses of any owner",
			[]dns.RR{
				m5CNAME("www.youtube.com", "youtube-ui.l.google.com", 3600),
				m5CNAME("youtube-ui.l.google.com", "x.l.google.com", 3600),
				m5A("youtube-ui.l.google.com", "192.0.2.10", 200),
				m5A("x.l.google.com", "192.0.2.11", 90),
				m5AAAA("x.l.google.com", "2001:db8::11", 250),
			},
			[]string{"192.0.2.10", "192.0.2.11", "2001:db8::11"}, 90 * time.Second},
		{"other records ignored",
			[]dns.RR{m5HTTPS("ifconfig.me"), m5A("ifconfig.me", "192.0.2.1", 60), m5RRSIG("ifconfig.me", dns.TypeA)},
			[]string{"192.0.2.1"}, 60 * time.Second},
		{"empty answer", nil, nil, 0},
		{"CNAME only", []dns.RR{m5CNAME("a.example", "b.example", 60)}, nil, 0},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			m := m5Reply("q.example", dns.TypeA, c.answer...)
			var (
				got []netip.Addr
				ttl time.Duration
			)
			m5NoPanic(t, "Addrs", func() { got, ttl = Addrs(m) })
			sorted := slices.Clone(got)
			slices.SortFunc(sorted, netip.Addr.Compare)
			if !slices.Equal(sorted, m5Addrs(c.want...)) {
				t.Errorf("addrs = %v, want %v (any order)", got, c.want)
			}
			if ttl != c.ttl {
				t.Errorf("ttl = %v, want %v", ttl, c.ttl)
			}
			if len(c.want) == 0 && got != nil {
				t.Errorf("addrs = %#v, want nil", got)
			}
		})
	}

	// Addresses outside the answer section are not taken.
	t.Run("authority and additional ignored", func(t *testing.T) {
		m := m5Reply("q.example", dns.TypeA, m5A("q.example", "192.0.2.1", 60))
		m.Ns = []dns.RR{m5A("ns.example", "192.0.2.53", 10)}
		m.Extra = []dns.RR{m5AAAA("ns.example", "2001:db8::53", 10)}
		var (
			got []netip.Addr
			ttl time.Duration
		)
		m5NoPanic(t, "Addrs", func() { got, ttl = Addrs(m) })
		if !slices.Equal(got, m5Addrs("192.0.2.1")) || ttl != 60*time.Second {
			t.Errorf("Addrs = %v, %v; want [192.0.2.1], 1m0s", got, ttl)
		}
	})
}

// --- NoData ------------------------------------------------------------------

// design 6.3 (fallback: block → NODATA), M5 "Модель" query step 2: NOERROR,
// the id and question of the request, empty answer, a SOA in authority with
// the TTL noDataTTL (30 s).
func TestM5NoData(t *testing.T) {
	if noDataTTL != 30*time.Second {
		t.Errorf("noDataTTL = %v, want 30s", noDataTTL)
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeMX, dns.TypeTXT} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("www.example.com.", qtype)
			req.Id = 4321
			var m *dns.Msg
			m5NoPanic(t, "NoData", func() { m = NoData(req) })
			if m == nil {
				t.Fatal("NoData returned nil")
			}
			if !m.Response {
				t.Error("QR not set")
			}
			if m.Id != req.Id {
				t.Errorf("id = %d, want %d", m.Id, req.Id)
			}
			if m.Rcode != dns.RcodeSuccess {
				t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
			}
			if !slices.Equal(m.Question, req.Question) {
				t.Errorf("question = %v, want %v", m.Question, req.Question)
			}
			if len(m.Answer) != 0 {
				t.Errorf("answer = %v, want empty", m.Answer)
			}
			var soas []*dns.SOA
			for _, rr := range m.Ns {
				if soa, ok := rr.(*dns.SOA); ok {
					soas = append(soas, soa)
				}
			}
			if len(soas) != 1 {
				t.Fatalf("authority = %v, want one SOA", m.Ns)
			}
			if soas[0].Hdr.Ttl != 30 {
				t.Errorf("SOA TTL = %d, want 30", soas[0].Hdr.Ttl)
			}
			// The reply must survive the wire.
			if _, err := m.Pack(); err != nil {
				t.Errorf("Pack: %v", err)
			}
		})
	}
}
