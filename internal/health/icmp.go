package health

import (
	"bytes"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IANA protocol numbers for icmp.ParseMessage.
const (
	protoICMP   = 1
	protoICMPv6 = 58
)

// echoRequest returns an ICMP (v6: ICMPv6) echo request with id, seq and
// nonce as its data; the ICMPv4 checksum is set, ICMPv6 leaves it to the kernel.
func echoRequest(v6 bool, id, seq uint16, nonce []byte) []byte {
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: nonce},
	}
	if v6 {
		m.Type = ipv6.ICMPTypeEchoRequest
	}
	// With a nil pseudo header Marshal computes the ICMPv4 checksum and
	// leaves the ICMPv6 one zero: the kernel fills it in (Wirefork M7 fact 6).
	b, err := m.Marshal(nil)
	if err != nil {
		panic(err) // cannot happen: an Echo body always marshals
	}
	return b
}

// isReply reports whether b (no IP header) is the echo reply to id, seq, nonce.
func isReply(v6 bool, b []byte, id, seq uint16, nonce []byte) bool {
	proto, want := protoICMP, icmp.Type(ipv4.ICMPTypeEchoReply)
	if v6 {
		proto, want = protoICMPv6, ipv6.ICMPTypeEchoReply
	}
	m, err := icmp.ParseMessage(proto, b)
	if err != nil || m.Type != want {
		return false
	}
	e, ok := m.Body.(*icmp.Echo)
	return ok && e.ID == int(id) && e.Seq == int(seq) && bytes.Equal(e.Data, nonce)
}
