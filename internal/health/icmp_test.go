package health

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// Tests follow design 9 "Ping" and the Wirefork M7 plan (fact 6, decision 8): echo
// request and reply by RFC 792 (ICMPv4) and RFC 4443 (ICMPv6), the ICMPv4
// checksum by RFC 1071, replies matched by id, seq and nonce because every
// ICMP socket of the process gets every reply. Packets are built by hand
// here, independently of the code under test.

const (
	m7EchoRequestV4 = 8
	m7EchoReplyV4   = 0
	m7EchoRequestV6 = 128
	m7EchoReplyV6   = 129
)

// m7Checksum is the RFC 1071 internet checksum of b (an odd byte padded
// with zero). Over a message with a correct checksum field it is 0.
func m7Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// m7Echo builds an ICMP echo message of type typ with id, seq and data;
// v4: the checksum is set, v6: left zero.
func m7Echo(v6 bool, typ byte, id, seq uint16, data []byte) []byte {
	b := make([]byte, 8+len(data))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], data)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:], m7Checksum(b))
	}
	return b
}

func m7EchoRequest(t *testing.T, v6 bool, id, seq uint16, nonce []byte) (b []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("echoRequest panicked: %v", r)
		}
	}()
	return echoRequest(v6, id, seq, nonce)
}

func m7IsReply(t *testing.T, v6 bool, b []byte, id, seq uint16, nonce []byte) (ok bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("isReply(% x) panicked: %v", b, r)
		}
	}()
	return isReply(v6, b, id, seq, nonce)
}

var m7Nonce = []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

// ICMPv4 echo request: type 8, code 0, id, seq, the nonce as data and a
// valid RFC 1071 checksum.
func TestM7EchoRequestV4(t *testing.T) {
	cases := []struct {
		id, seq uint16
		nonce   []byte
	}{
		{0x1234, 1, m7Nonce},
		{0xffff, 0xffff, m7Nonce},
		{0, 0, m7Nonce},
		{0xabcd, 7, m7Nonce[:7]}, // odd length: padding in the checksum
		{0x0102, 300, bytes.Repeat([]byte{0xff}, 16)},
	}
	for _, c := range cases {
		name := fmt.Sprintf("id %#x seq %d nonce %d bytes", c.id, c.seq, len(c.nonce))
		b := m7EchoRequest(t, false, c.id, c.seq, c.nonce)
		if len(b) != 8+len(c.nonce) {
			t.Errorf("%s: %d bytes, want %d", name, len(b), 8+len(c.nonce))
			continue
		}
		if b[0] != m7EchoRequestV4 || b[1] != 0 {
			t.Errorf("%s: type %d code %d, want 8 0", name, b[0], b[1])
		}
		if id, seq := binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:]); id != c.id || seq != c.seq {
			t.Errorf("%s: id %#x seq %d, want %#x %d", name, id, seq, c.id, c.seq)
		}
		if !bytes.Equal(b[8:], c.nonce) {
			t.Errorf("%s: data % x, want % x", name, b[8:], c.nonce)
		}
		if cs := m7Checksum(b); cs != 0 {
			t.Errorf("%s: checksum field %#04x is wrong (RFC 1071 sum %#04x)", name, binary.BigEndian.Uint16(b[2:]), cs)
		}
		if want := m7Echo(false, m7EchoRequestV4, c.id, c.seq, c.nonce); !bytes.Equal(b, want) {
			t.Errorf("%s: % x, want % x", name, b, want)
		}
	}
}

// ICMPv6 echo request: type 128, code 0, id, seq, nonce; the checksum is
// the kernel's (fact 6), left zero.
func TestM7EchoRequestV6(t *testing.T) {
	b := m7EchoRequest(t, true, 0x4321, 9, m7Nonce)
	want := m7Echo(true, m7EchoRequestV6, 0x4321, 9, m7Nonce)
	if !bytes.Equal(b, want) {
		t.Errorf("echoRequest v6 = % x, want % x", b, want)
	}
}

// isReply: only the echo reply of the same family to this id, seq and
// nonce; anything else (another Pinger's reply, an old seq, the own echo
// request looped back on lo0, a short packet) is not.
func TestM7IsReply(t *testing.T) {
	const id, seq = 0x1234, 42
	other := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x05}
	for _, v6 := range []bool{false, true} {
		reply, request := byte(m7EchoReplyV4), byte(m7EchoRequestV4)
		otherReply := byte(m7EchoReplyV6)
		fam := "v4"
		if v6 {
			reply, request, otherReply, fam = m7EchoReplyV6, m7EchoRequestV6, m7EchoReplyV4, "v6"
		}
		own := m7Echo(v6, reply, id, seq, m7Nonce)
		cases := []struct {
			name string
			b    []byte
			want bool
		}{
			{"own reply", own, true},
			{"other id", m7Echo(v6, reply, id+1, seq, m7Nonce), false},
			{"other seq", m7Echo(v6, reply, id, seq-1, m7Nonce), false},
			{"other nonce", m7Echo(v6, reply, id, seq, other), false},
			{"truncated nonce", m7Echo(v6, reply, id, seq, m7Nonce[:4]), false},
			{"no data", m7Echo(v6, reply, id, seq, nil), false},
			{"own echo request (lo0)", m7Echo(v6, request, id, seq, m7Nonce), false},
			{"reply of the other family", m7Echo(v6, otherReply, id, seq, m7Nonce), false},
			{"destination unreachable", m7Echo(v6, map[bool]byte{false: 3, true: 1}[v6], id, seq, m7Nonce), false},
			{"empty", nil, false},
			{"1 byte", own[:1], false},
			{"4 bytes", own[:4], false},
			{"7 bytes", own[:7], false},
		}
		for _, c := range cases {
			if got := m7IsReply(t, v6, c.b, id, seq, m7Nonce); got != c.want {
				t.Errorf("%s %s: isReply = %v, want %v", fam, c.name, got, c.want)
			}
		}
	}
}

// A request built by echoRequest, turned into a reply by the peer (type
// changed, checksum fixed), is recognized: the two agree on the layout.
func TestM7EchoRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		b := m7EchoRequest(t, v6, 0x0a0b, 3, m7Nonce)
		if len(b) < 8 {
			t.Fatalf("v6 %v: echoRequest %d bytes", v6, len(b))
		}
		r := bytes.Clone(b)
		r[2], r[3] = 0, 0
		if v6 {
			r[0] = m7EchoReplyV6
		} else {
			r[0] = m7EchoReplyV4
			binary.BigEndian.PutUint16(r[2:], m7Checksum(r))
		}
		if !m7IsReply(t, v6, r, 0x0a0b, 3, m7Nonce) {
			t.Errorf("v6 %v: the reply to echoRequest is not recognized: % x", v6, r)
		}
		if m7IsReply(t, v6, b, 0x0a0b, 3, m7Nonce) {
			t.Errorf("v6 %v: the request itself is taken for a reply", v6)
		}
	}
}
