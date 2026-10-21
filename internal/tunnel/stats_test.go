package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tests follow design 10.1 (Ключи: keys never leak), 14 (peer fields) and 13 and the Wirefork M6 plan (fact 6, the appendix
// "образец IpcGet"), not the implementation. The keys are stubs: every key
// is 32 copies of one byte, never a real key.

// m6IpcGet is the IpcGet sample of the Wirefork M6 plan appendix: the peers are listed
// in the reverse of the .conf order.
const m6IpcGet = `private_key=0101010101010101010101010101010101010101010101010101010101010101
listen_port=51820
public_key=0303030303030303030303030303030303030303030303030303030303030303
preshared_key=0000000000000000000000000000000000000000000000000000000000000000
protocol_version=1
endpoint=198.51.100.7:51820
last_handshake_time_sec=0
last_handshake_time_nsec=0
tx_bytes=148
rx_bytes=0
persistent_keepalive_interval=25
allowed_ip=0.0.0.0/0
public_key=0202020202020202020202020202020202020202020202020202020202020202
preshared_key=0404040404040404040404040404040404040404040404040404040404040404
protocol_version=1
endpoint=203.0.113.5:51820
last_handshake_time_sec=1760860800
last_handshake_time_nsec=500000000
tx_bytes=307200
rx_bytes=1258291
persistent_keepalive_interval=0
allowed_ip=10.0.0.0/8
allowed_ip=192.168.50.0/24
`

// m6StubKey is a key of 32 copies of b.
func m6StubKey(b byte) config.Key {
	var k config.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// m6KeyForms are the hex and base64 forms of every key byte of m6IpcGet
// (private 0x01, public 0x02 and 0x03, preshared 0x04) and of the extra
// .conf peer 0x05.
func m6KeyForms() []string {
	var out []string
	for _, b := range []byte{0x01, 0x02, 0x03, 0x04, 0x05} {
		raw := bytes.Repeat([]byte{b}, 32)
		out = append(out, hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw))
	}
	return out
}

func m6ParseStats(t *testing.T, uapi string, peers []config.Peer) (got []PeerStats) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseStats panicked: %v", r)
		}
	}()
	return parseStats(uapi, peers)
}

// Wirefork M6 appendix: peers are matched by public_key whatever the IpcGet order;
// handshake 0 is "never" (zero time); sec+nsec make the handshake time.
func TestM6ParseStatsSample(t *testing.T) {
	peers := []config.Peer{
		{PublicKey: m6StubKey(0x02), Endpoint: "203.0.113.5:51820"},
		{PublicKey: m6StubKey(0x03), Endpoint: "198.51.100.7:51820"},
	}
	got := m6ParseStats(t, m6IpcGet, peers)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (index = peer index)", len(got))
	}

	want0 := time.Unix(1760860800, 500000000)
	if !got[0].LastHandshake.Equal(want0) {
		t.Errorf("peer 0 handshake = %v, want %v (sec + nsec)", got[0].LastHandshake, want0)
	}
	if got[0].RxBytes != 1258291 || got[0].TxBytes != 307200 {
		t.Errorf("peer 0 rx/tx = %d/%d, want 1258291/307200", got[0].RxBytes, got[0].TxBytes)
	}

	if !got[1].LastHandshake.IsZero() {
		t.Errorf("peer 1 handshake = %v, want zero time (never)", got[1].LastHandshake)
	}
	if got[1].RxBytes != 0 || got[1].TxBytes != 148 {
		t.Errorf("peer 1 rx/tx = %d/%d, want 0/148", got[1].RxBytes, got[1].TxBytes)
	}
}

// Matching by public_key does not depend on the .conf order either.
func TestM6ParseStatsConfOrder(t *testing.T) {
	peers := []config.Peer{
		{PublicKey: m6StubKey(0x03)},
		{PublicKey: m6StubKey(0x02)},
	}
	got := m6ParseStats(t, m6IpcGet, peers)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].TxBytes != 148 || !got[0].LastHandshake.IsZero() {
		t.Errorf("peer 0 (key 0x03) = %+v, want tx 148, no handshake", got[0])
	}
	if got[1].RxBytes != 1258291 || got[1].TxBytes != 307200 {
		t.Errorf("peer 1 (key 0x02) = %+v, want rx 1258291, tx 307200", got[1])
	}
}

// A .conf peer the device does not list gets zero stats.
func TestM6ParseStatsMissingPeer(t *testing.T) {
	peers := []config.Peer{
		{PublicKey: m6StubKey(0x02)},
		{PublicKey: m6StubKey(0x05)}, // not in IpcGet
		{PublicKey: m6StubKey(0x03)},
	}
	got := m6ParseStats(t, m6IpcGet, peers)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[1] != (PeerStats{}) {
		t.Errorf("unlisted peer = %+v, want zero stats", got[1])
	}
	if got[0].RxBytes != 1258291 {
		t.Errorf("peer 0 rx = %d, want 1258291", got[0].RxBytes)
	}
	if got[2].TxBytes != 148 {
		t.Errorf("peer 2 tx = %d, want 148", got[2].TxBytes)
	}
}

// Empty IpcGet (or one without peers): every peer gets zero stats; no peers:
// an empty result.
func TestM6ParseStatsEmpty(t *testing.T) {
	peers := []config.Peer{{PublicKey: m6StubKey(0x02)}}
	for _, uapi := range []string{"", "private_key=0101010101010101010101010101010101010101010101010101010101010101\nlisten_port=51820\n"} {
		got := m6ParseStats(t, uapi, peers)
		if len(got) != 1 || got[0] != (PeerStats{}) {
			t.Errorf("parseStats(%q) = %+v, want one zero PeerStats", uapi, got)
		}
	}
	if got := m6ParseStats(t, m6IpcGet, nil); len(got) != 0 {
		t.Errorf("no peers: got %+v, want empty", got)
	}
}

// design 10.1: the result carries no key in any form, %#v or JSON.
func TestM6ParseStatsNoKeys(t *testing.T) {
	peers := []config.Peer{
		{PublicKey: m6StubKey(0x02), PresharedKey: m6StubKey(0x04)},
		{PublicKey: m6StubKey(0x03)},
		{PublicKey: m6StubKey(0x05)},
	}
	got := m6ParseStats(t, m6IpcGet, peers)
	js, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	outs := map[string]string{
		"%#v":  fmt.Sprintf("%#v", got),
		"%+v":  fmt.Sprintf("%+v", got),
		"JSON": string(js),
	}
	for how, out := range outs {
		for _, k := range m6KeyForms() {
			if strings.Contains(out, k) {
				t.Errorf("%s of the result contains a key: %s", how, out)
			}
		}
	}
}
