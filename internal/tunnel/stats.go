package tunnel

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/mrFokin/wgplex/internal/config"
)

// PeerStats is the runtime state of one peer (design 17.3, 13).
type PeerStats struct {
	LastHandshake time.Time // zero: never
	RxBytes       uint64
	TxBytes       uint64
}

// parseStats parses Device.IpcGet output into stats for peers (index = peer
// index), matching them by public_key; a peer the device does not list gets
// zero stats. Key lines are only compared, never stored or returned.
func parseStats(uapi string, peers []config.Peer) []PeerStats {
	res := make([]PeerStats, len(peers))
	cur := -1 // the peer of the current section; -1: none or unknown
	var sec, nsec int64
	// flush sets the handshake of the current peer from sec and nsec.
	flush := func() {
		if cur >= 0 && (sec != 0 || nsec != 0) {
			res[cur].LastHandshake = time.Unix(sec, nsec)
		}
		sec, nsec = 0, 0
	}
	for line := range strings.Lines(uapi) {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur = peerIndex(v, peers)
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur >= 0 {
				res[cur].RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur >= 0 {
				res[cur].TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	flush()
	return res
}

// peerIndex returns the index of the peer whose public key is the hex h; -1:
// none. The decoded bytes are only compared.
func peerIndex(h string, peers []config.Peer) int {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(config.Key{}) {
		return -1
	}
	for i, p := range peers {
		if bytes.Equal(b, p.PublicKey[:]) {
			return i
		}
	}
	return -1
}
