package tunnel

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/mrFokin/wgplex/internal/config"
)

const redacted = "(redacted)"

// uapiConfig is a UAPI configuration; it holds the private key, so every
// formatting path (String, GoString, Format, LogValue) prints "(redacted)".
type uapiConfig struct{ s string }

// reader returns the configuration text for Device.IpcSetOperation.
func (c uapiConfig) reader() io.Reader {
	return strings.NewReader(c.s)
}

// String returns "(redacted)".
func (c uapiConfig) String() string { return redacted }

// GoString returns "(redacted)", so %#v does not dump the field.
func (c uapiConfig) GoString() string { return redacted }

// Format writes "(redacted)" for every verb, including %+v and %x.
func (c uapiConfig) Format(f fmt.State, verb rune) {
	io.WriteString(f, redacted)
}

// LogValue makes slog print "(redacted)" in any handler.
func (c uapiConfig) LogValue() slog.Value { return slog.StringValue(redacted) }

// buildUAPI renders wg and endpoints as UAPI: private_key, listen_port (if
// set), replace_peers=true; per peer: public_key, preshared_key (if set),
// endpoint (if valid), persistent_keepalive_interval, replace_allowed_ips=true,
// allowed_ip per prefix. Keys are lowercase hex.
func buildUAPI(wg *config.WGConfig, endpoints []netip.AddrPort) uapiConfig {
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	line("private_key", hex.EncodeToString(wg.PrivateKey[:]))
	if wg.ListenPort != 0 {
		line("listen_port", strconv.Itoa(wg.ListenPort))
	}
	line("replace_peers", "true")
	for i, p := range wg.Peers {
		line("public_key", hex.EncodeToString(p.PublicKey[:]))
		if p.PresharedKey != (config.Key{}) {
			line("preshared_key", hex.EncodeToString(p.PresharedKey[:]))
		}
		if i < len(endpoints) && endpoints[i].IsValid() {
			line("endpoint", endpoints[i].String())
		}
		line("persistent_keepalive_interval", strconv.Itoa(p.PersistentKeepalive))
		line("replace_allowed_ips", "true")
		for _, ip := range p.AllowedIPs {
			line("allowed_ip", ip.String())
		}
	}
	return uapiConfig{b.String()}
}

// endpointUAPI is the UAPI text of SetEndpoint: public_key (lowercase hex),
// update_only=true, endpoint. It holds no private key.
func endpointUAPI(pub config.Key, ep netip.AddrPort) string {
	return "public_key=" + hex.EncodeToString(pub[:]) + "\nupdate_only=true\nendpoint=" + ep.String() + "\n"
}
