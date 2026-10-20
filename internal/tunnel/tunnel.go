// Package tunnel runs one WireGuard tunnel: wireguard-go device over its own
// utun, interface addresses and MTU from the .conf (design 5). Host routes to
// endpoints are not its business: the caller sets them before Start.
package tunnel

import (
	"fmt"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/mrFokin/wgplex/internal/config"
)

// Tunnel is a running tunnel.
type Tunnel struct {
	ifname string         // utunN chosen by the kernel
	dev    *device.Device // owns the utun; closing it removes the interface
}

// Start creates the utun, configures the device via UAPI, assigns addresses
// (MTU is set by CreateTUN) and brings it up. endpoints come from
// ResolveEndpoints; host routes to them must already be in place. On error
// everything created so far is torn down. Errors do not name the tunnel
// (the caller does), only the utun once it exists: "utun7: set up: ...".
func Start(name string, wg *config.WGConfig, endpoints []netip.AddrPort, log *slog.Logger) (*Tunnel, error) {
	tdev, err := tun.CreateTUN("utun", mtu(wg))
	if err != nil {
		return nil, fmt.Errorf("create utun: %w", err)
	}
	ifname, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, fmt.Errorf("utun name: %w", err)
	}

	keys := []config.Key{wg.PrivateKey}
	for _, p := range wg.Peers {
		keys = append(keys, p.PresharedKey)
	}
	// The device owns tdev from here on: dev.Close closes the utun too.
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), newLogger(log, name, keys...))
	fail := func(format string, args ...any) (*Tunnel, error) {
		dev.Close()
		return nil, fmt.Errorf("%s: %s", ifname, fmt.Sprintf(format, args...))
	}

	if err := dev.IpcSetOperation(buildUAPI(wg, endpoints).reader()); err != nil {
		// wireguard-go does not put key values into UAPI errors, but the
		// text is redacted anyway: it may end up in RPC replies (design 9.4).
		return fail("configure device: %s", newRedactor(keys...).Replace(err.Error()))
	}
	for _, p := range wg.Addresses {
		if err := addAddr(ifname, p); err != nil {
			return fail("add address %s: %v", p, err)
		}
	}
	if err := setUp(ifname); err != nil {
		return fail("set up: %v", err)
	}
	if err := dev.Up(); err != nil {
		return fail("device up: %v", err)
	}
	return &Tunnel{ifname: ifname, dev: dev}, nil
}

// Interface returns the utun name (utunN).
func (t *Tunnel) Interface() string {
	return t.ifname
}

// Stats returns the stats of peers (the .conf peers of this tunnel). The
// IpcGet text holds the private key: it is never logged or put into errors.
func (t *Tunnel) Stats(peers []config.Peer) ([]PeerStats, error) {
	uapi, err := t.dev.IpcGet()
	if err != nil {
		// IpcGet errors come from writing its own buffer, never from the text.
		return nil, fmt.Errorf("%s: get stats: %v", t.ifname, err)
	}
	return parseStats(uapi, peers), nil
}

// Rebind reopens the UDP sockets of the device (Device.BindUpdate) after a
// network change.
func (t *Tunnel) Rebind() error {
	if err := t.dev.BindUpdate(); err != nil {
		return fmt.Errorf("%s: rebind: %w", t.ifname, err)
	}
	return nil
}

// Rehandshake starts a handshake with every peer of peers (LookupPeer by
// public key); expire first drops the current keypairs (after a wake: the
// server dropped them, and the 5 s limit is lifted). Keys are never logged.
func (t *Tunnel) Rehandshake(peers []config.Peer, expire bool) {
	for _, p := range peers {
		peer := t.dev.LookupPeer(device.NoisePublicKey(p.PublicKey))
		if peer == nil {
			continue
		}
		if expire {
			peer.ExpireCurrentKeypairs()
		}
		// Errors are logged by wireguard-go itself; without expire a recent
		// attempt (under 5 s ago) makes this a no-op (M7 fact 8).
		peer.SendHandshakeInitiation(false)
	}
}

// SetEndpoint sets the endpoint of the peer with public key pub (UAPI
// update_only, endpointUAPI); the session and the other settings are kept.
// The key is never logged or put into errors.
func (t *Tunnel) SetEndpoint(pub config.Key, ep netip.AddrPort) error {
	if err := t.dev.IpcSet(endpointUAPI(pub, ep)); err != nil {
		// wireguard-go does not put key values into UAPI errors; redacted
		// anyway, as in Start (design 9.4).
		return fmt.Errorf("%s: set endpoint %s: %s", t.ifname, ep, newRedactor(pub).Replace(err.Error()))
	}
	return nil
}

// Close shuts down the device; the utun and its addresses are gone after it.
// It is idempotent.
func (t *Tunnel) Close() error {
	if t.dev != nil {
		t.dev.Close() // idempotent itself
	}
	return nil
}

// mtu returns wg.MTU or device.DefaultMTU (1420) when it is 0.
func mtu(wg *config.WGConfig) int {
	if wg.MTU == 0 {
		return device.DefaultMTU
	}
	return wg.MTU
}
