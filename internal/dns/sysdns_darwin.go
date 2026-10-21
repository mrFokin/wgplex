package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ErrFlush wraps the error of flushing the mDNSResponder cache returned by
// Capture and Release after the capture key itself was set or removed: the
// caller may log it and go on.
var ErrFlush = errors.New("flush the DNS cache")

// Capture makes 127.0.0.1 the system resolver (design 8): it sets CaptureKey
// with /usr/sbin/scutil (captureScript on stdin) and flushes the
// mDNSResponder cache (dscacheutil -flushcache, killall -HUP mDNSResponder).
// The key is read back: Capture fails unless ServerAddresses is exactly
// [127.0.0.1] and SupplementalMatchDomains exactly [""]. When only the flush
// fails, the error wraps ErrFlush.
func Capture() error {
	if _, err := scutil(captureScript()); err != nil {
		return fmt.Errorf("capture DNS: %w", err)
	}
	m, err := show(CaptureKey)
	if err != nil {
		return fmt.Errorf("capture DNS: %w", err)
	}
	if !slices.Equal(m["ServerAddresses"], []string{"127.0.0.1"}) ||
		!slices.Equal(m["SupplementalMatchDomains"], []string{""}) {
		return fmt.Errorf("capture DNS: %s was not set as expected: %q", CaptureKey, m)
	}
	return flush()
}

// Release removes the capture key (no error if it is absent) and flushes the
// cache. Called at stop and at start, after a crash (design 8). The key is
// read back: Release fails if it is still there. When only the flush fails,
// the error wraps ErrFlush.
func Release() error {
	if _, err := scutil("remove " + CaptureKey + "\n"); err != nil {
		return fmt.Errorf("release DNS: %w", err)
	}
	m, err := show(CaptureKey)
	if err != nil {
		return fmt.Errorf("release DNS: %w", err)
	}
	if len(m) > 0 {
		return fmt.Errorf("release DNS: %s is still set", CaptureKey)
	}
	return flush()
}

// Captured reports whether the capture key is set (a configd restart drops it).
func Captured() (bool, error) {
	m, err := show(CaptureKey)
	if err != nil {
		return false, fmt.Errorf("dns capture key: %w", err)
	}
	return len(m) > 0, nil
}

// SystemServers returns the DNS servers of the primary service: the
// PrimaryService of State:/Network/Global/IPv4, then ServerAddresses of
// Setup:/Network/Service/<id>/DNS, else of State:/Network/Service/<id>/DNS
// (systemServers, loopback addresses skipped). The capture key is never the
// primary service (it has no IPv4), so capturing does not change the result.
// No primary service or no servers is an error.
func SystemServers() ([]netip.Addr, error) {
	g, err := show("State:/Network/Global/IPv4")
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	ids := g["PrimaryService"]
	if len(ids) == 0 || ids[0] == "" {
		return nil, errors.New("system DNS: no primary network service")
	}
	id := ids[0]
	setup, err := show("Setup:/Network/Service/" + id + "/DNS")
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	state, err := show("State:/Network/Service/" + id + "/DNS")
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	servers := systemServers(setup, state)
	if len(servers) == 0 {
		return nil, fmt.Errorf("system DNS: service %s has no DNS servers", id)
	}
	return servers, nil
}

// PrimaryService returns PrimaryService of State:/Network/Global/IPv4;
// "" when there is none (no network). An error only when scutil fails.
func PrimaryService() (string, error) {
	g, err := show("State:/Network/Global/IPv4")
	if err != nil {
		return "", fmt.Errorf("primary service: %w", err)
	}
	if ids := g["PrimaryService"]; len(ids) > 0 {
		return ids[0], nil
	}
	return "", nil
}

// SystemResolver resolves via servers, bypassing the system resolver and so
// our own (design 6): for tunnel.ResolveEndpoints. It is a pure-Go resolver
// (PreferGo) whose Dial replaces the address with the servers, port 53.
// Successive dials take the servers in turn, so the resolver's retries reach
// the next server. No servers: every lookup fails.
func SystemResolver(servers []netip.Addr) *net.Resolver {
	servers = slices.Clone(servers)
	var next atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if len(servers) == 0 {
				return nil, errors.New("no system DNS servers")
			}
			s := servers[int(next.Add(1)-1)%len(servers)]
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(s.String(), strconv.Itoa(int(upstreamPort))))
		},
	}
}

// show returns the parsed value of key (parseScutil); an absent key gives an
// empty map.
func show(key string) (map[string][]string, error) {
	out, err := scutil("show " + key + "\n")
	if err != nil {
		return nil, err
	}
	return parseScutil(out), nil
}

// scutilTimeout bounds one scutil run: the daemon calls these under its
// operation lock.
const scutilTimeout = 5 * time.Second

// scutil runs /usr/sbin/scutil with script on stdin and returns its output;
// scutil is killed after scutilTimeout.
func scutil(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scutilTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// flush flushes the mDNSResponder cache (fact 9 of the Wirefork M5 plan); a failure
// wraps ErrFlush.
func flush() error {
	var errs []error
	for _, args := range [][]string{
		{"/usr/bin/dscacheutil", "-flushcache"},
		{"/usr/bin/killall", "-HUP", "mDNSResponder"},
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w: %s", args[0], err, strings.TrimSpace(string(out))))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrFlush, err)
	}
	return nil
}
