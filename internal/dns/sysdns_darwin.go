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

// Capture sends zones to our resolver (design 8): it sets CaptureKey through
// SCDynamicStore to captureValue(zones) (ServerAddresses [127.0.0.1],
// ServerPort Port, SupplementalMatchDomains zones, SupplementalMatchOrders
// matchOrder per zone, SupplementalMatchDomainsNoSearch 1), reads the key
// back (it must match exactly) and flushes the mDNSResponder cache
// (dscacheutil -flushcache, killall -HUP mDNSResponder). When only the flush
// fails, the error wraps ErrFlush.
//
// No zones is an error and leaves the key as it is: without zones there is
// no key (the caller calls Release); a key without domains is not written.
// Needs root.
func Capture(zones []string) error {
	if len(zones) == 0 {
		return errors.New("capture DNS: no zones")
	}
	s, err := openStore()
	if err != nil {
		return fmt.Errorf("capture DNS: %w", err)
	}
	defer s.close()
	want := captureValue(zones)
	if err := s.set(CaptureKey, want); err != nil {
		return fmt.Errorf("capture DNS: %w", err)
	}
	got, ok, err := s.get(CaptureKey)
	if err != nil {
		return fmt.Errorf("capture DNS: %w", err)
	}
	if !ok || !sameCapture(got, want) {
		return fmt.Errorf("capture DNS: %s was not set as expected (present %v, %d fields)", CaptureKey, ok, len(got))
	}
	return flush()
}

// Release removes the capture key (no error if it is absent) and flushes the
// cache. Called at stop and when there are no zones (design 8); at start a
// key left by the previous run is not removed but synced (design 4.1). The
// key is read back: Release fails if it is still there. When only the flush
// fails, the error wraps ErrFlush. Needs root.
func Release() error {
	s, err := openStore()
	if err != nil {
		return fmt.Errorf("release DNS: %w", err)
	}
	defer s.close()
	if err := s.remove(CaptureKey); err != nil {
		return fmt.Errorf("release DNS: %w", err)
	}
	_, ok, err := s.get(CaptureKey)
	if err != nil {
		return fmt.Errorf("release DNS: %w", err)
	}
	if ok {
		return fmt.Errorf("release DNS: %s is still set", CaptureKey)
	}
	return flush()
}

// Captured reports whether the capture key is set (a configd restart drops
// it) and its SupplementalMatchDomains, the zones currently captured. An
// absent key gives ok false and no zones; a key without the field gives ok
// true and no zones.
func Captured() (zones []string, ok bool, err error) {
	s, err := openStore()
	if err != nil {
		return nil, false, fmt.Errorf("dns capture key: %w", err)
	}
	defer s.close()
	m, ok, err := s.get(CaptureKey)
	if err != nil {
		return nil, false, fmt.Errorf("dns capture key: %w", err)
	}
	return m["SupplementalMatchDomains"], ok, nil
}

// scutilTimeout bounds the run of `scutil --dns`: the daemon calls
// VerifyZones under its operation lock.
const scutilTimeout = 5 * time.Second

// VerifyZones checks that the system resolver configuration sends zones to
// our resolver (design 8): it runs `scutil --dns` (read only, killed after
// scutilTimeout) and parses the output with parseScutilDNS. Every zone must
// have a resolver block whose domain is the zone, nameserver[0] 127.0.0.1
// and port Port; otherwise the error names the zones missing (the first
// maxNamed of them). No zones: nil, scutil is not run.
func VerifyZones(zones []string) error {
	if len(zones) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), scutilTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return fmt.Errorf("scutil --dns: %w", err)
	}
	return missingError(missingZones(parseScutilDNS(string(out)), zones), len(zones))
}

// SystemServers returns the DNS servers of the primary service: the
// PrimaryService of State:/Network/Global/IPv4, then ServerAddresses of
// Setup:/Network/Service/<id>/DNS, else of State:/Network/Service/<id>/DNS
// (systemServers, invalid addresses skipped). The capture key is never the
// primary service (it has no IPv4), so capturing does not change the result.
// No primary service or no servers is an error.
func SystemServers() ([]netip.Addr, error) {
	s, err := openStore()
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	defer s.close()
	id, err := primaryService(s)
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	if id == "" {
		return nil, errors.New("system DNS: no primary network service")
	}
	setup, _, err := s.get("Setup:/Network/Service/" + id + "/DNS")
	if err != nil {
		return nil, fmt.Errorf("system DNS: %w", err)
	}
	state, _, err := s.get("State:/Network/Service/" + id + "/DNS")
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
// "" when there is none (no network). An error only when the store fails.
func PrimaryService() (string, error) {
	s, err := openStore()
	if err != nil {
		return "", fmt.Errorf("primary service: %w", err)
	}
	defer s.close()
	id, err := primaryService(s)
	if err != nil {
		return "", fmt.Errorf("primary service: %w", err)
	}
	return id, nil
}

func primaryService(s *scStore) (string, error) {
	g, _, err := s.get("State:/Network/Global/IPv4")
	if err != nil {
		return "", err
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

// flush flushes the mDNSResponder cache; a failure
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
