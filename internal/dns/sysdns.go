package dns

import (
	"net/netip"
	"slices"
	"strconv"
)

// CaptureKey is the synthetic service of wgplex in SCDynamicStore
// (design 8); the UUID is our own (design 4.1) and never changes, so a key
// left by a crash is found and removed at the next start.
const CaptureKey = "State:/Network/Service/50054742-C5CE-4C74-866E-FBD7AC0A16AE/DNS"

// Port is the port of our resolver on 127.0.0.1 (design 8): ServerPort of
// CaptureKey. Not 53, so the resolver lives next to another one on :53;
// not 5353 (mDNS) nor 5354.
const Port = 5301

// matchOrder is the SupplementalMatchOrders value written for every zone:
// with the same zone in another service the order decides the winner
// (M0 D6, D7). That the smaller value wins is not verified yet: it is
// checked in the VM in M4 (plan m4-dns, decision 10).
const matchOrder = 1

// captureValue returns the dictionary of CaptureKey for zones (design 8):
// ServerAddresses [127.0.0.1], ServerPort Port, SupplementalMatchDomains
// zones (as given), SupplementalMatchOrders matchOrder per zone and
// SupplementalMatchDomainsNoSearch 1. A value is a string, an int, a
// []string or an []int: the types the SC layer writes.
func captureValue(zones []string) map[string]any {
	orders := make([]int, len(zones))
	for i := range orders {
		orders[i] = matchOrder
	}
	return map[string]any{
		"ServerAddresses":                  []string{"127.0.0.1"},
		"ServerPort":                       Port,
		"SupplementalMatchDomains":         slices.Clone(zones),
		"SupplementalMatchOrders":          orders,
		"SupplementalMatchDomainsNoSearch": 1,
	}
}

// sameCapture reports whether got, a dictionary read back from the store
// (scalars as one-element slices, numbers in decimal), holds exactly the
// fields of want (a captureValue) and no others. An empty array and an
// absent field differ.
func sameCapture(got map[string][]string, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok || !slices.Equal(g, valueStrings(w)) {
			return false
		}
	}
	return true
}

// valueStrings is v of captureValue as the SC layer reads it back: a scalar
// is a one-element slice, a number is decimal; an empty array is an empty,
// non-nil slice.
func valueStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case int:
		return []string{strconv.Itoa(v)}
	case []string:
		return append([]string{}, v...)
	case []int:
		res := []string{}
		for _, n := range v {
			res = append(res, strconv.Itoa(n))
		}
		return res
	}
	return nil
}

// systemServers returns ServerAddresses of setup if present, else of state
// (the DNS keys of the primary service); invalid addresses are skipped.
// Loopback addresses are kept (design 8): our resolver listens on Port and
// asks the system servers on :53, so 127.0.0.1 is a local upstream
// (dnscrypt-proxy, dnsmasq), not a loop back to us. The choice between setup
// and state is made before skipping: manual servers that are all invalid
// give none, not the DHCP ones.
func systemServers(setup, state map[string][]string) []netip.Addr {
	vals := setup["ServerAddresses"]
	if len(vals) == 0 {
		vals = state["ServerAddresses"]
	}
	var res []netip.Addr
	for _, v := range vals {
		if a, err := netip.ParseAddr(v); err == nil {
			res = append(res, a)
		}
	}
	return res
}
