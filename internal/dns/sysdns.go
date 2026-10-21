package dns

import (
	"net/netip"
	"strings"
)

// CaptureKey is the synthetic service of wgplex in SCDynamicStore
// (design 8); the UUID is our own (design 4.1) and never changes, so a key
// left by a crash is found and removed at the next start.
const CaptureKey = "State:/Network/Service/50054742-C5CE-4C74-866E-FBD7AC0A16AE/DNS"

// parseScutil parses the dictionary printed by `scutil` "show <key>":
// scalar values and arrays of scalars by key; nested dictionaries are skipped.
// A scalar is a one-element slice; an array keeps the order of its indexes.
//
// "No such key" (or any output without a dictionary) gives an empty map. A
// line is "key : value", the value being everything after the first " : ";
// an empty value ("key : ", trimmed to "key :") is the empty string, kept
// both as a scalar and as an array element ("0 : " → ""). An array of
// dictionaries is skipped as a whole.
func parseScutil(out string) map[string][]string {
	res := map[string][]string{}
	var (
		depth  int      // open braces
		arrKey string   // the top-level array being read; "": none
		arr    []string // its values
		arrBad bool     // it holds a nested container: skipped
	)
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if t == "}" {
			if depth == 2 && arrKey != "" {
				if !arrBad {
					res[arrKey] = arr
				}
				arrKey = ""
			}
			if depth > 0 {
				depth--
			}
			continue
		}
		k, v, ok := strings.Cut(t, " : ")
		if !ok && strings.HasSuffix(t, " :") {
			k, v, ok = strings.TrimSuffix(t, " :"), "", true
		}
		opens := strings.HasSuffix(t, "{")
		switch {
		case !ok: // "<dictionary> {" or "No such key"
		case depth == 1 && v == "<array> {":
			arrKey, arr, arrBad = k, []string{}, false
		case depth == 1 && !opens:
			res[k] = []string{v}
		case depth == 2 && arrKey != "":
			if opens {
				arrBad = true
			} else {
				arr = append(arr, v)
			}
		}
		if opens {
			depth++
		}
	}
	return res
}

// systemServers returns ServerAddresses of setup if present, else of state
// (the DNS keys of the primary service); invalid and loopback addresses
// (127.0.0.0/8, ::1, also IPv4-mapped) are skipped: a loopback upstream would
// send our queries back to our own resolver on 127.0.0.1. The choice between
// setup and state is made before skipping: manual servers that are all
// loopback give none, not the DHCP ones.
func systemServers(setup, state map[string][]string) []netip.Addr {
	vals := setup["ServerAddresses"]
	if len(vals) == 0 {
		vals = state["ServerAddresses"]
	}
	var res []netip.Addr
	for _, v := range vals {
		if a, err := netip.ParseAddr(v); err == nil && !a.Unmap().IsLoopback() {
			res = append(res, a)
		}
	}
	return res
}

// captureScript returns the scutil stdin that sets the capture key
// (CaptureKey, ServerAddresses 127.0.0.1, SupplementalMatchDomains ""):
// d.init, d.add of both keys, set CaptureKey. The empty domain is written as
// `""`: scutil's tokenizer takes quotes, so the array holds one empty string
// and "show" prints it as "0 : " (assumed, checked by Capture reading the key
// back).
func captureScript() string {
	return "d.init\n" +
		"d.add ServerAddresses * 127.0.0.1\n" +
		"d.add SupplementalMatchDomains * \"\"\n" +
		"set " + CaptureKey + "\n"
}
