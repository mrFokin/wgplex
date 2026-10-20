package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Tests follow design 9.4 (a key prints "(redacted)" under any formatting,
// %v, %#v and JSON included) and decision 13 of the M3 plan (Format prints
// "(redacted)" for every verb). All keys are generated per test.

// leakForms returns substrings that would reveal k: hex and base64 of the
// whole key, raw bytes (%s of a byte array) of every eight consecutive
// bytes and, for every four consecutive bytes, the way fmt prints byte array
// elements under each integer and character verb. Windows are long enough
// that random key bytes do not collide with the rest of the output.
func leakForms(k Key) []string {
	forms := []string{
		hex.EncodeToString(k[:]),
		strings.ToUpper(hex.EncodeToString(k[:])),
		base64.StdEncoding.EncodeToString(k[:]),
		base64.URLEncoding.EncodeToString(k[:]),
		base64.RawStdEncoding.EncodeToString(k[:]),
		base64.RawURLEncoding.EncodeToString(k[:]),
	}
	for i := 0; i+8 <= len(k); i++ {
		forms = append(forms, string(k[i:i+8]))
	}
	verbs := []string{"%d", "%o", "%#o", "%b", "%x", "%#x", "%X", "%#X", "%c", "%q", "%U", "%#U"}
	for i := 0; i+4 <= len(k); i++ {
		w := k[i : i+4]
		for _, v := range verbs {
			forms = append(forms, fmt.Sprintf(v+" "+v+" "+v+" "+v, w[0], w[1], w[2], w[3]))
		}
	}
	return forms
}

// checkNoLeak fails if out contains any form of keys; with redacted set it
// also requires the "(redacted)" marker.
func checkNoLeak(t *testing.T, what, out string, redacted bool, keys ...Key) {
	t.Helper()
	for _, k := range keys {
		for _, f := range leakForms(k) {
			if strings.Contains(out, f) {
				t.Errorf("%s = %q leaks key bytes (%q)", what, out, f)
				return
			}
		}
	}
	if redacted && !strings.Contains(out, "(redacted)") {
		t.Errorf("%s = %q, want it to contain (redacted)", what, out)
	}
}

var keyVerbs = []string{
	"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U",
	"%40v", "%-40s", "%#x", "%# x", "% x", "%08d", "%+d", "%#o", "%+q", "%#q", "%#U", "%12x", "%-12d",
}

// design 9.4, decision 13: a bare Key and a *Key print "(redacted)" under
// every verb, width and flag.
func TestKeyFormat(t *testing.T) {
	k, _ := genKey(t)
	for _, v := range keyVerbs {
		t.Run(v, func(t *testing.T) {
			checkNoLeak(t, "Sprintf("+v+", key)", fmt.Sprintf(v, k), true, k)
			checkNoLeak(t, "Sprintf("+v+", &key)", fmt.Sprintf(v, &k), true, k)
			checkNoLeak(t, "Sprint", fmt.Sprint(k), true, k)
			checkNoLeak(t, "Errorf("+v+")", fmt.Errorf("bad key "+v, k).Error(), true, k)
		})
	}
}

// design 9.4: keys stay redacted inside structs, slices, arrays, maps and
// behind pointers, including the real configuration types.
func TestKeyFormatNested(t *testing.T) {
	priv, _ := genKey(t)
	pub, _ := genKey(t)
	psk, _ := genKey(t)
	keys := []Key{priv, pub, psk}
	wg := WGConfig{
		PrivateKey: priv,
		Peers:      []Peer{{PublicKey: pub, PresharedKey: psk, Endpoint: "198.51.100.7:51820"}},
	}
	type holder struct {
		Name string
		K    Key
		Ks   []Key
	}
	h := holder{Name: "nl", K: priv, Ks: []Key{pub, psk}}
	values := []struct {
		name string
		v    any
	}{
		{"struct", h},
		{"pointer to struct", &h},
		{"slice", []Key{priv, pub, psk}},
		{"array", [3]Key{priv, pub, psk}},
		{"map", map[string]Key{"priv": priv, "pub": pub, "psk": psk}},
		{"slice of any", []any{priv, &pub, psk}},
		{"WGConfig", wg},
		{"pointer to WGConfig", &wg},
		{"[]Peer", wg.Peers},
	}
	for _, val := range values {
		for _, v := range keyVerbs {
			t.Run(val.name+"/"+v, func(t *testing.T) {
				checkNoLeak(t, "Sprintf("+v+")", fmt.Sprintf(v, val.v), true, keys...)
			})
		}
	}
}

// A pointer nested in a struct prints as an address, never as key bytes.
func TestKeyFormatNestedPointer(t *testing.T) {
	k, _ := genKey(t)
	v := struct{ K *Key }{&k}
	for _, verb := range keyVerbs {
		checkNoLeak(t, "Sprintf("+verb+")", fmt.Sprintf(verb, v), false, k)
	}
}

// design 9.4: JSON never carries key bytes.
func TestKeyJSON(t *testing.T) {
	priv, _ := genKey(t)
	pub, _ := genKey(t)
	psk, _ := genKey(t)
	keys := []Key{priv, pub, psk}
	wg := WGConfig{
		PrivateKey: priv,
		Peers:      []Peer{{PublicKey: pub, PresharedKey: psk}},
	}
	values := []struct {
		name string
		v    any
	}{
		{"key", priv},
		{"pointer to key", &priv},
		{"slice", []Key{priv, pub, psk}},
		{"array", [2]Key{priv, pub}},
		{"map value", map[string]Key{"k": psk}},
		{"struct", struct{ K, P Key }{priv, pub}},
		{"struct with pointer", struct{ K *Key }{&psk}},
		{"WGConfig", wg},
		{"pointer to WGConfig", &wg},
	}
	for _, val := range values {
		t.Run(val.name, func(t *testing.T) {
			b, err := json.Marshal(val.v)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			checkNoLeak(t, "json.Marshal", string(b), true, keys...)
		})
	}
}
