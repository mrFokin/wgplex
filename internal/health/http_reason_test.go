package health

import (
	"net/netip"
	"testing"
	"time"
)

// Tests follow design 9 "HTTP" ("Модель → HTTP-проверка",
// "Сигнатуры → internal/health"), not the implementation: failures and the
// verdict of an HTTP check are as of ping; the reason is
// `http <url>: N failures (<last error>)`, without parentheses when Err is
// empty; the ping reason is unchanged.

const checkURL = "https://example.com/health?x=1"

func failResult(err string) PingResult { return PingResult{Done: true, Err: err} }

// observeCheck feeds results at Interval steps from t0 with the given
// check address and URL.
func observeCheck(h Health, check netip.Addr, url string, results ...PingResult) Health {
	for i, r := range results {
		h = h.Observe(Sample{At: testTime(time.Duration(i+1) * Interval), Ping: r, Check: check, URL: url})
	}
	return h
}

func TestHTTPTimeout(t *testing.T) {
	if HTTPTimeout != 5*time.Second {
		t.Errorf("HTTPTimeout = %v, want 5s (design 9)", HTTPTimeout)
	}
}

// design 9 "HTTP": dead after 3 failures in a row with the reason naming the
// URL, the count and the last error.
func TestHTTPReason(t *testing.T) {
	defer noPanic(t)
	cases := []struct {
		name    string
		check   netip.Addr
		url     string
		results []PingResult
		want    string
	}{
		{
			name:    "last error",
			url:     checkURL,
			results: []PingResult{failResult("dial tcp: i/o timeout"), failResult("tls: handshake failure"), failResult("context deadline exceeded")},
			want:    "http " + checkURL + ": 3 failures (context deadline exceeded)",
		},
		{
			name:    "no error text",
			url:     checkURL,
			results: []PingResult{failResult(""), failResult(""), failResult("")},
			want:    "http " + checkURL + ": 3 failures",
		},
		{
			name:    "error only on an earlier failure",
			url:     checkURL,
			results: []PingResult{failResult("no such host"), failResult("no such host"), failResult("")},
			want:    "http " + checkURL + ": 3 failures",
		},
		{
			name:    "URL with an IP literal",
			url:     "http://10.255.255.1/",
			results: []PingResult{failResult("e1"), failResult("e2"), failResult("connect: no route to host")},
			want:    "http http://10.255.255.1/: 3 failures (connect: no route to host)",
		},
		{
			// design 9: the ping reason is unchanged.
			name:    "ping",
			check:   netip.MustParseAddr("1.1.1.1"),
			results: []PingResult{pingFail, pingFail, pingFail},
			want:    "ping 1.1.1.1: 3 failures",
		},
		{
			name:    "ping IPv6",
			check:   netip.MustParseAddr("2606:4700:4700::1111"),
			results: []PingResult{pingFail, pingFail, pingFail},
			want:    "ping 2606:4700:4700::1111: 3 failures",
		},
	}
	for _, c := range cases {
		h := observeCheck(New(t0), c.check, c.url, c.results...)
		if h.State != Dead {
			t.Errorf("%s: State %s, want Dead", c.name, stateName(h.State))
		}
		if h.Reason != c.want {
			t.Errorf("%s: Reason %q, want %q", c.name, h.Reason, c.want)
		}
		if h.Fails != 3 {
			t.Errorf("%s: Fails %d, want 3", c.name, h.Fails)
		}
	}
}

// design 9: the verdict of an HTTP check is as of ping: not dead after 2
// failures, alive after 1 success with its RTT; a success resets the count.
func TestHTTPVerdict(t *testing.T) {
	defer noPanic(t)
	h := observeCheck(New(t0), netip.Addr{}, checkURL, failResult("e1"), failResult("e2"))
	if h.State == Dead || h.Reason != "" || h.Fails != 2 {
		t.Errorf("2 failures: State %s Reason %q Fails %d, want not dead, no reason, 2",
			stateName(h.State), h.Reason, h.Fails)
	}

	h = observeCheck(New(t0), netip.Addr{}, checkURL,
		failResult("e1"), failResult("e2"), failResult("e3"), pingOK(42*time.Millisecond))
	if h.State != Alive || h.Reason != "" || h.Fails != 0 {
		t.Errorf("dead then OK: State %s Reason %q Fails %d, want Alive, no reason, 0",
			stateName(h.State), h.Reason, h.Fails)
	}
	if h.RTT != 42*time.Millisecond {
		t.Errorf("RTT %v, want 42ms", h.RTT)
	}
	if !h.LastOK.Equal(testTime(4 * Interval)) {
		t.Errorf("LastOK %v, want %v", h.LastOK, testTime(4*Interval))
	}
}
