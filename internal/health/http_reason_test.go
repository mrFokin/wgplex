package health

import (
	"net/netip"
	"testing"
	"time"
)

// Tests follow design 9 "HTTP" and the Wirefork M11 plan ("Модель → HTTP-проверка",
// "Сигнатуры → internal/health"), not the implementation: failures and the
// verdict of an HTTP check are as of ping; the reason is
// `http <url>: N failures (<last error>)`, without parentheses when Err is
// empty; the ping reason is unchanged.

const m11URL = "https://example.com/health?x=1"

func m11Fail(err string) PingResult { return PingResult{Done: true, Err: err} }

// m11Observe feeds results at Interval steps from m7T0 with the given
// check address and URL.
func m11Observe(h Health, check netip.Addr, url string, results ...PingResult) Health {
	for i, r := range results {
		h = h.Observe(Sample{At: m7At(time.Duration(i+1) * Interval), Ping: r, Check: check, URL: url})
	}
	return h
}

func TestM11HTTPTimeout(t *testing.T) {
	if HTTPTimeout != 5*time.Second {
		t.Errorf("HTTPTimeout = %v, want 5s (design 9)", HTTPTimeout)
	}
}

// design 9 "HTTP": dead after 3 failures in a row with the reason naming the
// URL, the count and the last error.
func TestM11HTTPReason(t *testing.T) {
	defer m7NoPanic(t)
	cases := []struct {
		name    string
		check   netip.Addr
		url     string
		results []PingResult
		want    string
	}{
		{
			name:    "last error",
			url:     m11URL,
			results: []PingResult{m11Fail("dial tcp: i/o timeout"), m11Fail("tls: handshake failure"), m11Fail("context deadline exceeded")},
			want:    "http " + m11URL + ": 3 failures (context deadline exceeded)",
		},
		{
			name:    "no error text",
			url:     m11URL,
			results: []PingResult{m11Fail(""), m11Fail(""), m11Fail("")},
			want:    "http " + m11URL + ": 3 failures",
		},
		{
			name:    "error only on an earlier failure",
			url:     m11URL,
			results: []PingResult{m11Fail("no such host"), m11Fail("no such host"), m11Fail("")},
			want:    "http " + m11URL + ": 3 failures",
		},
		{
			name:    "URL with an IP literal",
			url:     "http://10.255.255.1/",
			results: []PingResult{m11Fail("e1"), m11Fail("e2"), m11Fail("connect: no route to host")},
			want:    "http http://10.255.255.1/: 3 failures (connect: no route to host)",
		},
		{
			// design 9: the ping reason is unchanged.
			name:    "ping",
			check:   netip.MustParseAddr("1.1.1.1"),
			results: []PingResult{m7PingFail, m7PingFail, m7PingFail},
			want:    "ping 1.1.1.1: 3 failures",
		},
		{
			name:    "ping IPv6",
			check:   netip.MustParseAddr("2606:4700:4700::1111"),
			results: []PingResult{m7PingFail, m7PingFail, m7PingFail},
			want:    "ping 2606:4700:4700::1111: 3 failures",
		},
	}
	for _, c := range cases {
		h := m11Observe(New(m7T0), c.check, c.url, c.results...)
		if h.State != Dead {
			t.Errorf("%s: State %s, want Dead", c.name, m7StateName(h.State))
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
func TestM11HTTPVerdict(t *testing.T) {
	defer m7NoPanic(t)
	h := m11Observe(New(m7T0), netip.Addr{}, m11URL, m11Fail("e1"), m11Fail("e2"))
	if h.State == Dead || h.Reason != "" || h.Fails != 2 {
		t.Errorf("2 failures: State %s Reason %q Fails %d, want not dead, no reason, 2",
			m7StateName(h.State), h.Reason, h.Fails)
	}

	h = m11Observe(New(m7T0), netip.Addr{}, m11URL,
		m11Fail("e1"), m11Fail("e2"), m11Fail("e3"), m7PingOK(42*time.Millisecond))
	if h.State != Alive || h.Reason != "" || h.Fails != 0 {
		t.Errorf("dead then OK: State %s Reason %q Fails %d, want Alive, no reason, 0",
			m7StateName(h.State), h.Reason, h.Fails)
	}
	if h.RTT != 42*time.Millisecond {
		t.Errorf("RTT %v, want 42ms", h.RTT)
	}
	if !h.LastOK.Equal(m7At(4 * Interval)) {
		t.Errorf("LastOK %v, want %v", h.LastOK, m7At(4*Interval))
	}
}
