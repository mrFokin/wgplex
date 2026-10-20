package health

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Tests follow design 8 "HTTP" and the M11 plan ("Ход работы", step 3): the
// error of a failed GET in Reason is without `Get "<url>":` (Reason names
// the URL), a timeout is "timeout after 5s".

const m11ErrURL = "https://example.com/health?x=1"

func m11HTTPErr(t *testing.T, ctx context.Context, err error) (got string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("httpErr panicked: %v", r)
		}
	}()
	return httpErr(ctx, err)
}

func TestM11HTTPErrTimeout(t *testing.T) {
	// Check runs within HTTPTimeout: the context of the request has expired.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	cases := []struct {
		name string
		err  error
	}{
		{"url.Error deadline", &url.Error{Op: "Get", URL: m11ErrURL, Err: context.DeadlineExceeded}},
		{"bare deadline", context.DeadlineExceeded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m11HTTPErr(t, ctx, c.err)
			if !strings.Contains(got, "timeout after 5s") {
				t.Errorf("httpErr = %q, want %q", got, "timeout after 5s")
			}
			if strings.Contains(got, m11ErrURL) || strings.Contains(got, "Get ") {
				t.Errorf("httpErr = %q, want no method and URL", got)
			}
		})
	}
}

func TestM11HTTPErrStripsGet(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // substring kept
	}{
		{"connection refused", &url.Error{Op: "Get", URL: m11ErrURL, Err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused")}, "connection refused"},
		{"tls", &url.Error{Op: "Get", URL: m11ErrURL, Err: errors.New("tls: failed to verify certificate: x509: certificate is valid for other.example, not example.com")}, "certificate"},
		{"resolve", &url.Error{Op: "Get", URL: m11ErrURL, Err: errors.New("lookup example.com: no such host")}, "no such host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m11HTTPErr(t, context.Background(), c.err)
			if strings.Contains(got, `Get "`) || strings.Contains(got, m11ErrURL) {
				t.Errorf("httpErr = %q, want without `Get %q:`", got, m11ErrURL)
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("httpErr = %q, want it to keep %q", got, c.want)
			}
			if strings.Contains(got, "timeout") {
				t.Errorf("httpErr = %q, not a timeout", got)
			}
		})
	}
}
