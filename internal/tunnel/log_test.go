package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/mrFokin/wgplex/internal/config"
)

type logEntry struct {
	Level  string `json:"level"`
	Msg    string `json:"msg"`
	Tunnel string `json:"tunnel"`
}

func logEntries(t *testing.T, buf *bytes.Buffer) []logEntry {
	t.Helper()
	var out []logEntry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e logEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func jsonLogger(buf *bytes.Buffer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level}))
}

// Wirefork plan M3: Verbosef → Debug, Errorf → Warn, attribute tunnel=name; the
// message is the formatted text.
func TestNewLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(jsonLogger(&buf, slog.LevelDebug), "nl")
	l.Verbosef("peer(%s) - Sending handshake initiation", "AbCd…WxYz")
	l.Errorf("Failed to send data packets: %v", "no route to host")

	got := logEntries(t, &buf)
	want := []logEntry{
		{Level: "DEBUG", Msg: "peer(AbCd…WxYz) - Sending handshake initiation", Tunnel: "nl"},
		{Level: "WARN", Msg: "Failed to send data packets: no route to host", Tunnel: "nl"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Verbose output is Debug: an Info-level handler drops it, Errorf still passes.
func TestNewLoggerInfoLevelDropsVerbose(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(jsonLogger(&buf, slog.LevelInfo), "de")
	l.Verbosef("Routine: receive incoming %s - started", "v4")
	l.Errorf("UDP bind has been updated")
	got := logEntries(t, &buf)
	if len(got) != 1 || got[0].Level != "WARN" || got[0].Tunnel != "de" {
		t.Errorf("got %+v, want a single WARN entry for tunnel de", got)
	}
}

// design 10.1: keys never get into logs; Wirefork plan M3: any hex or base64 form of
// the given keys in a message is replaced with "(redacted)".
func TestNewLoggerRedactsKeys(t *testing.T) {
	priv, psk := testKey(t), testKey(t)
	hexPriv, b64Priv := hex.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(priv[:])
	hexPSK, b64PSK := hex.EncodeToString(psk[:]), base64.StdEncoding.EncodeToString(psk[:])

	tests := []struct {
		name   string
		format string
		args   []any
		want   string
	}{
		{"hex in format", "private_key=" + hexPriv, nil, "private_key=(redacted)"},
		{"hex in argument", "set %s", []any{"private_key=" + hexPriv}, "set private_key=(redacted)"},
		{"hex via %x", "key %x end", []any{priv[:]}, "key (redacted) end"},
		{"base64 in argument", "PrivateKey = %s", []any{b64Priv}, "PrivateKey = (redacted)"},
		{"second key, base64", "PresharedKey = %s", []any{b64PSK}, "PresharedKey = (redacted)"},
		{"second key, hex", "preshared_key=%s", []any{hexPSK}, "preshared_key=(redacted)"},
		{"several occurrences", "%s %s %s", []any{hexPriv, b64PSK, hexPriv}, "(redacted) (redacted) (redacted)"},
		{"no key: unchanged", "peer(%s) - Received handshake response", []any{"AbCd…WxYz"}, "peer(AbCd…WxYz) - Received handshake response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, lvl := range []string{"DEBUG", "WARN"} {
				var buf bytes.Buffer
				l := newLogger(jsonLogger(&buf, slog.LevelDebug), "nl", priv, psk)
				if lvl == "DEBUG" {
					l.Verbosef(tt.format, tt.args...)
				} else {
					l.Errorf(tt.format, tt.args...)
				}
				raw := buf.String()
				for _, s := range []string{hexPriv, b64Priv, hexPSK, b64PSK} {
					if strings.Contains(raw, s) {
						t.Errorf("%s: log leaks a key: %s", lvl, raw)
					}
				}
				got := logEntries(t, &buf)
				if len(got) != 1 {
					t.Fatalf("%s: got %d entries, want 1", lvl, len(got))
				}
				if got[0].Msg != tt.want || got[0].Level != lvl || got[0].Tunnel != "nl" {
					t.Errorf("%s: got %+v, want msg %q", lvl, got[0], tt.want)
				}
			}
		})
	}
}

// formKey returns a generated key whose base64 forms contain '+' and '/'
// (bytes fb ef be ff ff ff encode to "++++////"), so the standard and URL
// alphabets differ, and whose hex forms contain letters.
func formKey(t *testing.T) config.Key {
	t.Helper()
	k := testKey(t)
	copy(k[3:9], []byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff})
	return k
}

// design 10.1, go-dev decision 5 of Wirefork M3 step 2: every textual form of the
// private key and the PSK is redacted — hex in both cases, standard and URL
// base64, with and without padding.
func TestNewLoggerRedactsKeyForms(t *testing.T) {
	priv, psk := formKey(t), formKey(t)
	forms := []struct {
		name string
		enc  func(config.Key) string
	}{
		{"hex lower", func(k config.Key) string { return hex.EncodeToString(k[:]) }},
		{"hex upper", func(k config.Key) string { return strings.ToUpper(hex.EncodeToString(k[:])) }},
		{"base64 std", func(k config.Key) string { return base64.StdEncoding.EncodeToString(k[:]) }},
		{"base64 URL", func(k config.Key) string { return base64.URLEncoding.EncodeToString(k[:]) }},
		{"base64 std unpadded", func(k config.Key) string { return base64.RawStdEncoding.EncodeToString(k[:]) }},
		{"base64 URL unpadded", func(k config.Key) string { return base64.RawURLEncoding.EncodeToString(k[:]) }},
	}
	var all []string
	for _, f := range forms {
		all = append(all, f.enc(priv), f.enc(psk))
	}
	if b := base64.StdEncoding.EncodeToString(priv[:]); !strings.Contains(b, "++++////") {
		t.Fatalf("test key base64 %q lacks \"++++////\"", b)
	}

	for _, f := range forms {
		for _, k := range []struct {
			name string
			key  config.Key
		}{{"private key", priv}, {"preshared key", psk}} {
			t.Run(f.name+"/"+k.name, func(t *testing.T) {
				s := f.enc(k.key)
				for _, lvl := range []string{"DEBUG", "WARN"} {
					var buf bytes.Buffer
					l := newLogger(jsonLogger(&buf, slog.LevelDebug), "nl", priv, psk)
					if lvl == "DEBUG" {
						l.Verbosef("key=%s end", s)
					} else {
						l.Errorf("key=%s end", s)
					}
					raw := buf.String()
					got := logEntries(t, &buf)
					if len(got) != 1 {
						t.Fatalf("%s: got %d entries, want 1", lvl, len(got))
					}
					for _, leak := range all {
						if strings.Contains(raw, leak) || strings.Contains(got[0].Msg, leak) {
							t.Errorf("%s: log leaks a key form: %s", lvl, raw)
						}
					}
					if got[0].Msg != "key=(redacted) end" {
						t.Errorf("%s: msg %q, want %q", lvl, got[0].Msg, "key=(redacted) end")
					}
				}
			})
		}
	}
}

// Without keys the logger passes messages through unchanged.
func TestNewLoggerNoKeys(t *testing.T) {
	var buf bytes.Buffer
	l := newLogger(jsonLogger(&buf, slog.LevelDebug), "home")
	l.Verbosef("Interface state was %s, requested %s", "Down", "Up")
	got := logEntries(t, &buf)
	if len(got) != 1 || got[0].Msg != "Interface state was Down, requested Up" || got[0].Tunnel != "home" {
		t.Errorf("got %+v", got)
	}
}

// device.Logger functions must be safe for concurrent use (run with -race).
func TestNewLoggerConcurrent(t *testing.T) {
	var buf syncBuffer
	l := newLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		"nl", testKey(t))
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				if j%2 == 0 {
					l.Verbosef("worker %d message %d", i, j)
				} else {
					l.Errorf("worker %d error %d", i, j)
				}
			}
		}()
	}
	wg.Wait()
	if n := strings.Count(buf.String(), "\n"); n != 400 {
		t.Errorf("got %d lines, want 400", n)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
