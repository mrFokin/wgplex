package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"golang.zx2c4.com/wireguard/device"

	"github.com/mrFokin/wgplex/internal/config"
)

// newLogger adapts wireguard-go logging to slog: Verbosef → Debug, Errorf →
// Warn, attribute tunnel=name. Any hex or base64 form of the given keys in a
// message is replaced with "(redacted)" as a safety net (design 9.4).
func newLogger(l *slog.Logger, name string, keys ...config.Key) *device.Logger {
	l = l.With("tunnel", name)
	red := newRedactor(keys...)
	logf := func(level slog.Level) func(string, ...any) {
		return func(format string, args ...any) {
			ctx := context.Background()
			if !l.Enabled(ctx, level) {
				return
			}
			l.Log(ctx, level, red.Replace(fmt.Sprintf(format, args...)))
		}
	}
	return &device.Logger{
		Verbosef: logf(slog.LevelDebug),
		Errorf:   logf(slog.LevelWarn),
	}
}

// newRedactor returns a replacer of every textual form of keys (hex in both
// cases, standard and URL base64 with and without padding) with "(redacted)".
// Zero keys (an absent preshared key) are skipped.
func newRedactor(keys ...config.Key) *strings.Replacer {
	var pairs []string
	for _, k := range keys {
		if k == (config.Key{}) {
			continue
		}
		h := hex.EncodeToString(k[:])
		// Padded forms go first: Replacer tries old strings in argument order.
		for _, s := range []string{
			base64.StdEncoding.EncodeToString(k[:]),
			base64.URLEncoding.EncodeToString(k[:]),
			base64.RawStdEncoding.EncodeToString(k[:]),
			base64.RawURLEncoding.EncodeToString(k[:]),
			h,
			strings.ToUpper(h),
		} {
			pairs = append(pairs, s, redacted)
		}
	}
	return strings.NewReplacer(pairs...)
}
