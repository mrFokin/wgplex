package netwatch

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

const (
	scutilPath  = "/usr/sbin/scutil"
	quiet       = 500 * time.Millisecond // debounce: quiet after the last event
	maxDelay    = 3 * time.Second        // debounce: at most after the first event
	sleepTick   = 2 * time.Second        // how often a sleep is looked for
	resyncEvery = 30 * time.Second       // periodic Resync (design 7)
	minBackoff  = time.Second            // before restarting scutil
	maxBackoff  = 30 * time.Second
)

// Watch watches the keys and patterns (Netwatch model) with a long-lived
// scutil, the sleep ticker and Resync every 30 s; events come debounced.
// A scutil that exits is restarted with a growing delay (1 s … 30 s) and
// gives Resync. The channel is closed when ctx is done; scutil is killed
// and reaped then.
//
// Events that come while the receiver is busy are merged into the next
// value sent.
func Watch(ctx context.Context, captureKey string, log *slog.Logger) <-chan Event {
	out := make(chan Event)
	raw := make(chan Event, 64)
	go runScutil(ctx, captureKey, log, raw)
	go func() {
		defer close(out)
		deb := newDebouncer(quiet, maxDelay)
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		defer timer.Stop()
		sleepT := time.NewTicker(sleepTick)
		defer sleepT.Stop()
		resyncT := time.NewTicker(resyncEvery)
		defer resyncT.Stop()
		prev := time.Now()
		var ready Event // due, not yet received
		for {
			var send chan<- Event
			if ready != 0 {
				send = out
			}
			select {
			case <-ctx.Done():
				return
			case send <- ready:
				ready = 0
				continue
			case e := <-raw:
				deb.add(time.Now(), e)
			case now := <-sleepT.C:
				// now has a monotonic reading: Sub uses it, Round(0) drops it.
				wall, mono := now.Round(0).Sub(prev.Round(0)), now.Sub(prev)
				prev = now
				if slept(wall, mono) {
					log.Info("netwatch: wake", "slept", (wall - mono).Round(time.Second))
					deb.add(now, Wake)
				}
			case now := <-resyncT.C:
				deb.add(now, Resync)
			case <-timer.C:
			}
			e, next := deb.due(time.Now())
			ready |= e
			if !next.IsZero() {
				timer.Reset(time.Until(next))
			}
		}
	}()
	return out
}

// runScutil runs scutil watching the keys until ctx is done, sending the
// event of every changed key to raw; a scutil that exits is restarted with
// a growing delay and gives Resync.
func runScutil(ctx context.Context, captureKey string, log *slog.Logger, raw chan<- Event) {
	backoff := minBackoff
	for restarts := 0; ; restarts++ {
		if restarts > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, maxBackoff)
		}
		started := time.Now()
		err := watchOnce(ctx, captureKey, raw, restarts > 0)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > maxBackoff {
			backoff = minBackoff // it ran for a while: not a crash loop
		}
		log.Warn("netwatch: scutil exited, restarting", "err", err, "in", backoff)
	}
}

// watchOnce runs one scutil (watchScript on its stdin, kept open: closing
// it ends scutil) and sends the events of its changedKey lines to raw until
// it exits or ctx is done. resync: send Resync once it watches (a restart:
// changes may have been missed). The process is always reaped.
func watchOnce(ctx context.Context, captureKey string, raw chan<- Event, resync bool) error {
	cmd := exec.CommandContext(ctx, scutilPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Closing stdin ends scutil; ctx kills it.
	defer cmd.Wait()
	defer stdin.Close()
	if _, err := io.WriteString(stdin, watchScript(captureKey)); err != nil {
		cmd.Process.Kill()
		io.Copy(io.Discard, stdout)
		return fmt.Errorf("scutil: %w", err)
	}
	if resync {
		select {
		case raw <- Resync:
		case <-ctx.Done():
		}
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		key, ok := parseChangedKey(sc.Text())
		if !ok {
			continue
		}
		if e := classify(key, captureKey); e != 0 {
			select {
			case raw <- e:
			case <-ctx.Done():
			}
		}
	}
	if err := sc.Err(); err != nil {
		cmd.Process.Kill()
		io.Copy(io.Discard, stdout)
		return fmt.Errorf("scutil: %w", err)
	}
	return nil
}

// watchScript returns the scutil commands that watch the keys and patterns
// of the Netwatch model and start watching.
func watchScript(captureKey string) string {
	var b strings.Builder
	for _, k := range append(append([]string{}, networkKeys...), captureKey) {
		fmt.Fprintf(&b, "n.add %s\n", k)
	}
	for _, p := range networkPatterns {
		fmt.Fprintf(&b, "n.add %s pattern\n", p)
	}
	b.WriteString("n.watch\n")
	return b.String()
}
