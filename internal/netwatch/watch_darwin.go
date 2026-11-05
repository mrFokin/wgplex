package netwatch

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <stdint.h>
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

// Exported by this package (wgplexNetwatchChanged below).
extern void wgplexNetwatchChanged(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

const (
	quiet       = 500 * time.Millisecond // debounce: quiet after the last event
	maxDelay    = 3 * time.Second        // debounce: at most after the first event
	sleepTick   = 2 * time.Second        // how often a sleep is looked for
	resyncEvery = 30 * time.Second       // periodic Resync (design 8)
	minBackoff  = time.Second            // before recreating the SC session
	maxBackoff  = 30 * time.Second
	probeEvery  = 5 * time.Second // how often the SC session is checked alive
	sessionName = "wgplex.netwatch"
)

// Watch watches the keys and patterns (Netwatch model) with an
// SCDynamicStore session on a CFRunLoop, the sleep ticker and Resync every
// 30 s; events come debounced. A session that dies (configd restarted) is
// recreated with a growing delay (1 s … 30 s) and gives Resync. The channel
// is closed when ctx is done; the run loop is stopped and the session
// released then.
//
// Events that come while the receiver is busy are merged into the next
// value sent.
func Watch(ctx context.Context, captureKey string, log *slog.Logger) <-chan Event {
	out := make(chan Event)
	raw := make(chan Event, 64)
	go runSC(ctx, captureKey, log, raw)
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

// runSC runs SC sessions watching the keys until ctx is done, sending the
// events of changed keys to raw; a session that dies is recreated with a
// growing delay and gives Resync. The goroutine keeps its OS thread: the
// run loop and the callbacks are bound to it.
func runSC(ctx context.Context, captureKey string, log *slog.Logger, raw chan<- Event) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
		log.Warn("netwatch: SC session lost, recreating", "err", err, "in", backoff)
	}
}

// session is what the callback of one SC session needs; reached through
// a cgo.Handle stored in C memory (the context info).
type session struct {
	ctx        context.Context
	captureKey string
	raw        chan<- Event
}

// watchOnce creates one SC session with the notification keys, runs the
// current thread's run loop and sends events to raw until ctx is done
// (nil) or the session dies (an error). resync: send Resync once it
// watches (a recreated session: changes may have been missed). Everything
// created is released before it returns.
func watchOnce(ctx context.Context, captureKey string, raw chan<- Event, resync bool) error {
	h := cgo.NewHandle(&session{ctx: ctx, captureKey: captureKey, raw: raw})
	defer h.Delete()
	info := (*C.uintptr_t)(C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0)))))
	defer C.free(unsafe.Pointer(info))
	*info = C.uintptr_t(h)

	var sctx C.SCDynamicStoreContext // version 0, no retain/release
	sctx.info = unsafe.Pointer(info)
	name := cfString(sessionName)
	defer C.CFRelease(C.CFTypeRef(name))
	store := C.SCDynamicStoreCreate(0, name, C.SCDynamicStoreCallBack(C.wgplexNetwatchChanged), &sctx)
	if store == 0 {
		return scErr("SCDynamicStoreCreate")
	}
	defer C.CFRelease(C.CFTypeRef(store))

	keys, patterns := watchKeys(captureKey)
	keyArr, patArr := cfStringArray(keys), cfStringArray(patterns)
	ok := C.SCDynamicStoreSetNotificationKeys(store, keyArr, patArr)
	C.CFRelease(C.CFTypeRef(keyArr))
	C.CFRelease(C.CFTypeRef(patArr))
	if ok == 0 {
		return scErr("SCDynamicStoreSetNotificationKeys")
	}

	src := C.SCDynamicStoreCreateRunLoopSource(0, store, 0)
	if src == 0 {
		return scErr("SCDynamicStoreCreateRunLoopSource")
	}
	defer C.CFRelease(C.CFTypeRef(src))
	rl := C.CFRunLoopGetCurrent()
	C.CFRunLoopAddSource(rl, src, C.kCFRunLoopDefaultMode)
	defer C.CFRunLoopRemoveSource(rl, src, C.kCFRunLoopDefaultMode)
	defer C.CFRunLoopSourceInvalidate(src)

	// CFRunLoopStop is thread-safe; a stop before the run loop runs is
	// lost, so the run loop also times out every probeEvery.
	stop := context.AfterFunc(ctx, func() { C.CFRunLoopStop(rl) })
	defer stop()

	if resync {
		select {
		case raw <- Resync:
		case <-ctx.Done():
		}
	}

	probe := cfString(networkKeys[0])
	defer C.CFRelease(C.CFTypeRef(probe))
	for {
		res := C.CFRunLoopRunInMode(C.kCFRunLoopDefaultMode, C.CFTimeInterval(probeEvery.Seconds()), 0)
		if ctx.Err() != nil {
			return nil
		}
		if res == C.kCFRunLoopRunFinished {
			return errors.New("run loop has no sources")
		}
		if err := alive(store, src, probe); err != nil {
			return err
		}
	}
}

// alive reports a dead session: the run loop source invalidated, or a
// read of probe failing because configd or the session is gone. A missing
// key is not an error.
func alive(store C.SCDynamicStoreRef, src C.CFRunLoopSourceRef, probe C.CFStringRef) error {
	if C.CFRunLoopSourceIsValid(src) == 0 {
		return errors.New("run loop source invalidated")
	}
	v := C.SCDynamicStoreCopyValue(store, probe)
	if v != 0 {
		C.CFRelease(C.CFTypeRef(v))
		return nil
	}
	switch code := C.SCError(); code {
	case C.kSCStatusNoStoreServer, C.kSCStatusNoStoreSession:
		return fmt.Errorf("SCDynamicStoreCopyValue: %s", C.GoString(C.SCErrorString(code)))
	}
	return nil
}

//export wgplexNetwatchChanged
func wgplexNetwatchChanged(store C.SCDynamicStoreRef, changedKeys C.CFArrayRef, info unsafe.Pointer) {
	s := cgo.Handle(*(*C.uintptr_t)(info)).Value().(*session)
	var e Event
	for i := C.CFIndex(0); i < C.CFArrayGetCount(changedKeys); i++ {
		key := C.CFStringRef(uintptr(C.CFArrayGetValueAtIndex(changedKeys, i)))
		e |= classify(goString(key), s.captureKey)
	}
	if e == 0 {
		return
	}
	select {
	case s.raw <- e:
	case <-s.ctx.Done():
	}
}

// scErr is the error of a failed SC call fn with SCError.
func scErr(fn string) error {
	return fmt.Errorf("%s: %s", fn, C.GoString(C.SCErrorString(C.SCError())))
}

// cfString returns a CFString of s; the caller releases it.
func cfString(s string) C.CFStringRef {
	cs := C.CString(s)
	defer C.free(unsafe.Pointer(cs))
	return C.CFStringCreateWithCString(0, cs, C.kCFStringEncodingUTF8)
}

// cfStringArray returns a CFArray of CFStrings of ss; the caller releases it.
func cfStringArray(ss []string) C.CFArrayRef {
	vals := make([]C.CFStringRef, len(ss))
	for i, s := range ss {
		vals[i] = cfString(s)
		defer C.CFRelease(C.CFTypeRef(vals[i])) // the array retains its values
	}
	var p *unsafe.Pointer // const void ** of CFArrayCreate
	if len(vals) > 0 {
		p = (*unsafe.Pointer)(unsafe.Pointer(&vals[0]))
	}
	return C.CFArrayCreate(0, p, C.CFIndex(len(vals)), &C.kCFTypeArrayCallBacks)
}

// goString returns s as a Go string ("" for NULL).
func goString(s C.CFStringRef) string {
	if s == 0 {
		return ""
	}
	if p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8); p != nil {
		return C.GoString(p)
	}
	n := C.CFStringGetMaximumSizeForEncoding(C.CFStringGetLength(s), C.kCFStringEncodingUTF8) + 1
	buf := (*C.char)(C.malloc(C.size_t(n)))
	defer C.free(unsafe.Pointer(buf))
	if C.CFStringGetCString(s, buf, n, C.kCFStringEncodingUTF8) == 0 {
		return ""
	}
	return C.GoString(buf)
}
