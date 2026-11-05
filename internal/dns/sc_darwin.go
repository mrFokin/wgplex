package dns

// The SystemConfiguration layer (design 8): a session of SCDynamicStore and
// the conversion of its dictionaries. Reading needs no root, writing does.

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>

static SCDynamicStoreRef wgpStoreCreate(void) {
	return SCDynamicStoreCreate(NULL, CFSTR("wgplex"), NULL, NULL);
}

static CFStringRef wgpString(const char *s) {
	return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static CFNumberRef wgpNumber(long long v) {
	return CFNumberCreate(NULL, kCFNumberLongLongType, &v);
}

static void wgpRelease(CFTypeRef r) {
	if (r != NULL) CFRelease(r);
}

static CFMutableDictionaryRef wgpDictCreate(void) {
	return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static void wgpDictSet(CFMutableDictionaryRef d, CFStringRef k, CFTypeRef v) {
	CFDictionarySetValue(d, k, v);
}

static CFMutableArrayRef wgpArrayCreate(void) {
	return CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
}

static void wgpArrayAppend(CFMutableArrayRef a, CFTypeRef v) {
	CFArrayAppendValue(a, v);
}

static CFTypeRef wgpArrayGet(CFArrayRef a, CFIndex i) {
	return CFArrayGetValueAtIndex(a, i);
}

static int wgpIsString(CFTypeRef v) { return CFGetTypeID(v) == CFStringGetTypeID(); }
static int wgpIsNumber(CFTypeRef v) { return CFGetTypeID(v) == CFNumberGetTypeID(); }
static int wgpIsArray(CFTypeRef v) { return CFGetTypeID(v) == CFArrayGetTypeID(); }
static int wgpIsDict(CFTypeRef v) { return CFGetTypeID(v) == CFDictionaryGetTypeID(); }

// wgpCString returns a malloc'ed UTF-8 copy of s; NULL on failure.
static char *wgpCString(CFStringRef s) {
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *b = malloc(n);
	if (b == NULL) return NULL;
	if (!CFStringGetCString(s, b, n, kCFStringEncodingUTF8)) {
		free(b);
		return NULL;
	}
	return b;
}

// wgpInt reads n as an integer; 0 when it is not exactly one.
static int wgpInt(CFNumberRef n, long long *v) {
	if (CFNumberIsFloatType(n)) return 0;
	return CFNumberGetValue(n, kCFNumberLongLongType, v);
}

// wgpCopyEntries copies the keys and values of d into malloc'ed arrays of
// CFDictionaryGetCount(d) elements (not retained).
static void wgpCopyEntries(CFDictionaryRef d, CFTypeRef **keys, CFTypeRef **vals) {
	CFIndex n = CFDictionaryGetCount(d);
	*keys = malloc(sizeof(CFTypeRef) * (n > 0 ? n : 1));
	*vals = malloc(sizeof(CFTypeRef) * (n > 0 ? n : 1));
	if (*keys == NULL || *vals == NULL) {
		free(*keys);
		free(*vals);
		*keys = NULL;
		*vals = NULL;
		return;
	}
	CFDictionaryGetKeysAndValues(d, (const void **)*keys, (const void **)*vals);
}

static CFPropertyListRef wgpCopyValue(SCDynamicStoreRef s, CFStringRef k) {
	return SCDynamicStoreCopyValue(s, k);
}

static int wgpSetValue(SCDynamicStoreRef s, CFStringRef k, CFDictionaryRef v) {
	return SCDynamicStoreSetValue(s, k, v);
}

static int wgpRemoveValue(SCDynamicStoreRef s, CFStringRef k) {
	return SCDynamicStoreRemoveValue(s, k);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"
)

// scStore is a session of SCDynamicStore. A session is opened per operation
// and closed after it: a configd restart kills a session, a fresh one needs
// no recovery.
type scStore struct {
	ref C.SCDynamicStoreRef
}

// scErr is the error of the last SC call.
func scErr(op string) error {
	code := C.SCError()
	return fmt.Errorf("%s: %s (%d)", op, C.GoString(C.SCErrorString(code)), int(code))
}

// openStore opens a session of SCDynamicStore; close it with close.
func openStore() (*scStore, error) {
	ref := C.wgpStoreCreate()
	if ref == 0 {
		return nil, scErr("SCDynamicStoreCreate")
	}
	return &scStore{ref: ref}, nil
}

func (s *scStore) close() {
	C.wgpRelease(C.CFTypeRef(s.ref))
}

// cfString returns a new CFString of v; release it with C.wgpRelease.
func cfString(v string) (C.CFStringRef, error) {
	cs := C.CString(v)
	defer C.free(unsafe.Pointer(cs))
	r := C.wgpString(cs)
	if r == 0 {
		return 0, fmt.Errorf("CFString of %q", v)
	}
	return r, nil
}

// get returns the dictionary at key as map[string][]string: a string or an
// integer is a one-element slice (an integer in decimal), an array of them
// keeps its order; fields of other types (dictionaries, data, booleans,
// arrays holding them) are skipped. An absent key gives ok false.
func (s *scStore) get(key string) (m map[string][]string, ok bool, err error) {
	k, err := cfString(key)
	if err != nil {
		return nil, false, err
	}
	defer C.wgpRelease(C.CFTypeRef(k))
	v := C.wgpCopyValue(s.ref, k)
	if v == 0 {
		if code := C.SCError(); code == C.kSCStatusNoKey || code == C.kSCStatusOK {
			return nil, false, nil
		}
		return nil, false, scErr("SCDynamicStoreCopyValue " + key)
	}
	defer C.wgpRelease(C.CFTypeRef(v))
	if C.wgpIsDict(C.CFTypeRef(v)) == 0 {
		return nil, false, fmt.Errorf("%s is not a dictionary", key)
	}
	d := C.CFDictionaryRef(v)
	n := int(C.CFDictionaryGetCount(d))
	var ks, vs *C.CFTypeRef
	C.wgpCopyEntries(d, &ks, &vs)
	if ks == nil {
		return nil, false, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(ks))
	defer C.free(unsafe.Pointer(vs))
	keys := unsafe.Slice(ks, n)
	vals := unsafe.Slice(vs, n)
	m = map[string][]string{}
	for i := range n {
		if C.wgpIsString(keys[i]) == 0 {
			continue
		}
		name, ok := goString(C.CFStringRef(keys[i]))
		if !ok {
			continue
		}
		if val, ok := goValue(vals[i]); ok {
			m[name] = val
		}
	}
	return m, true, nil
}

// goValue converts a scalar or an array of scalars; ok false for other
// types. An empty array is an empty, non-nil slice.
func goValue(v C.CFTypeRef) ([]string, bool) {
	if C.wgpIsArray(v) == 0 {
		s, ok := goScalar(v)
		if !ok {
			return nil, false
		}
		return []string{s}, true
	}
	a := C.CFArrayRef(v)
	n := int(C.CFArrayGetCount(a))
	res := make([]string, 0, n)
	for i := range n {
		s, ok := goScalar(C.wgpArrayGet(a, C.CFIndex(i)))
		if !ok {
			return nil, false
		}
		res = append(res, s)
	}
	return res, true
}

// goScalar converts a CFString or an integer CFNumber.
func goScalar(v C.CFTypeRef) (string, bool) {
	switch {
	case C.wgpIsString(v) != 0:
		return goString(C.CFStringRef(v))
	case C.wgpIsNumber(v) != 0:
		var n C.longlong
		if C.wgpInt(C.CFNumberRef(v), &n) == 0 {
			return "", false
		}
		return strconv.FormatInt(int64(n), 10), true
	}
	return "", false
}

func goString(s C.CFStringRef) (string, bool) {
	b := C.wgpCString(s)
	if b == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(b))
	return C.GoString(b), true
}

// set writes val (see captureValue for the value types) at key; the key is
// persistent (not a temporary value) until removed or configd restarts.
func (s *scStore) set(key string, val map[string]any) error {
	k, err := cfString(key)
	if err != nil {
		return err
	}
	defer C.wgpRelease(C.CFTypeRef(k))
	d := C.wgpDictCreate()
	if d == 0 {
		return errors.New("CFDictionaryCreateMutable")
	}
	defer C.wgpRelease(C.CFTypeRef(d))
	for name, v := range val {
		cv, err := cfValue(v)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		ck, err := cfString(name)
		if err != nil {
			C.wgpRelease(cv)
			return err
		}
		C.wgpDictSet(d, ck, cv)
		C.wgpRelease(C.CFTypeRef(ck))
		C.wgpRelease(cv)
	}
	if C.wgpSetValue(s.ref, k, C.CFDictionaryRef(d)) == 0 {
		return scErr("SCDynamicStoreSetValue " + key)
	}
	return nil
}

// cfValue returns a new CF value of v: string, int, []string or []int.
func cfValue(v any) (C.CFTypeRef, error) {
	switch v := v.(type) {
	case string:
		s, err := cfString(v)
		return C.CFTypeRef(s), err
	case int:
		return cfNumber(v)
	case []string:
		return cfArray(len(v), func(i int) (C.CFTypeRef, error) {
			s, err := cfString(v[i])
			return C.CFTypeRef(s), err
		})
	case []int:
		return cfArray(len(v), func(i int) (C.CFTypeRef, error) { return cfNumber(v[i]) })
	}
	return 0, fmt.Errorf("unsupported value type %T", v)
}

func cfNumber(v int) (C.CFTypeRef, error) {
	r := C.wgpNumber(C.longlong(v))
	if r == 0 {
		return 0, fmt.Errorf("CFNumber of %d", v)
	}
	return C.CFTypeRef(r), nil
}

func cfArray(n int, elem func(int) (C.CFTypeRef, error)) (C.CFTypeRef, error) {
	a := C.wgpArrayCreate()
	if a == 0 {
		return 0, errors.New("CFArrayCreateMutable")
	}
	for i := range n {
		e, err := elem(i)
		if err != nil {
			C.wgpRelease(C.CFTypeRef(a))
			return 0, err
		}
		C.wgpArrayAppend(a, e)
		C.wgpRelease(e)
	}
	return C.CFTypeRef(a), nil
}

// remove removes key; an absent key is no error.
func (s *scStore) remove(key string) error {
	k, err := cfString(key)
	if err != nil {
		return err
	}
	defer C.wgpRelease(C.CFTypeRef(k))
	if C.wgpRemoveValue(s.ref, k) == 0 {
		if C.SCError() == C.kSCStatusNoKey {
			return nil
		}
		return scErr("SCDynamicStoreRemoveValue " + key)
	}
	return nil
}
