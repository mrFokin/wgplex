package rpc

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Tests follow design 5 (can_control, cache of membership for 30 s, group of
// the applied config) and plan M3 decision 2, not the implementation. The
// system calls are synthetic functions; the clock is controlled.

type accessFake struct {
	owner      uint32
	hasOwner   bool
	group      string
	members    map[uint32]bool // by uid, for the current group
	memberErr  error
	memberCall int
	now        time.Time
	logBuf     bytes.Buffer
}

func newAccessFake() *accessFake {
	return &accessFake{
		owner:    501,
		hasOwner: true,
		group:    "wgpctl",
		members:  map[uint32]bool{600: true},
		now:      time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
	}
}

func (f *accessFake) access(logged bool) *Access {
	var out io.Writer = io.Discard
	if logged {
		out = &f.logBuf
	}
	return &Access{
		OwnerUID:    func() (uint32, bool) { return f.owner, f.hasOwner },
		ConfigGroup: func() string { return f.group },
		IsMember: func(uid uint32, group string) (bool, error) {
			f.memberCall++
			if f.memberErr != nil {
				return false, f.memberErr
			}
			return f.members[uid] && group == "wgpctl", nil
		},
		Now: func() time.Time { return f.now },
		Log: slog.New(slog.NewTextHandler(out, nil)),
	}
}

// design 5: root, the owner of the config directory, a member of control_group.
func TestCanControl(t *testing.T) {
	cases := []struct {
		name string
		edit func(f *accessFake)
		uid  uint32
		want bool
	}{
		{"root", func(f *accessFake) {}, 0, true},
		{"owner of the config directory", func(f *accessFake) {}, 501, true},
		{"member of the group", func(f *accessFake) {}, 600, true},
		{"stranger", func(f *accessFake) {}, 700, false},
		// no config applied: control_group is "", only root and the owner
		{"no config: root", func(f *accessFake) { f.group = "" }, 0, true},
		{"no config: owner", func(f *accessFake) { f.group = "" }, 501, true},
		{"no config: would-be member", func(f *accessFake) { f.group = "" }, 600, false},
		// no config directory: only root
		{"no directory: root", func(f *accessFake) { f.hasOwner = false }, 0, true},
		{"no directory: former owner uid", func(f *accessFake) { f.hasOwner = false }, 501, false},
		{"no directory and no group: stranger", func(f *accessFake) { f.hasOwner = false; f.group = "" }, 600, false},
		// the directory owned by root: uid 501 is a stranger
		{"directory owned by root", func(f *accessFake) { f.owner = 0 }, 501, false},
	}
	for _, c := range cases {
		f := newAccessFake()
		c.edit(f)
		if got := f.access(false).CanControl(c.uid); got != c.want {
			t.Errorf("%s: CanControl(%d) = %v, want %v", c.name, c.uid, got, c.want)
		}
	}
}

// root and the owner are decided without asking Directory Services.
func TestCanControlNoLookupForRootAndOwner(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	a.CanControl(0)
	a.CanControl(501)
	if f.memberCall != 0 {
		t.Errorf("IsMember called %d times for root and the owner, want 0", f.memberCall)
	}
	f.group = ""
	a.CanControl(600)
	if f.memberCall != 0 {
		t.Errorf("IsMember called without a group: %d times", f.memberCall)
	}
}

// design 5: the owner is looked at on every call (stat), no cache.
func TestCanControlOwnerNotCached(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	if !a.CanControl(501) {
		t.Fatal("owner does not control")
	}
	f.owner = 502
	if a.CanControl(501) {
		t.Error("the old owner still controls after the directory changed hands")
	}
	if !a.CanControl(502) {
		t.Error("the new owner does not control")
	}
	f.hasOwner = false
	if a.CanControl(502) {
		t.Error("the owner controls after the directory is gone")
	}
}

// design 5: the answer is cached by uid for 30 s.
func TestCanControlCache(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	if !a.CanControl(600) {
		t.Fatal("member does not control")
	}
	f.now = f.now.Add(10 * time.Second)
	if !a.CanControl(600) {
		t.Fatal("member does not control on the second call")
	}
	f.now = f.now.Add(19 * time.Second) // 29 s since the answer
	a.CanControl(600)
	if f.memberCall != 1 {
		t.Errorf("IsMember called %d times within 30 s, want 1", f.memberCall)
	}

	// 31 s since the first answer: asked again
	f.now = f.now.Add(2 * time.Second)
	a.CanControl(600)
	if f.memberCall != 2 {
		t.Errorf("IsMember called %d times after 31 s, want 2", f.memberCall)
	}

	// the cache is by uid
	a.CanControl(700)
	if f.memberCall != 3 {
		t.Errorf("a new uid did not reach IsMember: %d calls, want 3", f.memberCall)
	}
	a.CanControl(700)
	if f.memberCall != 3 {
		t.Errorf("a non-member answer is not cached: %d calls, want 3", f.memberCall)
	}
}

// design 5: a user removed from the group loses control after the TTL, a
// user added gains it, without a restart.
func TestCanControlMembershipChanges(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	f.members[700] = true
	if !a.CanControl(700) {
		t.Fatal("added member does not control")
	}
	delete(f.members, 700)
	if !a.CanControl(700) {
		t.Error("the answer changed within the TTL")
	}
	f.now = f.now.Add(31 * time.Second)
	if a.CanControl(700) {
		t.Error("the removed member still controls after the TTL")
	}
	f.members[700] = true
	f.now = f.now.Add(31 * time.Second)
	if !a.CanControl(700) {
		t.Error("the member added again does not control after the TTL")
	}
}

// plan M3 decision 2: a change of control_group in the config drops the cache.
func TestCanControlGroupChangeDropsCache(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	if !a.CanControl(600) {
		t.Fatal("member does not control")
	}
	// the new group: 600 is not in it (the fake knows only wgpctl)
	f.group = "other"
	if a.CanControl(600) {
		t.Error("cached answer of the old group is used for the new one")
	}
	if f.memberCall != 2 {
		t.Errorf("IsMember called %d times, want 2 (the cache dropped)", f.memberCall)
	}
	// and back, within 30 s of the first answer: asked again, not served from the old cache
	f.group = "wgpctl"
	if !a.CanControl(600) {
		t.Error("member does not control after the group came back")
	}
	if f.memberCall != 3 {
		t.Errorf("IsMember called %d times, want 3", f.memberCall)
	}
	// the group goes empty and back
	f.group = ""
	if a.CanControl(600) {
		t.Error("member controls without a group")
	}
}

// plan M3 decision 2: an IsMember error is "not a member", not cached, and
// logged as a warning once per distinct error.
func TestCanControlMembershipError(t *testing.T) {
	f := newAccessFake()
	a := f.access(true)
	f.memberErr = errors.New("mbr: directory services unavailable")
	for i := 0; i < 3; i++ {
		if a.CanControl(600) {
			t.Fatal("a member controls although IsMember failed")
		}
	}
	if f.memberCall != 3 {
		t.Errorf("IsMember called %d times, want 3 (the error is not cached)", f.memberCall)
	}
	if n := warnLines(f.logBuf.String()); n != 1 {
		t.Errorf("%d warnings for one repeated error, want 1:\n%s", n, f.logBuf.String())
	}

	// a different error is logged again
	f.memberErr = errors.New("mbr: another failure")
	a.CanControl(600)
	if n := warnLines(f.logBuf.String()); n != 2 {
		t.Errorf("%d warnings after a different error, want 2:\n%s", n, f.logBuf.String())
	}

	// the service is back: not stuck on "not a member"
	f.memberErr = nil
	if !a.CanControl(600) {
		t.Error("member does not control after the error is gone")
	}
	// and that answer is cached
	calls := f.memberCall
	a.CanControl(600)
	if f.memberCall != calls {
		t.Error("the successful answer after an error is not cached")
	}
}

// An error does not poison the cached answer of another uid.
func TestCanControlErrorKeepsOtherCache(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	f.members[601] = true
	a.CanControl(600)
	f.memberErr = errors.New("boom")
	if a.CanControl(601) {
		t.Error("601 controls despite the error")
	}
	if !a.CanControl(600) {
		t.Error("cached member 600 lost control within the TTL because of an error for 601")
	}
}

func TestAccessGroup(t *testing.T) {
	f := newAccessFake()
	a := f.access(false)
	if got := a.Group(); got != "wgpctl" {
		t.Errorf("Group() = %q, want wgpctl", got)
	}
	f.group = ""
	if got := a.Group(); got != "" {
		t.Errorf("Group() = %q without a config, want empty", got)
	}
}

func warnLines(log string) int {
	n := 0
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "level=WARN") {
			n++
		}
	}
	return n
}
