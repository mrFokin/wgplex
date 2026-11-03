package rpc

import (
	"log/slog"
	"sync"
	"time"
)

// membershipTTL is how long a membership answer of IsMember is cached by uid
// (design 5): status.get is polled every 1–10 s by every user.
const membershipTTL = 30 * time.Second

// Access decides can_control(uid) (design 5): root, the owner of the config
// directory, or a member of control_group of the applied config. The logic is
// pure; the system calls come through the funcs, so tests use synthetic ones.
// The funcs are set before the first call and not changed after; Access is
// safe for concurrent use.
type Access struct {
	// OwnerUID returns the owner uid of the config directory (stat on every
	// call); false: the directory is not there, so only root controls.
	OwnerUID func() (uint32, bool)
	// ConfigGroup returns control_group of the applied config; "": no config
	// applied, so only root and the owner control.
	ConfigGroup func() string
	// IsMember reports whether uid is a member of group (IsMember of this
	// package in the daemon).
	IsMember func(uid uint32, group string) (bool, error)
	// Now is the clock of the cache.
	Now func() time.Time
	// Log gets the warning on an IsMember error, once per distinct error.
	Log *slog.Logger

	mu      sync.Mutex
	group   string                // the group the cache is for
	cache   map[uint32]membership // by uid, for group
	lastErr string                // the text of the last IsMember error logged
}

// membership is a cached IsMember answer.
type membership struct {
	member bool
	at     time.Time // when IsMember answered
}

// CanControl reports whether uid may call the mutating methods and sees the
// full replies (design 5): uid 0; or the uid of OwnerUID; or, with a non-empty
// ConfigGroup, a member of it by IsMember. A membership answer is cached by
// uid for membershipTTL; a change of ConfigGroup drops the cache. An IsMember
// error is "not a member", is not cached and is logged as a warning once per
// distinct error.
//
// A nil OwnerUID is "no directory", a nil ConfigGroup is "no config", a nil
// Now is time.Now and a nil Log drops the warning.
func (a *Access) CanControl(uid uint32) bool {
	if uid == 0 {
		return true
	}
	if a.OwnerUID != nil {
		if owner, ok := a.OwnerUID(); ok && owner == uid {
			return true
		}
	}
	group := a.Group()
	if group == "" || a.IsMember == nil {
		return false
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}

	// The lock is held over IsMember (0.1–2 ms, design 5): simpler than
	// checking the group again after it.
	a.mu.Lock()
	defer a.mu.Unlock()
	if group != a.group {
		a.group, a.cache = group, nil
	}
	t := now()
	if m, ok := a.cache[uid]; ok && t.Sub(m.at) < membershipTTL {
		return m.member
	}
	member, err := a.IsMember(uid, group)
	if err != nil {
		if msg := err.Error(); msg != a.lastErr {
			a.lastErr = msg
			if a.Log != nil {
				a.Log.Warn("control_group membership check failed", "uid", uid, "group", group, "err", err)
			}
		}
		return false
	}
	a.lastErr = ""
	if a.cache == nil {
		a.cache = make(map[uint32]membership)
	}
	a.cache[uid] = membership{member: member, at: t}
	return member
}

// Group returns control_group of the applied config (ConfigGroup): the data
// of CodeNoPermission and control_group of status.get; "" without a config.
func (a *Access) Group() string {
	if a.ConfigGroup == nil {
		return ""
	}
	return a.ConfigGroup()
}
