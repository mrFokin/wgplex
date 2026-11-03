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
func (a *Access) CanControl(uid uint32) bool {
	panic("not implemented")
}

// Group returns control_group of the applied config (ConfigGroup): the data
// of CodeNoPermission and control_group of status.get; "" without a config.
func (a *Access) Group() string {
	panic("not implemented")
}
