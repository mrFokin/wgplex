// Package dns is the resolver of the daemon on 127.0.0.1:Port (design 8): it
// picks the upstream for each query by the rules and dns_domains, sends rule
// domains through their tunnel, records the answered addresses as dynamic
// routes before replying, and makes itself the system resolver for the zones
// of the config.
//
// Pure logic, testable without root: choose.go (the upstream for a name),
// answer.go (editing upstream answers, NODATA), dynamic.go (deadlines of
// dynamic addresses), sysdns.go (the capture key, the system servers),
// scutildns.go (parsing `scutil --dns`). server.go is the UDP/TCP server; it
// runs without root on 127.0.0.1:0 with an unbound upstream.
//
// The system layer: sc_darwin.go is SCDynamicStore (cgo); sysdns_darwin.go
// sets and removes the capture key through it, reads the original servers,
// runs `scutil --dns` (read only) and flushes the cache with dscacheutil and
// killall; bind_darwin.go binds upstream sockets to a utun (IP_BOUND_IF).
package dns
