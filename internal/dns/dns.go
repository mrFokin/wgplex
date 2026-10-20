// Package dns is the resolver of the daemon on 127.0.0.1:53 (design 7): it
// picks the upstream for each query by the rules and dns_domains, sends rule
// domains through their tunnel, records the answered addresses as dynamic
// routes before replying, and makes itself the system resolver.
//
// Pure logic, testable without root: choose.go (the upstream for a name),
// answer.go (editing upstream answers, NODATA), dynamic.go (deadlines of
// dynamic addresses), sysdns.go (parsing scutil output, the capture script).
// server.go is the UDP/TCP server; it runs without root on 127.0.0.1:0 with an
// unbound upstream.
//
// The system layer: sysdns_darwin.go execs scutil, dscacheutil and killall to
// capture and release the system DNS and read the original servers;
// bind_darwin.go binds upstream sockets to a utun (IP_BOUND_IF).
package dns
