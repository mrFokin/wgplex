package rpc

// The Redact functions build the reply for a caller that cannot control
// (design 5, Visibility). They return a copy and do not change the slices of
// their argument. Kept: names and states of tunnels, services and via of
// rules, the serving tunnel, the fallback and its reason, addresses of the
// tunnels, handshakes and traffic, config_error_count and warning_count. The
// per-tunnel Reason and Error are dropped: they name the check URL (which may
// hold a token), the pinged address, or the DNS servers of a failed resolve.

// RedactStatus returns s without the endpoints of peers (Endpoint, Resolved),
// the check address or URL (Check.Addr), the reason and error of tunnels
// (Reason, Error), the texts of config errors and warnings (ConfigErrors,
// Warnings; ConfigErrorCount and WarningCount stay).
func RedactStatus(s Status) Status {
	if n := len(s.ConfigErrors); n > s.ConfigErrorCount {
		s.ConfigErrorCount = n
	}
	if n := len(s.Warnings); n > s.WarningCount {
		s.WarningCount = n
	}
	s.ConfigErrors, s.Warnings = nil, nil
	tunnels := make([]TunnelStatus, len(s.Tunnels))
	for i, t := range s.Tunnels {
		t.Reason, t.Error = "", ""
		if t.Peers != nil {
			peers := make([]PeerStatus, len(t.Peers))
			for j, p := range t.Peers {
				p.Endpoint, p.Resolved = "", ""
				peers[j] = p
			}
			t.Peers = peers
		}
		if t.Check != nil {
			c := *t.Check
			c.Addr = ""
			t.Check = &c
		}
		tunnels[i] = t
	}
	if s.Tunnels != nil {
		s.Tunnels = tunnels
	}
	return s
}

// RedactExplanation returns e without Servers, without Addrs (they reveal
// which names somebody resolved) and without Names of its Route.
func RedactExplanation(e Explanation) Explanation {
	e.Servers = nil
	e.Addrs = nil
	if e.Route != nil {
		r := *e.Route
		r.Names = nil
		e.Route = &r
	}
	return e
}

// RedactRoutes returns r without Names of the routes.
func RedactRoutes(r Routes) Routes {
	if r.Routes == nil {
		return r
	}
	routes := make([]RouteInfo, len(r.Routes))
	for i, ri := range r.Routes {
		ri.Names = nil
		routes[i] = ri
	}
	r.Routes = routes
	return r
}
