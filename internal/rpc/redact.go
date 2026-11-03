package rpc

// The Redact functions build the reply for a caller that cannot control
// (design 5, Visibility). They return a copy and do not change the slices of
// their argument. Kept: names and states of tunnels, services and via of
// rules, the serving tunnel, the fallback and its reason, addresses of the
// tunnels, handshakes and traffic, config_error_count and warning_count.

// RedactStatus returns s without the endpoints of peers (Endpoint, Resolved),
// the check address or URL (Check.Addr), the texts of config errors and
// warnings (ConfigErrors, Warnings; ConfigErrorCount and WarningCount stay).
func RedactStatus(s Status) Status {
	panic("not implemented")
}

// RedactExplanation returns e without Servers and without Names of its Route.
func RedactExplanation(e Explanation) Explanation {
	panic("not implemented")
}

// RedactRoutes returns r without Names of the routes.
func RedactRoutes(r Routes) Routes {
	panic("not implemented")
}
