package router

import "net/netip"

// Overlaps returns the routes of t whose prefix overlaps one of local (the
// subnets of physical interfaces, LocalNets), in t's order. Endpoint routes
// are not reported. The daemon logs them as warnings (design 16).
func Overlaps(t Table, local []netip.Prefix) []Route {
	var res []Route
	for _, r := range t {
		if r.Source == SourceEndpoint {
			continue
		}
		for _, l := range local {
			if r.Prefix.Overlaps(l) {
				res = append(res, r)
				break
			}
		}
	}
	return res
}
