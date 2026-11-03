package dns

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// SystemError names the servers the lookup actually went to in place of the
// resolv.conf server Go puts into *net.DNSError (SystemResolver dials its own
// servers). Other errors and nil are returned as is.
//
// When err is or wraps a *net.DNSError, the result carries a copy of it whose
// Server is servers joined by "," (addresses only, e.g. "192.168.20.1"),
// wrapped the same way as the original, so errors.As on the result still
// finds a *net.DNSError. The original error is not modified. A non-DNS
// error, nil, or an empty servers list gives err unchanged.
func SystemError(err error, servers []netip.Addr) error {
	if err == nil || len(servers) == 0 {
		return err
	}
	var orig *net.DNSError
	if !errors.As(err, &orig) {
		return err
	}
	names := make([]string, len(servers))
	for i, s := range servers {
		names[i] = s.String()
	}
	cp := *orig
	cp.Server = strings.Join(names, ",")
	if orig == err {
		return &cp
	}
	return &serverError{
		msg: strings.Replace(err.Error(), orig.Error(), cp.Error(), 1),
		dns: &cp,
	}
}

// serverError is a wrapped *net.DNSError with the server replaced: the text
// of the original chain with the new DNSError text, unwrapping to the copy.
type serverError struct {
	msg string
	dns *net.DNSError
}

func (e *serverError) Error() string { return e.msg }

func (e *serverError) Unwrap() error { return e.dns }
