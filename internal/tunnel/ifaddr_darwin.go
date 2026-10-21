package tunnel

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// siocAIFADDRIn6 is SIOCAIFADDR_IN6, _IOW('i', 26, struct in6_aliasreq);
// x/sys/unix lacks it.
const siocAIFADDRIn6 = 0x8080691a

// nd6InfiniteLifetime is ND6_INFINITE_LIFETIME (netinet6/nd6.h).
const nd6InfiniteLifetime = 0xffffffff

// ifAliasReq is struct ifaliasreq (net/if.h), the SIOCAIFADDR argument. 64 bytes.
type ifAliasReq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	Dst  unix.RawSockaddrInet4
	Mask unix.RawSockaddrInet4
}

// in6AddrLifetime is struct in6_addrlifetime (netinet6/in6_var.h).
type in6AddrLifetime struct {
	Expire    int64 // time_t
	Preferred int64 // time_t
	Vltime    uint32
	Pltime    uint32
}

// in6AliasReq is struct in6_aliasreq (netinet6/in6_var.h), the
// SIOCAIFADDR_IN6 argument. 128 bytes.
type in6AliasReq struct {
	Name     [unix.IFNAMSIZ]byte
	Addr     unix.RawSockaddrInet6
	Dst      unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    int32
	Lifetime in6AddrLifetime
}

// ifreqFlags is struct ifreq (net/if.h) with the ifr_flags member of the union. 32 bytes.
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// newIfAliasReq builds the SIOCAIFADDR argument for p on ifname: address and
// netmask from p, dst = own address (like "ifconfig utunN inet A/len A alias").
func newIfAliasReq(ifname string, p netip.Prefix) ifAliasReq {
	var r ifAliasReq
	copy(r.Name[:unix.IFNAMSIZ-1], ifname)
	r.Addr = sockaddr4(p.Addr().As4())
	r.Dst = r.Addr
	r.Mask = sockaddr4([4]byte(maskBytes(p.Bits(), 4)))
	return r
}

// newIn6AliasReq builds the SIOCAIFADDR_IN6 argument for p on ifname: address
// and netmask from p, infinite lifetime (ND6_INFINITE_LIFETIME).
func newIn6AliasReq(ifname string, p netip.Prefix) in6AliasReq {
	var r in6AliasReq
	copy(r.Name[:unix.IFNAMSIZ-1], ifname)
	r.Addr = sockaddr6(p.Addr().As16())
	r.Mask = sockaddr6([16]byte(maskBytes(p.Bits(), 16)))
	r.Lifetime.Vltime = nd6InfiniteLifetime
	r.Lifetime.Pltime = nd6InfiniteLifetime
	return r
}

// maskBytes returns a netmask of bits ones in n bytes.
func maskBytes(bits, n int) []byte {
	m := make([]byte, n)
	for i := range m {
		switch {
		case bits >= 8:
			m[i] = 0xff
			bits -= 8
		case bits > 0:
			m[i] = ^byte(0xff >> bits)
			bits = 0
		}
	}
	return m
}

func sockaddr4(a [4]byte) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Addr: a}
}

func sockaddr6(a [16]byte) unix.RawSockaddrInet6 {
	return unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: a}
}

// addAddr assigns p to ifname: SIOCAIFADDR on an AF_INET socket for IPv4,
// SIOCAIFADDR_IN6 on an AF_INET6 socket for IPv6. Requires root.
func addAddr(ifname string, p netip.Prefix) error {
	if p.Addr().Is4() {
		r := newIfAliasReq(ifname, p)
		return ioctl(unix.AF_INET, unix.SIOCAIFADDR, unsafe.Pointer(&r))
	}
	r := newIn6AliasReq(ifname, p)
	return ioctl(unix.AF_INET6, siocAIFADDRIn6, unsafe.Pointer(&r))
}

// setUp sets IFF_UP on ifname (SIOCGIFFLAGS/SIOCSIFFLAGS). Requires root.
func setUp(ifname string) error {
	var r ifreqFlags
	copy(r.Name[:unix.IFNAMSIZ-1], ifname)
	if err := ioctl(unix.AF_INET, unix.SIOCGIFFLAGS, unsafe.Pointer(&r)); err != nil {
		return err
	}
	r.Flags |= unix.IFF_UP
	return ioctl(unix.AF_INET, unix.SIOCSIFFLAGS, unsafe.Pointer(&r))
}

// ioctl runs req with arg on a fresh datagram socket of family af.
func ioctl(af int, req uint, arg unsafe.Pointer) error {
	fd, err := unix.Socket(af, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}
