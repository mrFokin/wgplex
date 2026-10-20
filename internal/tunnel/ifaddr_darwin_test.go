package tunnel

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mrFokin/wgplex/internal/config"
)

// wantInfiniteLifetime is ND6_INFINITE_LIFETIME (netinet6/nd6.h).
const wantInfiniteLifetime = 0xffffffff

// Layouts must match the kernel structs (plan M3, spike): ifaliasreq is 64
// bytes, in6_aliasreq is 128 bytes.
func TestIoctlStructLayout(t *testing.T) {
	if s := unsafe.Sizeof(ifAliasReq{}); s != 64 {
		t.Errorf("sizeof(ifAliasReq) = %d, want 64", s)
	}
	if s := unsafe.Sizeof(in6AliasReq{}); s != 128 {
		t.Errorf("sizeof(in6AliasReq) = %d, want 128", s)
	}
	var r in6AliasReq
	if o := unsafe.Offsetof(r.Flags); o != 100 {
		t.Errorf("offsetof(in6AliasReq.Flags) = %d, want 100", o)
	}
	if o := unsafe.Offsetof(r.Lifetime); o != 104 {
		t.Errorf("offsetof(in6AliasReq.Lifetime) = %d, want 104", o)
	}
	if siocAIFADDRIn6 != 0x8080691a {
		t.Errorf("siocAIFADDRIn6 = %#x, want 0x8080691a", siocAIFADDRIn6)
	}
}

func ifname16(s string) [unix.IFNAMSIZ]byte {
	var b [unix.IFNAMSIZ]byte
	copy(b[:], s)
	return b
}

func sin4(a string) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   netip.MustParseAddr(a).As4(),
	}
}

// design 5: Address from .conf is assigned to the interface; plan M3: like
// "ifconfig utunN inet A/len A alias" — address and mask from the prefix,
// dst = own address; the address is not masked to the network.
func TestNewIfAliasReq(t *testing.T) {
	tests := []struct {
		ifname string
		prefix string
		addr   string
		mask   string
	}{
		{"utun4", "10.0.0.2/24", "10.0.0.2", "255.255.255.0"},
		{"utun10", "10.66.66.2/32", "10.66.66.2", "255.255.255.255"},
		{"utun123", "172.16.130.7/17", "172.16.130.7", "255.255.128.0"},
		{"utun0", "100.64.0.1/10", "100.64.0.1", "255.192.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := newIfAliasReq(tt.ifname, netip.MustParsePrefix(tt.prefix))
			if got.Name != ifname16(tt.ifname) {
				t.Errorf("Name = %q, want %q NUL-padded", got.Name[:], tt.ifname)
			}
			if want := sin4(tt.addr); got.Addr != want {
				t.Errorf("Addr = %+v, want %+v", got.Addr, want)
			}
			if want := sin4(tt.addr); got.Dst != want {
				t.Errorf("Dst = %+v, want own address %+v", got.Dst, want)
			}
			// The kernel takes the mask only when sin_len is set.
			if got.Mask.Len != unix.SizeofSockaddrInet4 {
				t.Errorf("Mask.Len = %d, want %d", got.Mask.Len, unix.SizeofSockaddrInet4)
			}
			if want := netip.MustParseAddr(tt.mask).As4(); got.Mask.Addr != want {
				t.Errorf("Mask = %v, want %v", netip.AddrFrom4(got.Mask.Addr), tt.mask)
			}
			if got.Mask.Port != 0 {
				t.Errorf("Mask.Port = %d, want 0", got.Mask.Port)
			}
		})
	}
}

func TestNewIn6AliasReq(t *testing.T) {
	tests := []struct {
		ifname string
		prefix string
		addr   string
		mask   string
	}{
		{"utun4", "fd00::2/64", "fd00::2", "ffff:ffff:ffff:ffff::"},
		{"utun7", "fd42:42:42::2/128", "fd42:42:42::2", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"utun12", "2001:db8:1:2::abcd/48", "2001:db8:1:2::abcd", "ffff:ffff:ffff::"},
		{"utun3", "fd00:1::5/57", "fd00:1::5", "ffff:ffff:ffff:ff80::"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := newIn6AliasReq(tt.ifname, netip.MustParsePrefix(tt.prefix))
			if got.Name != ifname16(tt.ifname) {
				t.Errorf("Name = %q, want %q NUL-padded", got.Name[:], tt.ifname)
			}
			wantAddr := unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   netip.MustParseAddr(tt.addr).As16(),
			}
			if got.Addr != wantAddr {
				t.Errorf("Addr = %+v, want %+v", got.Addr, wantAddr)
			}
			if got.Mask.Len != unix.SizeofSockaddrInet6 {
				t.Errorf("Mask.Len = %d, want %d", got.Mask.Len, unix.SizeofSockaddrInet6)
			}
			if want := netip.MustParseAddr(tt.mask).As16(); got.Mask.Addr != want {
				t.Errorf("Mask = %v, want %v", netip.AddrFrom16(got.Mask.Addr), tt.mask)
			}
			if got.Mask.Port != 0 || got.Mask.Flowinfo != 0 || got.Mask.Scope_id != 0 {
				t.Errorf("Mask has stray fields: %+v", got.Mask)
			}
			if got.Lifetime.Vltime != wantInfiniteLifetime || got.Lifetime.Pltime != wantInfiniteLifetime {
				t.Errorf("Lifetime = %+v, want infinite vltime and pltime", got.Lifetime)
			}
		})
	}
}

// design 5: MTU from .conf; without MTU — 1420.
func TestMTU(t *testing.T) {
	tests := []struct {
		in, want int
	}{
		{0, 1420},
		{1280, 1280},
		{1420, 1420},
		{1380, 1380},
		{9000, 9000},
	}
	for _, tt := range tests {
		if got := mtu(&config.WGConfig{MTU: tt.in}); got != tt.want {
			t.Errorf("mtu(MTU=%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
