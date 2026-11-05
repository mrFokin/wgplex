package dns

import (
	"reflect"
	"testing"
)

// Tests follow design 8 (verification of the capture by parsing
// `scutil --dns`) and the M4 plan decision 6, not the implementation.

const scutilDNSTypical = `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  if_index : 15 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  domain   : example.com
  nameserver[0] : 127.0.0.1
  port     : 5301
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
  order    : 1

resolver #4
  domain   : corp.example
  nameserver[0] : 127.0.0.1
  nameserver[1] : 10.0.0.1
  port     : 5301
  order    : 1

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 15 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : scoped.example
  nameserver[0] : 10.9.9.9
  port     : 5353
  if_index : 20 (utun4)
`

func TestParseScutilDNS(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []resolverBlock
	}{
		{name: "empty output", out: "", want: nil},
		{name: "whitespace only", out: "\n  \n", want: nil},
		{name: "no resolver blocks", out: "DNS configuration\n\nsomething else\n", want: nil},
		{
			// design 8: blocks of the main section in order, with domain,
			// nameserver[0] and port; scoped section skipped
			name: "typical output",
			out:  scutilDNSTypical,
			want: []resolverBlock{
				{domain: "", nameserver: "192.168.1.1", port: 0},
				{domain: "local", nameserver: "", port: 0},
				{domain: "example.com", nameserver: "127.0.0.1", port: 5301},
				{domain: "corp.example", nameserver: "127.0.0.1", port: 5301},
			},
		},
		{
			// no "port" line: 0 (the default, 53)
			name: "block without port",
			out:  "DNS configuration\n\nresolver #1\n  domain   : example.com\n  nameserver[0] : 127.0.0.1\n  flags    : Request A records\n",
			want: []resolverBlock{{domain: "example.com", nameserver: "127.0.0.1", port: 0}},
		},
		{
			name: "only scoped section",
			out:  "DNS configuration (for scoped queries)\n\nresolver #1\n  domain : x.example\n  nameserver[0] : 10.0.0.1\n  port : 53\n",
			want: nil,
		},
		{
			// only nameserver[0] is taken, not later nameservers
			name: "several nameservers",
			out:  "DNS configuration\n\nresolver #1\n  domain : a.example\n  nameserver[0] : 127.0.0.1\n  nameserver[1] : 10.0.0.1\n  port : 5301\n",
			want: []resolverBlock{{domain: "a.example", nameserver: "127.0.0.1", port: 5301}},
		},
		{
			name: "ipv6 nameserver",
			out:  "DNS configuration\n\nresolver #1\n  domain : a.example\n  nameserver[0] : fe80::1%en0\n  port : 5301\n",
			want: []resolverBlock{{domain: "a.example", nameserver: "fe80::1%en0", port: 5301}},
		},
		{
			// unknown lines are skipped, a block without any known field still exists
			name: "unknown lines skipped",
			out:  "DNS configuration\n\nresolver #1\n  garbage line\n  flags : x\n  domain : a.example\n\nresolver #2\n  options : mdns\n",
			want: []resolverBlock{{domain: "a.example"}, {}},
		},
		{
			name: "no trailing newline",
			out:  "DNS configuration\n\nresolver #1\n  domain : a.example\n  nameserver[0] : 127.0.0.1\n  port : 5301",
			want: []resolverBlock{{domain: "a.example", nameserver: "127.0.0.1", port: 5301}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseScutilDNS(tc.out)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseScutilDNS() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
