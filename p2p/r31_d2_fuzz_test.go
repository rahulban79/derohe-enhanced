// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r31 dimension 2 (security fuzz-coverage, DF-fuzz-coverage-57dc9661cb): ParseAddress (the --ban / ban-list / console
// address parser) was reached by no Go fuzz target. Pure: no network, no ban-list state.

import (
	"net"
	"strings"
	"testing"
)

// FuzzR31ParseAddress: never panics; an accepted address yields a non-empty canonical form that parses to itself (a
// fixpoint, so a ban stored under it is found again under the same key), and a CIDR yields its network.
func FuzzR31ParseAddress(f *testing.F) {
	for _, s := range []string{"192.0.2.7", "192.0.2.7/24", "0:0:0:0:0:0:0:1", "2001:db8::1/64", "::ffff:192.0.2.1",
		"192.0.2.7:11011", " 192.0.2.7", "", "/", "300.1.1.1", "2001:db8::/129", "192.0.2.0/0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ipnet, result, err := ParseAddress(s)
		if err != nil {
			return
		}
		if result == "" {
			t.Fatalf("%q accepted with an empty form", s)
		}
		if strings.Contains(s, "/") != (ipnet != nil) {
			t.Fatalf("%q: ipnet %v", s, ipnet)
		}
		if ipnet == nil { // a single IP: its key is the canonical text form (so "0:0:0:0:0:0:0:1" and "::1" ban alike)
			if ip := net.ParseIP(result); ip == nil || ip.String() != result {
				t.Fatalf("%q -> %q: not the canonical IP text", s, result)
			}
		} else if ipnet.String() != result {
			t.Fatalf("%q -> %q: not the network %v", s, result, ipnet)
		}
		_, again, err := ParseAddress(result)
		if err != nil || again != result {
			t.Fatalf("%q -> %q -> %q (%v): not a fixpoint", s, result, again, err)
		}
	})
}
