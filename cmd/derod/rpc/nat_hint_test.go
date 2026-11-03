// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

import "strings"
import "testing"

import "github.com/deroproject/derohe/p2p/nat"

func TestNATHint(t *testing.T) {
	un := "unreachable: no inbound connection since start; forward UDP (not TCP) for the --p2p-bind port to this host"
	if got := nat_hint("reachable: peers have connected in", nat.Status{Mode: "off"}); got != "reachable: peers have connected in" {
		t.Fatalf("reachable verdict changed: %q", got)
	}
	if got := nat_hint(un, nat.Status{Mode: "off"}); !strings.Contains(got, "--p2p-nat=auto") {
		t.Fatalf("off: %q", got)
	}
	if got := nat_hint(un, nat.Status{Mode: "auto", Error: "natpmp: gateway did not answer"}); !strings.Contains(got, "could not map") {
		t.Fatalf("failed: %q", got)
	}
	if got := nat_hint(un, nat.Status{Mode: "auto", Active: true, Protocol: "upnp", ExternalIP: "203.0.113.7", ExternalPort: 11011}); !strings.Contains(got, "203.0.113.7:11011") {
		t.Fatalf("active: %q", got)
	}
	if got := nat_hint(un, nat.Status{Mode: "auto", Active: true, Warning: "double NAT"}); !strings.Contains(got, "double NAT") {
		t.Fatalf("warning: %q", got)
	}
	// r22 --p2p-nat=probe: the verdict is passed through; never "could not map" (probe mode maps nothing)
	if got := nat_hint(un, nat.Status{Mode: "probe", Verdict: "router answers no mapping protocol"}); !strings.Contains(got, "NAT probe: router answers no mapping protocol") {
		t.Fatalf("probe: %q", got)
	}
	if got := nat_hint(un, nat.Status{Mode: "probe"}); !strings.Contains(got, "probe still running") {
		t.Fatalf("probe running: %q", got)
	}
}
