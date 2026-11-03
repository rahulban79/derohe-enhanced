// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package nat

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestExternalClass(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7": "public", "100.64.0.1": "cgnat", "100.127.255.254": "cgnat", "100.128.0.1": "public",
		"10.1.2.3": "private", "172.16.0.1": "private", "192.168.1.1": "private", "127.0.0.1": "private",
		"0.0.0.0": "unknown",
	}
	for ip, want := range cases {
		if got := ExternalClass(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %s, want %s", ip, got, want)
		}
	}
	if ExternalClass(nil) != "unknown" {
		t.Error("nil")
	}
}

func TestProbeVerdict(t *testing.T) {
	none := []ProbeResult{{Protocol: "pcp"}, {Protocol: "natpmp"}, {Protocol: "upnp"}}
	if v := ProbeVerdict(none); !strings.Contains(v, "forward UDP (not TCP)") {
		t.Fatalf("none: %s", v)
	}
	ok := []ProbeResult{{Protocol: "natpmp", Available: true, ExternalClass: "public"}}
	if v := ProbeVerdict(ok); !strings.Contains(v, "--p2p-nat=auto") {
		t.Fatalf("public: %s", v)
	}
	cg := []ProbeResult{{Protocol: "pcp", Available: true, ExternalClass: "unknown"}, {Protocol: "upnp", Available: true, ExternalClass: "cgnat"}}
	if v := ProbeVerdict(cg); !strings.Contains(v, "carrier-grade") {
		t.Fatalf("cgnat: %s", v)
	}
	pr := []ProbeResult{{Protocol: "upnp", Available: true, ExternalClass: "private"}}
	if v := ProbeVerdict(pr); !strings.Contains(v, "second router") {
		t.Fatalf("private: %s", v)
	}
	// an unavailable protocol's class never counts
	if v := ProbeVerdict([]ProbeResult{{Protocol: "upnp", ExternalClass: "cgnat"}}); strings.Contains(v, "carrier-grade") {
		t.Fatalf("unavailable counted: %s", v)
	}
}

var noUPnP = &UPnP{SSDP: "127.0.0.1:9", Wait: 50 * time.Millisecond}

func TestProbeFakeGatewayReadOnly(t *testing.T) {
	g := newFakeGateway(t, true, true)
	rs := Probe(net.IPv4(127, 0, 0, 1), g.addr().Port, fastRetry, noUPnP)
	if len(rs) != 3 || rs[0].Protocol != "pcp" || !rs[0].Available || rs[1].Protocol != "natpmp" || !rs[1].Available ||
		rs[1].ExternalClass != "public" || rs[2].Protocol != "upnp" || rs[2].Available {
		t.Fatalf("results %+v", rs)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.maps) != 0 || g.requests != 2 {
		t.Fatalf("probe must only ask: maps %d requests %d", len(g.maps), g.requests)
	}
}

func TestProbeNATPMPOnlyGateway(t *testing.T) {
	g := newFakeGateway(t, false, true, func(g *fakeGateway) { g.extIP = net.IPv4(100, 70, 1, 2).To4() })
	rs := Probe(net.IPv4(127, 0, 0, 1), g.addr().Port, fastRetry, noUPnP)
	if rs[0].Available || rs[0].Error != "unsupported-version" || !rs[1].Available || rs[1].ExternalClass != "cgnat" {
		t.Fatalf("results %+v", rs)
	}
	if v := ProbeVerdict(rs); !strings.Contains(v, "carrier-grade") {
		t.Fatalf("verdict %s", v)
	}
}

func TestProbeUPnPReadOnly(t *testing.T) {
	f := newFakeIGD(t, nil)
	rs := Probe(nil, 0, fastRetry, f.upnp())
	if rs[0].Available || rs[1].Available || !rs[2].Available || rs[2].ExternalClass != "public" {
		t.Fatalf("results %+v", rs)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.maps) != 0 {
		t.Fatal("probe created a UPnP mapping")
	}
}

func TestManagerProbeModeNeverMaps(t *testing.T) {
	g := newFakeGateway(t, true, true)
	m := Start(Options{Mode: ModeProbe, InternalPort: 11011, Gateway: net.IPv4(127, 0, 0, 1), GatewayPort: g.addr().Port,
		Retry: fastRetry, UPnP: noUPnP})
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Verdict == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := m.Status()
	if st.Active || st.Mode != ModeProbe || len(st.Probe) != 3 || !strings.Contains(st.Verdict, "--p2p-nat=auto") || m.ExternalPort() != 0 {
		t.Fatalf("status %+v", st)
	}
	if g.mapped(11011) != nil {
		t.Fatal("probe mode mapped the port")
	}
	m.Stop(time.Second)
	m.Stop(time.Second)
}

// r22 merge (SP22-NAT review): a probe result carries an error KIND, never raw error text (GetSyncInfo shows it to
// anyone who can reach --rpc-bind), and the kinds map to themselves.
func TestProbeErrorIsKind(t *testing.T) {
	g := newFakeGateway(t, false, true, func(g *fakeGateway) { g.extIP = net.IPv4(100, 70, 1, 2).To4() })
	rs := Probe(net.IPv4(127, 0, 0, 1), g.addr().Port, fastRetry, noUPnP)
	for _, r := range rs {
		if r.Error != error_kind(r.Error) {
			t.Fatalf("%s: error %q is not a kind", r.Protocol, r.Error)
		}
	}
	if rs[0].Error != "unsupported-version" {
		t.Fatalf("pcp error %q, want the kind unsupported-version", rs[0].Error)
	}
	for _, k := range []string{"", "no-response", "unsupported-version", "other", "no default gateway"} {
		if error_kind(k) != k {
			t.Fatalf("kind %q not idempotent", k)
		}
	}
}
