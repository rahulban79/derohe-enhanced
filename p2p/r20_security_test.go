// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/globals"
	"golang.org/x/time/rate"
)

// r20: one /16 flooding sessions exhausts only its own bucket; the shared bucket keeps its tokens for everyone else.
func TestAdmitInboundPerNetgroupBucket(t *testing.T) {
	inbound_group_limiters = &group_limiters{m: map[string]*rate.Limiter{}}
	shared := rate.NewLimiter(rate.Every(time.Hour), 40) // 40 tokens for the whole test
	admitted := 0
	for i := 0; i < 100; i++ {
		if admit_inbound("203.0.113."+strconv.Itoa(i%250), shared) { // one /16 (203.0)
			admitted++
		}
	}
	if admitted != INBOUND_GROUP_BURST {
		t.Fatalf("flooding /16 admitted %d sessions, want its burst %d", admitted, INBOUND_GROUP_BURST)
	}
	if !admit_inbound("198.51.100.7", shared) { // another /16 still gets in
		t.Fatal("an honest peer in another /16 was refused")
	}
	for i := 0; i < 20; i++ { // LAN / loopback are exempt from the per-group checks
		if !admit_inbound("10.1.2.3", shared) {
			t.Fatal("a LAN peer hit a per-netgroup limit")
		}
	}
	left := 0
	for shared.Allow() {
		left++
	}
	if want := 40 - INBOUND_GROUP_BURST - 1 - 20; left != want { // the 92 refused flood sessions took no token
		t.Fatalf("shared bucket has %d tokens left, want %d", left, want)
	}
	if InboundGroupRefusals() == 0 {
		t.Fatal("refusals not counted")
	}
}

// r20: a /16 already holding MAX_INBOUND_PER_NETGROUP handshaken inbound peers gets no more; outbound peers in the
// same /16 and never-ban nodes do not count against or are exempt from the cap.
func TestAdmitInboundNetgroupCap(t *testing.T) {
	inbound_group_limiters = &group_limiters{m: map[string]*rate.Limiter{}}
	shared := rate.NewLimiter(1000, 1000)
	var conns []*Connection
	full := inbound_group_cap("192.0")
	for i := 0; i < full; i++ {
		c := &Connection{Incoming: true, Addr: &net.UDPAddr{IP: net.ParseIP("192.0.2." + strconv.Itoa(10+i)), Port: 11011}}
		conns = append(conns, c)
		connection_map.Store(Address(c), c)
	}
	out := &Connection{Incoming: false, Addr: &net.UDPAddr{IP: net.ParseIP("192.0.7.1"), Port: 11011}}
	connection_map.Store(Address(out), out)
	defer func() {
		for _, c := range append(conns, out) {
			connection_map.Delete(Address(c))
		}
	}()
	if got := inbound_group_count("192.0"); got != full {
		t.Fatalf("inbound_group_count = %d, want %d (outbound must not count)", got, full)
	}
	if admit_inbound("192.0.2.99", shared) {
		t.Fatal("a full /16 admitted another inbound peer")
	}
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = []string{"192.0.2.99:11011"} // a priority node in that /16 is exempt
	if !admit_inbound("192.0.2.99", shared) {
		t.Fatal("a never-ban node was refused by the netgroup cap")
	}
	connection_map.Delete(Address(conns[0])) // one leaves: room again
	nonbanlist = nil
	if !admit_inbound("192.0.2.98", shared) {
		t.Fatal("the cap did not free a slot")
	}
}

// r20 merge (SEC20-03 review): the cap scales with max-peers, an override replaces it, IPv6 /32 gets twice the cap.
func TestInboundGroupCapScales(t *testing.T) {
	cases := []struct {
		g        string
		peers    int64
		override int
		want     int
	}{
		{"192.0", 20, 0, MAX_INBOUND_PER_NETGROUP}, {"192.0", 101, 0, 10}, {"192.0", 400, 0, 40},
		{"192.0", 101, 3, 3}, {"2001:db8::/32", 101, 0, 20}, {"2001:db8::/32", 20, 0, 2 * MAX_INBOUND_PER_NETGROUP},
	}
	for _, c := range cases {
		if got := inbound_group_cap_for(c.g, c.peers, c.override); got != c.want {
			t.Fatalf("inbound_group_cap_for(%q, %d, %d) = %d, want %d", c.g, c.peers, c.override, got, c.want)
		}
	}
	if inbound_group_cap("192.0") != inbound_group_cap_for("192.0", Max_Peers, inbound_group_cap_env) {
		t.Fatal("inbound_group_cap does not use the live max-peers and override")
	}
}

func TestGroupLimitersBounded(t *testing.T) {
	l := &group_limiters{m: map[string]*rate.Limiter{}}
	for i := 0; i < INBOUND_GROUP_LIMITERS_MAX+10; i++ {
		l.allow("g" + strconv.Itoa(i))
	}
	if n := len(l.m); n > INBOUND_GROUP_LIMITERS_MAX {
		t.Fatalf("limiter map holds %d entries, cap %d", n, INBOUND_GROUP_LIMITERS_MAX)
	}
}

// r20 (r19 SEC-10 residual 7): the live binary's DefaultGODEBUG has tls10server=1; the p2p configs pin TLS 1.2.
func TestP2PTLSMinVersion(t *testing.T) {
	srvcfg := p2p_tls_server_config(generate_random_tls_cert())
	try := func(client *tls.Config) error {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		errc := make(chan error, 1)
		go func() { errc <- tls.Server(a, srvcfg).Handshake() }()
		cerr := tls.Client(b, client).Handshake()
		if cerr != nil {
			a.Close()
		}
		serr := <-errc
		if cerr != nil {
			return cerr
		}
		return serr
	}
	old := p2p_tls_client_config()
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	if err := try(old); err == nil {
		t.Fatal("a TLS 1.1 client completed a handshake with the p2p server")
	}
	if err := try(p2p_tls_client_config()); err != nil {
		t.Fatalf("the p2p client failed against the p2p server: %v", err)
	}
	upstream := &tls.Config{InsecureSkipVerify: true} // what an upstream peer's dialer sends
	if err := try(upstream); err != nil {
		t.Fatalf("an upstream peer's client config failed: %v", err)
	}
	if p2p_tls_client_config().MinVersion != tls.VersionTLS12 {
		t.Fatal("client floor")
	}
}

// r20 (r19 SEC-4 follow-up): writer and readers of the NTP offset no longer race (-race catches the plain version).
func TestClockOffsetPublishIsAtomic(t *testing.T) {
	var wg sync.WaitGroup
	var writes int64
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			globals.SetClockOffsetNTP(time.Duration(i%3) * time.Millisecond)
			globals.SetClockOffsetP2P(time.Duration(i%5) * time.Millisecond)
			atomic.AddInt64(&writes, 1)
		}
	}()
	// r20 merge: read until the writer has demonstrably run alongside (its first 2000 writes), so the reads and
	// writes overlap whatever the scheduler does; a fixed 2000 reads could finish before the writer started, and
	// then -race had nothing to see (gm-r20-clock-atomic-read was MISSED once in the merge run).
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < 2000 || atomic.LoadInt64(&writes) < 2000; i++ {
		globals.Time()
		globals.GetOffsetNTP()
		globals.GetOffsetP2P()
		if time.Now().After(deadline) {
			break
		}
	}
	close(stop)
	wg.Wait()
	globals.SetClockOffsetNTP(0)
	globals.SetClockOffsetP2P(0)
}
