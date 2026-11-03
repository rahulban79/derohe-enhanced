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
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/p2p/nat"
	"github.com/go-logr/logr"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

func TestKCPMTUPerFamily(t *testing.T) {
	saved := KCP_MTU_OVERRIDE
	defer func() { KCP_MTU_OVERRIDE = saved }()
	KCP_MTU_OVERRIDE = 0
	cases := map[string]int{
		"203.0.113.7:11011":      KCP_MTU_DEFAULT,
		"[::ffff:1.2.3.4]:11011": KCP_MTU_DEFAULT, // IPv4 peer on the dual-stack listener
		"[2001:db8::1]:11011":    KCP_MTU_IPV6,
	}
	for a, want := range cases {
		ua, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			t.Fatal(err)
		}
		if got := kcp_mtu_for(ua); got != want {
			t.Errorf("%s: mtu %d want %d", a, got, want)
		}
	}
	// 1232 + 40 (IPv6) + 8 (UDP) must fit the IPv6 minimum MTU
	if KCP_MTU_IPV6+40+8 > 1280 {
		t.Fatal("IPv6 payload budget exceeds the 1280 minimum MTU")
	}
	KCP_MTU_OVERRIDE = 100
	if kcp_mtu_for(nil) != 576 {
		t.Fatal("override below 576 not clamped")
	}
	KCP_MTU_OVERRIDE = 1300
	if kcp_mtu_for(&net.UDPAddr{IP: net.ParseIP("2001:db8::1")}) != 1300 {
		t.Fatal("override ignored")
	}
}

// an IPv6 KCP session with the clamped MTU still carries data intact (the receiver reads segment lengths from the
// segment headers, so an upstream peer at the default 1400 interoperates)
func TestIPv6ClampedSessionRoundTrip(t *testing.T) {
	l6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	key := pbkdf2.Key([]byte("t"), []byte("t"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	l, err := kcp.ServeConn(block, 10, 3, l6)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer l6.Close()
	payload := make([]byte, 256*1024)
	rand.Read(payload)
	done := make(chan []byte, 1)
	go func() {
		s, err := l.AcceptKCP()
		if err != nil {
			done <- nil
			return
		}
		defer s.Close()
		got := make([]byte, len(payload))
		s.SetReadDeadline(time.Now().Add(20 * time.Second))
		io.ReadFull(s, got)
		done <- got
	}()
	c, err := kcp.DialWithOptions(l6.LocalAddr().String(), block, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if kcp_mtu_for(c.RemoteAddr()) != KCP_MTU_IPV6 {
		t.Fatalf("dial to %s not treated as IPv6", c.RemoteAddr())
	}
	tunekcp(c)
	c.Write(payload)
	if got := <-done; !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted over clamped IPv6 session")
	}
}

func TestDSCPMarkingAcceptedBySockets(t *testing.T) {
	saved := P2P_DSCP
	defer func() { P2P_DSCP = saved }()
	P2P_DSCP = 46
	key := pbkdf2.Key([]byte("t"), []byte("t"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	l, err := kcp.ListenWithOptions("127.0.0.1:0", block, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	before := atomic.LoadUint64(&dscp_applied)
	tune_listener(l)
	if atomic.LoadUint64(&dscp_applied) != before+1 {
		t.Fatalf("tune_listener did not mark the listener socket (applied %d -> %d, failed %d)", before, atomic.LoadUint64(&dscp_applied), atomic.LoadUint64(&dscp_failed))
	}
	if err := l.SetDSCP(P2P_DSCP); err != nil {
		t.Fatalf("listener rejects DSCP: %v", err)
	}
	c, err := kcp.DialWithOptions(l.Addr().String(), block, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	before = atomic.LoadUint64(&dscp_applied)
	tunekcp(c)
	if atomic.LoadUint64(&dscp_applied) != before+1 {
		t.Fatalf("tunekcp did not mark the dialed socket (applied %d -> %d, failed %d)", before, atomic.LoadUint64(&dscp_applied), atomic.LoadUint64(&dscp_failed))
	}
	P2P_DSCP = 0
	before = atomic.LoadUint64(&dscp_applied)
	tunekcp(c)
	if atomic.LoadUint64(&dscp_applied) != before {
		t.Fatal("DSCP marked although DERO_P2P_DSCP is 0 (default off)")
	}
	P2P_DSCP = 46
	if err := c.SetDSCP(P2P_DSCP); err != nil {
		t.Fatalf("dialed session rejects DSCP: %v", err)
	}
}

// minimal NAT-PMP gateway granting externalPort for any request
func fake_pmp_gateway(t *testing.T, externalPort uint16) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1100)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			switch {
			case n >= 2 && buf[0] == 2: // PCP: "unsupported version" so the client falls back
				c.WriteToUDP([]byte{0, 128 + buf[1], 0, 1}, from)
			case n == 2 && buf[1] == 0:
				r := make([]byte, 12)
				r[1] = 128
				copy(r[8:], []byte{198, 51, 100, 20})
				c.WriteToUDP(r, from)
			case n == 12 && buf[1] == 1:
				r := make([]byte, 16)
				r[1] = 129
				copy(r[8:10], buf[4:6])
				if binary.BigEndian.Uint32(buf[8:12]) != 0 {
					binary.BigEndian.PutUint16(r[10:12], externalPort)
					copy(r[12:16], buf[8:12])
				}
				c.WriteToUDP(r, from)
			}
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c
}

// while a mapping is active the handshake must advertise the gateway's external port, not the bound one
func TestAdvertisedPortFollowsNATMapping(t *testing.T) {
	logger = logr.Discard()
	savedPort := P2P_Port
	defer func() { P2P_Port = savedPort }()
	P2P_Port = 11011
	if advertised_port() != 11011 {
		t.Fatal("no mapping: must advertise the bound port")
	}
	gw := fake_pmp_gateway(t, 40404)
	nat_mu.Lock()
	nat_manager = nat.Start(nat.Options{Mode: nat.ModeNATPMP, InternalPort: 11011, Gateway: net.IPv4(127, 0, 0, 1),
		GatewayPort: gw.LocalAddr().(*net.UDPAddr).Port, Retry: nat.Retry{Initial: 40 * time.Millisecond, Tries: 3}})
	m := nat_manager
	nat_mu.Unlock()
	defer func() {
		stop_nat()
		nat_mu.Lock()
		nat_manager = nil
		nat_mu.Unlock()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !m.Status().Active && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := advertised_port(); got != 40404 {
		t.Fatalf("advertised %d, want the external port 40404 (status %+v)", got, NAT_Status())
	}
	if st := NAT_Status(); st.ExternalIP != "198.51.100.20" || st.Protocol != "natpmp" {
		t.Fatalf("status %+v", st)
	}
	stop_nat()
	if advertised_port() != 11011 {
		t.Fatal("after unmapping the bound port must be advertised again")
	}
}

func TestNATModeParsing(t *testing.T) {
	logger = logr.Discard()
	saved, had := globals.Arguments["--p2p-nat"]
	defer func() {
		if had {
			globals.Arguments["--p2p-nat"] = saved
		} else {
			delete(globals.Arguments, "--p2p-nat")
		}
	}()
	if globals.Arguments == nil {
		globals.Arguments = map[string]interface{}{}
	}
	delete(globals.Arguments, "--p2p-nat")
	if nat_mode() != nat.ModeOff {
		t.Fatal("absent flag must be off")
	}
	globals.Arguments["--p2p-nat"] = "auto"
	if nat_mode() != nat.ModeAuto {
		t.Fatal("auto")
	}
	globals.Arguments["--p2p-nat"] = "yes-please"
	if nat_mode() != nat.ModeOff {
		t.Fatal("invalid value must disable mapping")
	}
}

// a never-ban entry must never be reported as banned, even when a ban for it exists
func TestNonBanListEntryIsNotReportedBanned(t *testing.T) {
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = append(append([]string{}, saved...), "198.51.100.77")
	ban_mutex.Lock()
	ban_map["198.51.100.77"] = uint64(time.Now().Unix()) + 3600
	ban_mutex.Unlock()
	defer func() {
		ban_mutex.Lock()
		delete(ban_map, "198.51.100.77")
		ban_mutex.Unlock()
	}()
	if IsAddressInBanList("198.51.100.77") {
		t.Fatal("priority/seed address reported as banned")
	}
}

// NL-04: on the wire, an IPv6 session tuned by tunekcp sends no UDP payload above KCP_MTU_IPV6. A relay between the
// dialer and the listener records the largest datagram the dialer sent.
func TestKCPWireSizeIPv6(t *testing.T) {
	l6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	relay, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	key := pbkdf2.Key([]byte("t"), []byte("t"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	l, err := kcp.ServeConn(block, 10, 3, l6)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer l6.Close()
	var mu sync.Mutex
	largest := 0
	go func() { // dialer <-> relay <-> listener
		buf := make([]byte, 65536)
		var dialer *net.UDPAddr
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if from.Port == l6.LocalAddr().(*net.UDPAddr).Port {
				if dialer != nil {
					relay.WriteToUDP(buf[:n], dialer)
				}
				continue
			}
			dialer = from
			mu.Lock()
			if n > largest {
				largest = n
			}
			mu.Unlock()
			relay.WriteToUDP(buf[:n], l6.LocalAddr().(*net.UDPAddr))
		}
	}()
	payload := make([]byte, 128*1024)
	rand.Read(payload)
	done := make(chan bool, 1)
	go func() {
		s, err := l.AcceptKCP()
		if err != nil {
			done <- false
			return
		}
		defer s.Close()
		got := make([]byte, len(payload))
		s.SetReadDeadline(time.Now().Add(20 * time.Second))
		_, err = io.ReadFull(s, got)
		done <- err == nil && bytes.Equal(got, payload)
	}()
	c, err := kcp.DialWithOptions(relay.LocalAddr().String(), block, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tunekcp(c)
	c.Write(payload)
	if !<-done {
		t.Fatal("payload not delivered through the relay")
	}
	mu.Lock()
	defer mu.Unlock()
	if largest > KCP_MTU_IPV6 || largest < KCP_MTU_IPV6-200 {
		t.Fatalf("largest datagram on the IPv6 path %d bytes, want <= %d (and near it)", largest, KCP_MTU_IPV6)
	}
}
