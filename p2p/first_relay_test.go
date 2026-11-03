package p2p

import (
	"net"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": false, "192.168.1.218": false, "10.1.2.3": false, "172.16.5.4": false,
		"100.85.181.2": false, "169.254.1.1": false, "0.0.0.0": false, "::1": false, "fe80::1": false,
		"203.0.113.10": true, "203.0.113.22": true, "100.128.0.1": true, "2a01:4f8::1": true,
	}
	for s, want := range cases {
		if got := is_public(net.ParseIP(s)); got != want {
			t.Errorf("is_public(%s)=%v want %v", s, got, want)
		}
	}
}

func TestDialAddress(t *testing.T) {
	out := &Connection{Addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 11011}}
	if got := dial_address(out); got != "203.0.113.10:11011" {
		t.Errorf("outgoing: %q", got)
	}
	in := &Connection{Incoming: true, Port: 10101, Addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 55555}}
	if got := dial_address(in); got != "1.2.3.4:10101" { // the advertised port, not the ephemeral source port
		t.Errorf("incoming: %q", got)
	}
	in.Port = 0
	if got := dial_address(in); got != "" {
		t.Errorf("incoming without port must not be dialable: %q", got)
	}
	if dial_address(nil) != "" || dial_address(&Connection{}) != "" {
		t.Error("nil connection/addr")
	}
}

func TestFirstRelayRankingAndHalving(t *testing.T) {
	tb := first_relay_table{Peers: map[string]*RelayStat{}}
	now := time.Unix(1792769000, 0)
	integ := make([]byte, 33)
	for i := 0; i < 7; i++ {
		tb.record("1.1.1.1", "1.1.1.1:11011", integ, 80_000, now)
	}
	for i := 0; i < 3; i++ {
		tb.record("2.2.2.2", "2.2.2.2:11011", integ, 200_000, now)
	}
	for i := 0; i < 9; i++ {
		tb.record("3.3.3.3", "", integ, 50_000, now) // never told us a port: not dialable
	}
	tb.record("4.4.4.4", "4.4.4.4:11011", integ, -5, now) // clock skew: counted, delay ignored
	tb.record("", "x", integ, 1, now)                     // no ip: ignored
	if got := tb.top(8, 5); len(got) != 1 || got[0] != "1.1.1.1:11011" {
		t.Fatalf("top(8,5)=%v", got)
	}
	if got := tb.top(8, 1); len(got) != 3 || got[0] != "1.1.1.1:11011" || got[1] != "2.2.2.2:11011" || got[2] != "4.4.4.4:11011" {
		t.Fatalf("top(8,1)=%v", got)
	}
	if got := tb.top(1, 1); len(got) != 1 {
		t.Fatalf("top(1,1)=%v", got)
	}
	if tb.score("3.3.3.3") != 9 || tb.score("9.9.9.9") != 0 {
		t.Fatalf("score")
	}
	if s := tb.Peers["4.4.4.4"]; s.DelayN != 0 || s.Firsts != 1 {
		t.Fatalf("skewed delay must not be averaged: %+v", s)
	}
	if s := tb.Peers["1.1.1.1"]; s.DelayN != 7 || s.DelaySumUs != 7*80_000 || s.Builders["0000000000000000"] != 7 {
		t.Fatalf("stats %+v", s)
	}
	tb.halve()
	if tb.score("1.1.1.1") != 3 || tb.score("2.2.2.2") != 1 || tb.Peers["4.4.4.4"] != nil {
		t.Fatalf("halve: %d %d %v", tb.score("1.1.1.1"), tb.score("2.2.2.2"), tb.Peers["4.4.4.4"])
	}
	// automatic halving after FIRST_RELAY_HALVE_AFTER blocks keeps counters bounded
	tb2 := first_relay_table{Peers: map[string]*RelayStat{}}
	for i := 0; i < FIRST_RELAY_HALVE_AFTER; i++ {
		tb2.record("5.5.5.5", "5.5.5.5:1", integ, 1, now)
	}
	if f := tb2.score("5.5.5.5"); f != FIRST_RELAY_HALVE_AFTER/2 {
		t.Fatalf("auto-halve: %d", f)
	}
}

// helpers to drive the package-level peer map in isolation
func with_peer_map(t *testing.T, m map[string]*Peer) {
	t.Helper()
	peer_mutex.Lock()
	saved := peer_map
	peer_map = m
	peer_mutex.Unlock()
	saved_fr := first_relay.Peers
	first_relay.Lock()
	first_relay.Peers = map[string]*RelayStat{}
	first_relay.Unlock()
	t.Cleanup(func() {
		peer_mutex.Lock()
		peer_map = saved
		peer_mutex.Unlock()
		first_relay.Lock()
		first_relay.Peers = saved_fr
		first_relay.Unlock()
	})
}

func TestGetPeerListKeepsDisconnectedWhitelisted(t *testing.T) {
	now := uint64(time.Now().UTC().Unix())
	with_peer_map(t, map[string]*Peer{
		"203.0.113.7": {Address: "203.0.113.7:11011", Whitelist: true, LastConnected: now},
	})
	if l := get_peer_list(); len(l) != 0 { // not connected -> not shared (same as upstream)
		t.Fatalf("shared a disconnected peer: %v", l)
	}
	if !IsPeerInList("203.0.113.7") { // ...but no longer deleted
		t.Fatal("get_peer_list deleted a proven peer that was momentarily disconnected")
	}
}

func TestRetention(t *testing.T) {
	if retention_seconds(&Peer{Whitelist: true}) != 86400 || retention_seconds(&Peer{}) != 3600 {
		t.Fatal("retention")
	}
	now := uint64(time.Now().UTC().Unix())
	with_peer_map(t, map[string]*Peer{
		"203.0.113.8": {Address: "203.0.113.8:11011", Whitelist: true, LastConnected: now - 7200},
		"203.0.113.9": {Address: "203.0.113.9:11011", LastConnected: now - 7200},
	})
	clean_up()
	if !IsPeerInList("203.0.113.8") || IsPeerInList("203.0.113.9") {
		t.Fatal("2h-old proven peer must stay, 2h-old grey peer must go")
	}
}

func TestFindPeerPrefersFirstRelay(t *testing.T) {
	now := uint64(time.Now().UTC().Unix())
	m := map[string]*Peer{}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"} {
		m[ip] = &Peer{Address: ip + ":11011", Whitelist: true, LastConnected: now}
	}
	with_peer_map(t, m)
	for i := 0; i < 4; i++ {
		first_relay.record("203.0.113.12", "203.0.113.12:11011", nil, 1, time.Now())
	}
	first_relay.record("203.0.113.11", "203.0.113.11:11011", nil, 1, time.Now())
	for trial := 0; trial < 20; trial++ { // map order is random; the ranked peer must win every time
		peer_mutex.Lock()
		for _, v := range peer_map {
			v.ConnectAfter = 0
		}
		peer_mutex.Unlock()
		if p := find_peer_to_connect(1); p == nil || p.Address != "203.0.113.12:11011" {
			t.Fatalf("trial %d picked %+v", trial, p)
		}
	}
	// with the ranked peer in its 10 s ConnectAfter gap, the next best is chosen
	if p := find_peer_to_connect(1); p == nil || p.Address != "203.0.113.11:11011" {
		t.Fatalf("second pick %+v", p)
	}
}
