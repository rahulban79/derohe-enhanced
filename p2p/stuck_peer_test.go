// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package p2p

import (
	"net"
	"testing"
	"time"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

func sv(c *Connection, ip string, h int64, out, exempt bool) stuck_view {
	return stuck_view{c: c, ip: ip, height: h, outgoing: out, exempt: exempt}
}

// the live r21 shape: healthy peers at the tip, one outgoing peer frozen far below
func stuck_views(frozen *Connection, frozen_h int64, tip int64, healthy ...*Connection) []stuck_view {
	var vs []stuck_view
	for i, c := range healthy {
		vs = append(vs, sv(c, "203.0.113."+string(rune('1'+i)), tip, true, false))
	}
	return append(vs, sv(frozen, "198.51.100.9", frozen_h, true, false))
}

func TestStuckSelectEvictsOnlyAfterWindow(t *testing.T) {
	t0 := time.Unix(1793281000, 0)
	track := map[*Connection]*stuck_track{}
	frozen, a, b, c := &Connection{}, &Connection{}, &Connection{}, &Connection{}
	tip := int64(7827000)
	for i, dt := range []time.Duration{0, 5 * time.Minute, STUCK_PEER_WINDOW - time.Second} {
		if got := stuck_select(stuck_views(frozen, 7537830, tip+int64(i), a, b, c), tip+int64(i), t0.Add(dt), track, nil); len(got) != 0 {
			t.Fatalf("evicted before the window at +%s", dt)
		}
	}
	got := stuck_select(stuck_views(frozen, 7537830, tip+3, a, b, c), tip+3, t0.Add(STUCK_PEER_WINDOW), track, nil)
	if len(got) != 1 || got[0].c != frozen {
		t.Fatalf("frozen peer not evicted after the window: %+v", got)
	}
}

func TestStuckSelectSparesCatchingUpPeer(t *testing.T) {
	t0 := time.Unix(1793281000, 0)
	track := map[*Connection]*stuck_track{}
	slow, a, b := &Connection{}, &Connection{}, &Connection{}
	tip := int64(7827000)
	for m := 0; m <= 60; m++ { // an hour, one block of progress per minute (far behind, but moving)
		if got := stuck_select(stuck_views(slow, 7500000+int64(m), tip, a, b), tip, t0.Add(time.Duration(m)*time.Minute), track, nil); len(got) != 0 {
			t.Fatalf("a peer that is catching up was evicted at minute %d", m)
		}
	}
}

func TestStuckSelectNeverEvictsIncomingOrExempt(t *testing.T) {
	t0 := time.Unix(1793281000, 0)
	track := map[*Connection]*stuck_track{}
	in, ex, a, b, c := &Connection{}, &Connection{}, &Connection{}, &Connection{}, &Connection{}
	tip := int64(1000)
	vs := []stuck_view{sv(a, "a", tip, true, false), sv(b, "b", tip, true, false), sv(c, "c", tip, true, false),
		sv(in, "in", 10, false, false), sv(ex, "ex", 10, true, true)}
	stuck_select(vs, tip, t0, track, nil)
	if got := stuck_select(vs, tip, t0.Add(time.Hour), track, nil); len(got) != 0 {
		t.Fatalf("evicted %+v", got)
	}
}

func TestStuckSelectNeedsCorroboration(t *testing.T) {
	t0 := time.Unix(1793281000, 0)
	tip := int64(1000)
	// only one healthy peer: our view of the tip is not corroborated
	track := map[*Connection]*stuck_track{}
	s1, a := &Connection{}, &Connection{}
	vs := []stuck_view{sv(a, "a", tip, true, false), sv(s1, "s1", 10, true, false)}
	stuck_select(vs, tip, t0, track, nil)
	if got := stuck_select(vs, tip, t0.Add(time.Hour), track, nil); len(got) != 0 {
		t.Fatal("evicted with one healthy peer")
	}
	// more stuck than healthy: refuse
	track = map[*Connection]*stuck_track{}
	s2, s3, b := &Connection{}, &Connection{}, &Connection{}
	vs = []stuck_view{sv(a, "a", tip, true, false), sv(b, "b", tip, true, false),
		sv(s1, "s1", 10, true, false), sv(s2, "s2", 11, true, false), sv(s3, "s3", 12, true, false)}
	stuck_select(vs, tip, t0, track, nil)
	if got := stuck_select(vs, tip, t0.Add(time.Hour), track, nil); len(got) != 0 {
		t.Fatal("evicted while stuck peers outnumber healthy ones")
	}
	// two stuck, two healthy: one per sweep, the lowest first
	vs = vs[:4]
	got := stuck_select(vs, tip, t0.Add(2*time.Hour), track, nil)
	if len(got) != 1 || got[0].c != s1 {
		t.Fatalf("want s1 only, got %+v", got)
	}
	// a peer exactly at the window edge is healthy
	edge := &Connection{}
	vs = []stuck_view{sv(a, "a", tip, true, false), sv(b, "b", tip, true, false), sv(edge, "e", tip-STUCK_PEER_BLOCKS, true, false)}
	stuck_select(vs, tip, t0, track, nil)
	if got := stuck_select(vs, tip, t0.Add(time.Hour), track, nil); len(got) != 0 {
		t.Fatal("evicted a peer inside the relay window")
	}
}

func TestStuckTrackForgetsGoneConnections(t *testing.T) {
	track := map[*Connection]*stuck_track{}
	a, gone := &Connection{}, &Connection{}
	now := time.Unix(1793281000, 0)
	stuck_select([]stuck_view{sv(a, "a", 1, true, false), sv(gone, "g", 1, true, false)}, 1, now, track, nil)
	stuck_select([]stuck_view{sv(a, "a", 1, true, false)}, 1, now, track, nil)
	if len(track) != 1 || track[gone] != nil {
		t.Fatalf("track %d entries", len(track))
	}
}

func TestStuckHoldDoublesAndCaps(t *testing.T) {
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, STUCK_HOLD_MAX, STUCK_HOLD_MAX}
	for i, w := range want {
		if got := stuck_hold_duration(uint(i + 1)); got != w {
			t.Fatalf("strike %d: %s want %s", i+1, got, w)
		}
	}
	now := time.Unix(1793281000, 0)
	ip := "198.51.100.61"
	defer func() { stuck.Lock(); delete(stuck.hold, ip); stuck.Unlock() }()
	if stuck_held(ip, now) {
		t.Fatal("held before any eviction")
	}
	u1 := stuck_hold_add(ip, 0, now)
	if !stuck_held(ip, now.Add(29*time.Minute)) || stuck_held(ip, u1) {
		t.Fatal("first hold is not 30 min")
	}
	if u2 := stuck_hold_add(ip, 0, u1); u2.Sub(u1) != time.Hour {
		t.Fatalf("second hold %s", u2.Sub(u1))
	}
}

func TestStuckHoldFailsOpenWhenFull(t *testing.T) {
	now := time.Unix(1793281000, 0)
	stuck.Lock()
	saved := stuck.hold
	stuck.hold = map[string]*stuck_hold_entry{}
	for i := 0; i < STUCK_HOLD_ENTRIES; i++ {
		stuck.hold[net.IPv4(10, 0, byte(i>>8), byte(i)).String()] = &stuck_hold_entry{strikes: 1, until: now.Add(time.Hour)}
	}
	stuck.Unlock()
	defer func() { stuck.Lock(); stuck.hold = saved; stuck.Unlock() }()
	if stuck_hold_add("198.51.100.62", 0, now); stuck_held("198.51.100.62", now) {
		t.Fatal("recorded beyond the bound")
	}
	if stuck_held_count(now) != STUCK_HOLD_ENTRIES {
		t.Fatal("count")
	}
}

// the sweep exits the connection, leaves the pool, holds the address and defers its peer-list entry
func TestStuckSweepEvictsHoldsAndDefers(t *testing.T) {
	now := time.Unix(1793281000, 0)
	ip := "198.51.100.63"
	mk := func(addr string, h int64) *Connection {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		c := &Connection{Addr: fake_addr(addr), Conn: a, ConnTls: a, logger: globals.Logger}
		c.State.Store(ACTIVE)
		c.Height.Store(h)
		connection_map.Store(Address(c), c)
		t.Cleanup(func() { connection_map.CompareAndDelete(Address(c), c) })
		return c
	}
	h1, h2, frozen := mk("203.0.113.71:11011", 5000), mk("203.0.113.72:11011", 5000), mk(ip+":11011", 100)
	peer_mutex.Lock()
	peer_map[ip] = &Peer{Address: ip + ":11011", Whitelist: true, LastConnected: uint64(now.Unix())}
	peer_mutex.Unlock()
	defer func() {
		peer_mutex.Lock()
		delete(peer_map, ip)
		peer_mutex.Unlock()
		stuck.Lock()
		delete(stuck.hold, ip)
		stuck.track = map[*Connection]*stuck_track{}
		stuck.Unlock()
	}()
	vs := []stuck_view{sv(h1, Address(h1), 5000, true, false), sv(h2, Address(h2), 5000, true, false), sv(frozen, ip, 100, true, false)}
	if got := stuck_peer_sweep_with(vs, 5000, now); len(got) != 0 {
		t.Fatal("evicted on first sight")
	}
	got := stuck_peer_sweep_with(vs, 5000, now.Add(STUCK_PEER_WINDOW))
	if len(got) != 1 || got[0].c != frozen {
		t.Fatalf("got %+v", got)
	}
	if frozen.exited.Load() != 1 || IsAddressConnected(ip) {
		t.Fatal("frozen peer still connected")
	}
	if h1.exited.Load() != 0 || h2.exited.Load() != 0 {
		t.Fatal("a healthy peer was evicted")
	}
	if !stuck_held(ip, now.Add(STUCK_PEER_WINDOW+time.Minute)) {
		t.Fatal("address not held")
	}
	peer_mutex.Lock()
	ca := peer_map[ip].ConnectAfter
	peer_mutex.Unlock()
	if ca < uint64(now.Add(STUCK_PEER_WINDOW+STUCK_HOLD).Unix()) {
		t.Fatalf("peer list ConnectAfter %d not deferred", ca)
	}
}

// connect_with_endpoint refuses a held address before it records a dial back-off or opens a socket
func TestDialRefusesStuckHeldAddress(t *testing.T) {
	ip := "127.0.0.1"
	stuck_hold_add(ip, 0, time.Now())
	defer func() {
		stuck.Lock()
		delete(stuck.hold, ip)
		stuck.Unlock()
		backoff_mutex.Lock()
		delete(backoff, ip)
		backoff_mutex.Unlock()
	}()
	connect_with_endpoint("127.0.0.1:1", false)
	backoff_mutex.Lock()
	_, dialed := backoff[ip]
	backoff_mutex.Unlock()
	if dialed {
		t.Fatal("a stuck-held address was dialled")
	}
}

// r23 fast re-eviction: the live r22 cycle (evicted at height H, held, redialled, still at H) costs one sweep, not
// another STUCK_PEER_WINDOW; a peer that moved even one block is judged by the normal window again.
func TestStuckSelectFastReevictsKnownHeight(t *testing.T) {
	t0 := time.Unix(1793281000, 0)
	tip := int64(7830381)
	a, b, c := &Connection{}, &Connection{}, &Connection{}
	hold := map[string]*stuck_hold_entry{"198.51.100.9": {strikes: 3, until: t0.Add(-time.Second), height: 7472150}}

	again := &Connection{} // a fresh connection after the hold, same frozen height
	got := stuck_select(stuck_views(again, 7472150, tip, a, b, c), tip, t0, map[*Connection]*stuck_track{}, hold)
	if len(got) != 1 || got[0].c != again {
		t.Fatalf("known-stuck peer not re-evicted on first sight: %+v", got)
	}

	moved := &Connection{} // same address, one block further: not the recorded height
	track := map[*Connection]*stuck_track{}
	if got := stuck_select(stuck_views(moved, 7472151, tip, a, b, c), tip, t0, track, hold); len(got) != 0 {
		t.Fatalf("a peer that moved was fast-evicted: %+v", got)
	}
	if got := stuck_select(stuck_views(moved, 7472151, tip, a, b, c), tip, t0.Add(STUCK_PEER_WINDOW), track, hold); len(got) != 1 {
		t.Fatal("a moved-then-frozen peer must still be evicted after the normal window")
	}

	// the safety rules still apply: no corroboration -> no eviction, even for a known-stuck peer
	if got := stuck_select([]stuck_view{sv(a, "a", tip, true, false), sv(again, "198.51.100.9", 7472150, true, false)}, tip, t0,
		map[*Connection]*stuck_track{}, hold); len(got) != 0 {
		t.Fatal("fast re-eviction bypassed corroboration")
	}
	// and an exempt (seed/priority) or incoming known-stuck peer is never evicted
	for _, v := range []stuck_view{sv(again, "198.51.100.9", 7472150, true, true), sv(again, "198.51.100.9", 7472150, false, false)} {
		vs := []stuck_view{sv(a, "a", tip, true, false), sv(b, "b", tip, true, false), v}
		if got := stuck_select(vs, tip, t0, map[*Connection]*stuck_track{}, hold); len(got) != 0 {
			t.Fatalf("evicted exempt/incoming known-stuck peer %+v", v)
		}
	}
}

// the sweep records the eviction height, so the next cycle is fast; it counts fast evictions separately
func TestStuckSweepRecordsHeightForFastCycle(t *testing.T) {
	now := time.Unix(1793281000, 0)
	ip := "198.51.100.64"
	mk := func(addr string, h int64) *Connection {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		c := &Connection{Addr: fake_addr(addr), Conn: a, ConnTls: a, logger: globals.Logger}
		c.State.Store(ACTIVE)
		c.Height.Store(h)
		return c
	}
	defer func() {
		stuck.Lock()
		delete(stuck.hold, ip)
		stuck.track = map[*Connection]*stuck_track{}
		stuck.Unlock()
	}()
	h1, h2 := mk("203.0.113.81:11011", 5000), mk("203.0.113.82:11011", 5000)
	first := mk(ip+":11011", 100)
	vs := func(c *Connection) []stuck_view {
		return []stuck_view{sv(h1, "203.0.113.81", 5000, true, false), sv(h2, "203.0.113.82", 5000, true, false), sv(c, ip, 100, true, false)}
	}
	stuck_peer_sweep_with(vs(first), 5000, now)
	fastw := metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total").Get()
	if got := stuck_peer_sweep_with(vs(first), 5000, now.Add(STUCK_PEER_WINDOW)); len(got) != 1 {
		t.Fatal("first eviction did not happen after the window")
	}
	if d := metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total").Get() - fastw; d != 0 {
		t.Fatalf("a window-based eviction was counted as fast (%d)", d)
	}
	stuck.Lock()
	e := stuck.hold[ip]
	rec := int64(-1)
	if e != nil {
		rec = e.height
	}
	stuck.Unlock()
	if rec != 100 {
		t.Fatalf("eviction height not recorded: %d", rec)
	}
	fast0 := metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total").Get()
	second := mk(ip+":11011", 100) // redialled after the hold
	back := now.Add(STUCK_PEER_WINDOW + STUCK_HOLD + time.Second)
	got := stuck_peer_sweep_with(vs(second), 5000, back)
	if len(got) != 1 || got[0].c != second || second.exited.Load() != 1 {
		t.Fatalf("redialled known-stuck peer not evicted on the first sweep: %+v", got)
	}
	if d := metrics.Set.GetOrCreateCounter("p2p_stuck_peer_fast_evictions_total").Get() - fast0; d != 1 {
		t.Fatalf("fast eviction counter moved by %d", d)
	}
	if !stuck_held(ip, back.Add(STUCK_HOLD+time.Minute)) { // second strike: 1 h
		t.Fatal("second strike hold is not doubled")
	}
}
