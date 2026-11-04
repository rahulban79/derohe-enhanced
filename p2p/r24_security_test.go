// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r24 (security): forged-input tests for the hard penalty-table bound (B28) and the returning-peer accept lane (B30).

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func reset_proven(t testing.TB) {
	proven_mu.Lock()
	saved_m, saved_l, saved_pg := proven_map, proven_lane, proven_groups // r25: the netgroup counts too
	proven_map, proven_lane = map[string]*proven_rec{}, rate.NewLimiter(PROVEN_LANE_RATE, PROVEN_LANE_BURST)
	proven_groups = map[string]*int{}
	proven_mu.Unlock()
	saved_g := inbound_group_limiters
	inbound_group_limiters = &group_limiters{m: map[string]*rate.Limiter{}}
	t.Cleanup(func() {
		proven_mu.Lock()
		proven_map, proven_lane, proven_groups = saved_m, saved_l, saved_pg
		proven_mu.Unlock()
		inbound_group_limiters = saved_g
	})
}

// Every record under a running ban: r23c let the table grow past its bound (85,536 records after 85,536 banned /64s
// on base 04ceb55). Now it never holds more than PENALTY_MAX_ENTRIES, the newest bans are kept and the ones ending
// soonest are evicted.
func TestR24PenaltyHardBoundAllBanned(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(1700000000, 0)
	total := PENALTY_MAX_ENTRIES + 20000
	scope := func(i int) string { return fmt.Sprintf("2001:db8:%x:%x::/64", i/65536, i%65536) }
	for i := 0; i < total; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		add_penalty(scope(i), "invalid_pow", at)
		if add_penalty(scope(i), "undecodable", at) == 0 {
			t.Fatalf("record %d was not banned: the scenario is wrong", i)
		}
		penalty_mu.Lock()
		n := len(penalty_map)
		penalty_mu.Unlock()
		if n > PENALTY_MAX_ENTRIES {
			t.Fatalf("after %d banned scopes the table holds %d records (bound %d)", i+1, n, PENALTY_MAX_ENTRIES)
		}
	}
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	if penalty_map[scope(total-1)] == nil {
		t.Fatal("the newest ban was evicted")
	}
	if penalty_map[scope(0)] != nil {
		t.Fatal("the ban ending soonest survived while newer ones were evicted")
	}
}

// What carries no running ban goes first: score-only records and ended bans are evicted before any running ban.
func TestR24PenaltyEvictPrefersUnbanned(t *testing.T) {
	reset_penalty(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Unix(1700000000, 0)
	half := PENALTY_MAX_ENTRIES / 2
	for i := 0; i < half; i++ { // running bans
		ip := fmt.Sprintf("2001:db8:1:%x::/64", i)
		add_penalty(ip, "invalid_pow", now)
		add_penalty(ip, "undecodable", now)
	}
	for i := 0; i < PENALTY_MAX_ENTRIES-half; i++ { // score-only records (50 of 100 points)
		add_penalty(fmt.Sprintf("2001:db8:2:%x::/64", i), "invalid_pow", now)
	}
	add_penalty("192.0.2.1", "busy", now.Add(time.Second)) // one more record: past the bound
	penalty_mu.Lock()
	defer penalty_mu.Unlock()
	banned := 0
	for _, v := range penalty_map {
		if now.Add(time.Second).Before(v.banned_until) {
			banned++
		}
	}
	if banned != half {
		t.Fatalf("%d of %d running bans kept: a running ban was evicted while score-only records remained", banned, half)
	}
	if len(penalty_map) > PENALTY_MAX_ENTRIES {
		t.Fatalf("table %d > %d", len(penalty_map), PENALTY_MAX_ENTRIES)
	}
}

// B30: forged sources from 1,000 different /16s drain the shared 10/s accept bucket. An unproven honest peer is then
// refused (as before: the forgery works against strangers), a peer that completed a handshake before still gets in
// through the lane, once per PROVEN_PER_IP_INTERVAL.
func TestR24ProvenLaneSurvivesSpoofDrain(t *testing.T) {
	reset_proven(t)
	shared := rate.NewLimiter(10, 40)
	for i := 0; i < 1000; i++ {
		admit_inbound(fmt.Sprintf("11.%d.%d.1", i/200, i%200), shared)
	}
	if admit_inbound("198.51.100.9", shared) {
		t.Fatal("the forged flood did not drain the shared bucket: the test does not test the drain")
	}
	note_proven("203.0.113.9", time.Now())
	if !admit_inbound("203.0.113.9", shared) {
		t.Fatal("a proven returning peer was refused while forged sources held the shared bucket")
	}
	if admit_inbound("203.0.113.9", shared) {
		t.Fatal("the lane admitted the same proven address twice within PROVEN_PER_IP_INTERVAL")
	}
}

// A forger that knows the proven addresses gets at most the lane's burst + rate, and one per address per interval.
func TestR24ProvenLaneBounded(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	for i := 0; i < 200; i++ { // r25 (B48): 50 per /16, under the netgroup quota, so every proof is kept
		note_proven(fmt.Sprintf("198.%d.0.%d", 18+i/50, i%50), now)
	}
	admitted := 0
	for s := 0; s < 10; s++ { // 10 s of forging every proven address 10 times a second
		for r := 0; r < 10; r++ {
			at := now.Add(time.Duration(s)*time.Second + time.Duration(r)*100*time.Millisecond)
			for i := 0; i < 200; i++ {
				if proven_lane_allow(fmt.Sprintf("198.%d.0.%d", 18+i/50, i%50), at) {
					admitted++
				}
			}
		}
	}
	if limit := PROVEN_LANE_BURST + int(PROVEN_LANE_RATE*10) + 1; admitted > limit {
		t.Fatalf("lane admitted %d sessions in 10 s (bound %d)", admitted, limit)
	}
	if proven_lane_allow("198.18.9.9", now.Add(time.Minute)) {
		t.Fatal("an unproven address used the lane")
	}
	if proven_lane_allow("198.18.0.1", now.Add(PROVEN_TTL+time.Hour)) {
		t.Fatal("an expired proof still opens the lane")
	}
}

// The proven set is bounded and keeps the newest proofs.
func TestR24ProvenSetBounded(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	for i := 0; i < PROVEN_MAX+500; i++ {
		note_proven(fmt.Sprintf("2001:db8::%x", i), now.Add(time.Duration(i)*time.Millisecond))
	}
	proven_mu.Lock()
	defer proven_mu.Unlock()
	if len(proven_map) > PROVEN_MAX {
		t.Fatalf("proven set holds %d (bound %d)", len(proven_map), PROVEN_MAX)
	}
	if proven_map[fmt.Sprintf("2001:db8::%x", PROVEN_MAX+499)] == nil {
		t.Fatal("the newest proof was dropped")
	}
}

// The proof is recorded where a verified handshake joins the pool (both directions run handshake_accepted).
func TestR24HandshakeAcceptedProvesAddress(t *testing.T) {
	reset_proven(t)
	defer reset_unlisted()()
	addr, _ := net.ResolveUDPAddr("udp", "203.0.113.44:11011")
	c := &Connection{Addr: addr}
	if proven_lane_allow("203.0.113.44", time.Now()) {
		t.Fatal("unproven address admitted by the lane")
	}
	c.handshake_accepted(&Handshake_Struct{DaemonVersion: "3.6.0-153", Local_Port: 11011, Peer_ID: 9})
	if !proven_lane_allow("203.0.113.44", time.Now()) {
		t.Fatal("a peer whose handshake was accepted is not proven")
	}
}

// Forged sources inside the proven peer's own /16 drain that netgroup's accept bucket (1/s, burst 8); the proven peer
// still gets in through the lane, an unproven neighbour does not.
func TestR24ProvenLaneSurvivesNetgroupDrain(t *testing.T) {
	reset_proven(t)
	shared := rate.NewLimiter(10, 40)
	for i := 0; i < 50; i++ {
		admit_inbound(fmt.Sprintf("203.0.%d.%d", 100+i/200, 1+i%200), shared)
	}
	if admit_inbound("203.0.7.7", shared) {
		t.Fatal("the forged flood did not drain the /16 bucket: the test does not test it")
	}
	note_proven("203.0.113.9", time.Now())
	if !admit_inbound("203.0.113.9", shared) {
		t.Fatal("a proven returning peer was refused while forged sources of its /16 held the netgroup bucket")
	}
}
