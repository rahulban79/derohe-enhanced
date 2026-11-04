// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r25 (secpool): forged-input tests of the proven-lane netgroup quota (B48) and of the unservable-sync back-off (B47).

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

// honest_proofs notes n honest proofs, one per /16 (198.51.x.7, x < 256: n <= 256), and returns their addresses.
func r25_honest_proofs(n int, now time.Time) (ips []string) {
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("%d.%d.0.7", 40+i/256, i%256)
		note_proven(ip, now)
		ips = append(ips, ip)
	}
	return
}

func r25_survivors(ips []string) (n int) {
	proven_mu.Lock()
	defer proven_mu.Unlock()
	for _, ip := range ips {
		if proven_map[ip] != nil {
			n++
		}
	}
	return
}

// r25_operator completes handshakes from `total` addresses spread round-robin over `groups` /16s (60.0/16 upward),
// each one millisecond after the last, starting at `at`.
func r25_operator(groups, total int, at time.Time) {
	for i := 0; i < total; i++ {
		g := i % groups
		host := i / groups
		note_proven(fmt.Sprintf("%d.%d.%d.%d", 100+g/256, g%256, host/250, 1+host%250), at.Add(time.Duration(i)*time.Millisecond))
	}
}

// B48: r24 kept the newest PROVEN_MAX proofs whatever their netgroup, so PROVEN_MAX real handshakes from ONE /16
// evicted every honest proof (base 17da0dc: 0 of 100 honest proofs left). Now that /16 holds at most
// PROVEN_PER_NETGROUP and every honest proof survives.
func TestR25ProvenQuotaOneNetgroupCannotEvictHonest(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	honest := r25_honest_proofs(100, now)
	r25_operator(1, PROVEN_MAX, now.Add(time.Second))
	if s := r25_survivors(honest); s != len(honest) {
		t.Fatalf("one netgroup with %d handshakes evicted %d of %d honest proofs", PROVEN_MAX, len(honest)-s, len(honest))
	}
	proven_mu.Lock()
	defer proven_mu.Unlock()
	if n := proven_groups["100.0"]; n == nil || *n > PROVEN_PER_NETGROUP {
		t.Fatalf("netgroup count %v (quota %d)", n, PROVEN_PER_NETGROUP)
	}
	if len(proven_map) > PROVEN_MAX {
		t.Fatalf("proven set %d > %d", len(proven_map), PROVEN_MAX)
	}
	// the counts stay exact: recount from the records
	recount := map[string]int{}
	for _, r := range proven_map {
		if r.group != "" {
			recount[r.group]++
			if r.gn != proven_groups[r.group] {
				t.Fatalf("record of %s points at a stale count", r.group)
			}
		}
	}
	for g, n := range recount {
		if c := proven_groups[g]; c == nil || *c != n {
			t.Fatalf("netgroup %s counted %v, holds %d", g, c, n)
		}
	}
	if len(recount) != len(proven_groups) {
		t.Fatalf("stale netgroup counts: %d counted, %d hold proofs", len(proven_groups), len(recount))
	}
}

// B48: with the set full, the LARGEST netgroup loses its oldest proof. An operator that fills the set from 64 /16s
// (64 each, its own quota) still evicts no honest single-address /16; neither do 256 /16s nor 1,024 /16s (measured: 100/100 honest kept; 2,048 /16s also 100/100 in a one-off run).
func TestR25ProvenFullSetEvictsLargestNetgroup(t *testing.T) {
	for _, groups := range []int{64, 256, 1024} {
		reset_proven(t)
		now := time.Unix(1700000000, 0)
		honest := r25_honest_proofs(100, now)
		r25_operator(groups, 2*PROVEN_MAX, now.Add(time.Second))
		s := r25_survivors(honest)
		t.Logf("SECPOOL proven-quota operator_groups=%d handshakes=%d honest_survivors=%d/%d", groups, 2*PROVEN_MAX, s, len(honest))
		if s != len(honest) {
			t.Fatalf("an operator spread over %d netgroups evicted %d honest proofs", groups, len(honest)-s)
		}
		proven_mu.Lock()
		size := len(proven_map)
		proven_mu.Unlock()
		if size > PROVEN_MAX {
			t.Fatalf("proven set %d > %d", size, PROVEN_MAX)
		}
	}
}

// Loopback and LAN addresses are exempt from the quota (netgroup ""), as in the rest of the inbound guard.
func TestR25ProvenQuotaExemptsNonPublic(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	var lan []string
	for i := 0; i < 3*PROVEN_PER_NETGROUP; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/200, 1+i%200)
		note_proven(ip, now.Add(time.Duration(i)*time.Millisecond))
		lan = append(lan, ip)
	}
	note_proven("127.0.0.1", now)
	if s := r25_survivors(append(lan, "127.0.0.1")); s != len(lan)+1 {
		t.Fatalf("non-public proofs were quota-evicted: %d of %d kept", s, len(lan)+1)
	}
}

// A full netgroup replaces its own oldest proof: the newest handshake of that /16 is always remembered.
func TestR25ProvenQuotaKeepsNewestOfGroup(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	note_proven("198.51.100.1", now.Add(-time.Hour)) // older than every proof below, in another netgroup
	for i := 0; i < PROVEN_PER_NETGROUP+10; i++ {
		note_proven(fmt.Sprintf("203.0.%d.%d", i/200, 1+i%200), now.Add(time.Duration(i)*time.Second))
	}
	last := fmt.Sprintf("203.0.%d.%d", (PROVEN_PER_NETGROUP+9)/200, 1+(PROVEN_PER_NETGROUP+9)%200)
	if !proven_lane_allow(last, now.Add(time.Hour)) {
		t.Fatal("the newest proof of a full netgroup was not kept")
	}
	if proven_lane_allow("203.0.0.1", now.Add(time.Hour)) {
		t.Fatal("the oldest proof of a full netgroup was kept past the quota")
	}
	if !proven_lane_allow("198.51.100.1", now.Add(time.Hour)) {
		t.Fatal("a full netgroup evicted another netgroup's proof")
	}
}

func r25_sync_conn(ip string) *Connection {
	return &Connection{Addr: fake_addr(ip + ":11011"), logger: logr.Discard()}
}

// B47: over one hour a peer that answers every sync fetch with its own error is asked ~900 times at the r24 shadow
// cadence (one round every 4 s); with the hold it is asked once per hold. r25 merge: on the peers B47 hold
// (peer_observe.go sync_failed / sync_held; secpool's sync_unservable.go was folded into it).
func TestR25SyncUnservableAttemptsPerHour(t *testing.T) {
	now := time.Unix(1700000000, 0)
	c := r25_sync_conn("203.0.113.72")
	attempts := 0
	for at := now; at.Before(now.Add(time.Hour)); at = at.Add(4 * time.Second) {
		if c.sync_held(at) {
			continue
		}
		attempts++
		c.sync_failed(call_failure_remote, at)
	}
	t.Logf("SECPOOL sync-unservable attempts_per_hour=%d (no hold: %d)", attempts, 900)
	if attempts > 20 {
		t.Fatalf("%d sync attempts in an hour against an unservable peer", attempts)
	}
}

// B47: trigger_sync never touches a held peer. With chain == nil any candidate that reaches the selection code
// panics into trigger_sync's recover (recovered_panics_total{level="3"}); a held one must not get that far. The
// unheld control proves the probe sees a candidate.
func TestR25TriggerSyncSkipsHeldPeer(t *testing.T) {
	if chain != nil {
		t.Skip("needs the package without a chain")
	}
	ctr := metrics.Set.GetOrCreateCounter(`recovered_panics_total{level="3"}`)
	c := r25_sync_conn("203.0.113.73")
	c.Peer_ID = 0x5ec9001
	c.State.Store(ACTIVE)
	connection_map.Store(Address(c), c)
	defer connection_map.Delete(Address(c))
	before := ctr.Get()
	trigger_sync()
	if ctr.Get() == before {
		t.Fatal("control: an unheld candidate did not reach the selection code; the probe does not work")
	}
	c.obs.sync_hold_until.Store(time.Now().Add(time.Hour).UnixNano()) // r25 merge: the peers B47 field
	before = ctr.Get()
	trigger_sync()
	if ctr.Get() != before {
		t.Fatal("trigger_sync considered a peer held for an unservable sync")
	}
}

// B48 bound, measured: an operator needs about PROVEN_MAX single-address netgroups (real handshakes from ~4,000
// distinct /16s) before honest single-address proofs start to go, and then the OLDEST proofs of the tied size go first.
func TestR25ProvenQuotaAttackBound(t *testing.T) {
	reset_proven(t)
	now := time.Unix(1700000000, 0)
	honest := r25_honest_proofs(100, now)
	r25_operator(PROVEN_MAX, PROVEN_MAX, now.Add(time.Second)) // 4,096 /16s, one handshake each
	s := r25_survivors(honest)
	t.Logf("SECPOOL proven-quota operator_groups=%d handshakes=%d honest_survivors=%d/%d", PROVEN_MAX, PROVEN_MAX, s, len(honest))
	if s != 0 {
		t.Fatalf("at the bound the oldest single-address proofs should go first: %d honest left", s)
	}
}

// B42: a tracked tx that a recent block carries is pooled until HouseKeeping; the rebroadcast loop must forget it
// instead of re-announcing it REBROADCAST_MAX times (base 17da0dc: 4 re-announcements of the mined tx).
func TestR25RebroadcastSkipsMinedTx(t *testing.T) {
	defer reset_announced(0)()
	mined_tx, _ := flow_tx(31)
	pending, _ := flow_tx(32)
	t0 := time.Unix(1700000000, 0)
	track_announced_tx(mined_tx, t0)
	track_announced_tx(pending, t0)
	pool := map[crypto.Hash]bool{mined_tx.GetHash(): true, pending.GetHash(): true} // both still pooled
	mined := map[crypto.Hash]bool{mined_tx.GetHash(): true}
	in := rebroadcast_in_pool(func(h crypto.Hash) bool { return pool[h] }, mined)
	sent := map[crypto.Hash]int{}
	for i := 1; i <= REBROADCAST_MAX+2; i++ {
		for _, tx := range due_announced_txs(t0.Add(time.Duration(i)*REBROADCAST_AFTER), in, 3) {
			sent[tx.GetHash()]++
		}
	}
	t.Logf("SECPOOL rebroadcast mined=%d pending=%d (r24: %d each)", sent[mined_tx.GetHash()], sent[pending.GetHash()], REBROADCAST_MAX)
	if sent[mined_tx.GetHash()] != 0 {
		t.Fatalf("a mined tx was re-announced %d times", sent[mined_tx.GetHash()])
	}
	if sent[pending.GetHash()] != REBROADCAST_MAX {
		t.Fatalf("a pending tx was re-announced %d times, want %d", sent[pending.GetHash()], REBROADCAST_MAX)
	}
	if got := rebroadcast_in_pool(func(crypto.Hash) bool { return true }, nil); !got(mined_tx.GetHash()) {
		t.Fatal("no mined source must keep the r24 predicate")
	}
}

func TestR25DerodSetsP2PMinedSource(t *testing.T) {
	src, err := os.ReadFile("../cmd/derod/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\tp2p.SetMinedSource(derodrpc.RecentlyMined)") {
		t.Fatal("cmd/derod/main.go no longer tells the p2p rebroadcast loop which pooled txs are mined")
	}
}
