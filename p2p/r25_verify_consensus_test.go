// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r25 (verify-consensus): tests for the two fixes the adversarial verifier made to consensus_obs_r25.go.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/go-logr/logr"
)

// A slow topo-index read inside settle must not block note(): note runs on the p2p add path before the block is
// relayed. Forged input: main_at blocks until released; note() of a new block must still return at once.
func TestR25AltSettleReadsOutsideLock(t *testing.T) {
	a := new_alt_tracker()
	id := func(s string) crypto.Hash { return crypto.Keccak256([]byte(s)) }
	a.note(id("main1"), 1)
	a.note(id("side1"), 1)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	slow := func(h int64) []crypto.Hash {
		entered <- struct{}{}
		<-release
		return []crypto.Hash{id("main1")}
	}
	done := make(chan Alt_Stats, 1)
	go func() { done <- a.settle(1+config.STABLE_LIMIT+1, slow) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("settle never read the topo index")
	}
	noted := make(chan struct{})
	go func() { a.note(id("new"), 2+config.STABLE_LIMIT); close(noted) }()
	select {
	case <-noted:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("note() blocked behind a topo-index read in settle (the p2p relay path would stall)")
	}
	close(release)
	var st Alt_Stats
	select {
	case st = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("settle did not finish")
	}
	if st.Count != 1 || st.Settled != 2 || st.Unsettled != 1 || st.Tracked != 3 || len(st.Blocks) != 1 || st.Blocks[0].Hash != id("side1").String() {
		t.Fatalf("verdicts %+v", st)
	}
	// a second settle (a concurrent one that lost the race looks the same) never counts an entry twice
	st = a.settle(1+config.STABLE_LIMIT+1, func(int64) []crypto.Hash { return nil })
	if st.Count != 1 || st.Settled != 2 {
		t.Fatalf("re-settle counted twice %+v", st)
	}
}

// Two settles that both picked the same due entries (forced: each blocks in its first topo read until both are
// there) judge each entry once (run with -race too).
func TestR25AltSettleConcurrentOnce(t *testing.T) {
	a := new_alt_tracker()
	for i := 0; i < 3; i++ {
		a.note(crypto.Keccak256([]byte(fmt.Sprint("b", i))), 1)
	}
	entered, gate := make(chan struct{}, 64), make(chan struct{})
	slow := func(int64) []crypto.Hash {
		entered <- struct{}{}
		<-gate
		return nil
	}
	res := make(chan Alt_Stats, 2)
	for k := 0; k < 2; k++ {
		go func() { res <- a.settle(100, slow) }()
	}
	for k := 0; k < 2; k++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("settles never reached the topo read")
		}
	}
	close(gate)
	<-res
	<-res
	st := a.settle(100, func(int64) []crypto.Hash { return nil })
	if st.Count != 3 || st.Settled != 3 || st.Unsettled != 0 || len(st.Blocks) != 3 {
		t.Fatalf("concurrent settles double-counted: %+v", st)
	}
}

// advance_block and previous_block are routine skips (file log, V(1)) like past_missing; a rule refusal stays at V(0).
func TestR25RoutineRejectionsStayOffConsole(t *testing.T) {
	r25_reset(t)
	s := &r25_sink{}
	logger = logr.New(s)
	c := &Connection{Peer_ID: 0x55}
	cbl := &block.Complete_Block{Bl: &block.Block{Height: 9, Timestamp: 2}}
	note_block_result(c, cbl, errors.New("advance Block"), false)
	note_block_result(c, cbl, errors.New("previous Block"), false)
	note_block_result(c, cbl, errors.New("Registration TX has not solved PoW"), false) // "other": a rule refusal
	lines := s.find("Block rejected")
	if len(lines) != 3 {
		t.Fatalf("lines %+v", lines)
	}
	want := map[string]int{"advance_block": 1, "previous_block": 1, "other": 0}
	for _, l := range lines {
		r := fmt.Sprint(l.kv["reason"])
		if lv, ok := want[r]; !ok || l.level != lv {
			t.Fatalf("reason %s logged at V(%d), want V(%d)", r, l.level, want[r])
		}
	}
	m, total := block_rejected.snapshot()
	if total != 3 || m["advance_block"] != 1 || m["previous_block"] != 1 || m["other"] != 1 {
		t.Fatalf("counters %v", m)
	}
}
