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
	"os"
	"strings"
	"testing"
)

// eager is the pre-r23b rule: one height read per block.
func eager_too_far(load func() int64, height int64) bool { return height > load()+4 }

// The gate must give the per-block verdict for every block of a sync stream in which each added block raises the
// chain height (and some blocks are far ahead and skipped), while reading the height far less often.
func TestSyncHeightGateMatchesPerBlockRuleWithFewerReads(t *testing.T) {
	for _, start := range []int64{0, 7821726} {
		chain_h := start
		reads := 0
		load := func() int64 { reads++; return chain_h }
		g := new_sync_height_gate(load)
		eager_reads := 0
		eager_load := func() int64 { eager_reads++; return chain_h }
		blocks := 0
		for i := int64(1); i <= 1000; i++ {
			heights := []int64{start + i}
			if i%97 == 0 {
				heights = append([]int64{start + i + 5, start + i + 40}, heights...) // far-ahead blocks: skipped
			}
			for _, h := range heights {
				blocks++
				want := eager_too_far(eager_load, h)
				if got := g.too_far(h); got != want {
					t.Fatalf("start %d height %d (chain %d): gate %v, per-block rule %v", start, h, chain_h, got, want)
				}
				if !want {
					chain_h = h // the block was added: the chain height rises to it
				}
			}
		}
		if eager_reads != blocks {
			t.Fatalf("per-block rule read %d times for %d blocks", eager_reads, blocks)
		}
		// within the window the remembered height answers; it is reloaded about once per SYNC_AHEAD_BLOCKS+1 blocks
		// and once more for every far-ahead block
		if reads*3 > blocks {
			t.Fatalf("gate read the height %d times for %d blocks (want < 1/3)", reads, blocks)
		}
		t.Logf("start %d: %d blocks, per-block reads %d, gate reads %d", start, blocks, eager_reads, reads)
	}
}

// A block more than SYNC_AHEAD_BLOCKS ahead is skipped on a fresh height, and a later rise lets the same height in.
func TestSyncHeightGateReloadsBeforeSkipping(t *testing.T) {
	chain_h := int64(100)
	reads := 0
	g := new_sync_height_gate(func() int64 { reads++; return chain_h })
	if g.too_far(104) || reads != 1 {
		t.Fatalf("104 at chain 100 must be within the window with one read (reads %d)", reads)
	}
	if !g.too_far(105) {
		t.Fatalf("105 at chain 100 must be too far")
	}
	if reads != 2 {
		t.Fatalf("a too-far verdict must come from a fresh read (reads %d)", reads)
	}
	chain_h = 103 // the chain moved on behind the gate's back
	if g.too_far(105) {
		t.Fatalf("105 at chain 103 must be within the window (stale height used)")
	}
	if reads != 3 {
		t.Fatalf("reads %d, want 3", reads)
	}
	if g.too_far(106) || reads != 3 {
		t.Fatalf("106 at remembered 103 is within the window without a read (reads %d)", reads)
	}
}

// The sync path must ask the gate, not read the height per block (static: the loop needs a live chain to run).
func TestSyncPathUsesHeightGate(t *testing.T) {
	src, err := os.ReadFile("chain_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "if syncing && ahead.too_far(int64(bl.Height)) {") {
		t.Fatalf("process_object_response_want no longer consults the sync height gate")
	}
	if strings.Contains(s, "chain.Get_Height()+4") {
		t.Fatalf("a per-block chain.Get_Height()+4 read is back in chain_sync.go")
	}
}
