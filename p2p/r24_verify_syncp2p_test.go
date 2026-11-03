// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r24 (verify-syncp2p): adversarial counter-tests for the syncp2p patch.

import (
	goreflect "reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// upstream_locator is the 04ceb55 sync_chain locator loop verbatim except that a read error panics (upstream spun).
func upstream_locator(start_point int64, read func(int64) (blockchain.TopoRecord, error)) (ids [][32]byte, heights []int64) {
	for i := int64(0); i < start_point; {
		tr, err := read(start_point - i)
		if err != nil {
			panic("upstream would spin here")
		}
		if tr.IsClean() {
			break
		}
		ids = append(ids, tr.BLOCK_ID)
		heights = append(heights, start_point-i)
		switch {
		case len(ids) < 20:
			i++
		case len(ids) < 40:
			i += 5
		case len(ids) < 60:
			i += 50
		case len(ids) < 80:
			i += 500
		default:
			i = i * 2
		}
	}
	return
}

// r24 verify: on every healthy store (no read error) the wire locator is identical to upstream, including stores
// with a clean (pruned) record somewhere below the top.
func TestR24VerifyLocatorIdenticalToUpstream(t *testing.T) {
	for _, top := range []int64{0, 1, 2, 19, 20, 21, 39, 40, 59, 60, 79, 80, 81, 100, 999, 1000, 1001, 4096, 123457, 7845944} {
		for _, clean := range []int64{-1, 0, 1, top / 2, top - 1, top - 25, top - 600} {
			read := func(i int64) (blockchain.TopoRecord, error) {
				var r blockchain.TopoRecord
				if i <= clean {
					return r, nil // clean record
				}
				r.BLOCK_ID[0], r.BLOCK_ID[1], r.BLOCK_ID[2], r.State_Version = byte(i), byte(i>>8), byte(i>>16), uint64(i)
				return r, nil
			}
			a, ah := chain_locator(top, read)
			b, bh := upstream_locator(top, read)
			if !goreflect.DeepEqual(a, b) || !goreflect.DeepEqual(ah, bh) {
				t.Fatalf("top=%d clean=%d: locator differs from upstream (%d vs %d entries)", top, clean, len(a), len(b))
			}
		}
	}
}

// r24 verify: an overlap whose prewarm panicked never claims coverage, so the loop prewarms the block itself.
func TestR24VerifyPanickedOverlapNotCovered(t *testing.T) {
	var blid crypto.Hash
	blid[0] = 7
	o := start_prewarm_overlap(func() bool { return true }, func() int { panic("verify blew up") })
	o.blid = blid
	o.finish()
	if o.covered(blid) {
		t.Fatal("a panicked prewarm must not count as covered")
	}
	o2 := start_prewarm_overlap(func() bool { return true }, func() int { return PREWARM_MINIBLOCKS - 1 })
	o2.blid = blid
	o2.finish()
	if o2.covered(blid) {
		t.Fatal("a partial prewarm must not count as covered")
	}
}

// r24 verify: with a shape that changes between batches and peek hammered from process, every id is processed once,
// in order, and peek only ever shows the first id of the response processed next.
func TestR24VerifyPeekWithShapeChanges(t *testing.T) {
	ids := ids_n(57)
	var calls int32
	shape := func() (int, int) {
		c := atomic.AddInt32(&calls, 1)
		if c%3 == 0 {
			return 1, 1
		}
		return 4, 3
	}
	fetch := func(b []crypto.Hash) (o Objects, err error) {
		if b[0][0]%5 == 0 {
			time.Sleep(2 * time.Millisecond)
		}
		for _, id := range b {
			o.CBlocks = append(o.CBlocks, Complete_Block{Block: append([]byte{}, id[:2]...)})
		}
		return
	}
	var got [][]byte
	var want_next []byte
	n, err := fetch_pipelined_peek(ids, shape, fetch, func(o Objects, peek func() []byte) error {
		if want_next != nil && string(o.CBlocks[0].Block) != string(want_next) {
			t.Fatalf("peek showed %v but the next response starts with %v", want_next, o.CBlocks[0].Block)
		}
		want_next = nil
		for _, b := range o.CBlocks {
			got = append(got, b.Block)
		}
		for k := 0; k < 3; k++ {
			if p := peek(); p != nil {
				if want_next != nil && string(p) != string(want_next) {
					t.Fatal("peek changed its answer")
				}
				want_next = append([]byte{}, p...)
			}
			time.Sleep(time.Millisecond)
		}
		return nil
	})
	if err != nil || n != len(ids) || len(got) != len(ids) {
		t.Fatalf("n=%d got=%d err=%v", n, len(got), err)
	}
	for i := range ids {
		if got[i][0] != ids[i][0] || got[i][1] != ids[i][1] {
			t.Fatalf("order changed at %d", i)
		}
	}
}
