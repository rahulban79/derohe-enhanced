package p2p

// r28d (rft §7 B177; first seen upstream in DEROFDN community-dev commit 8ef3fb1d): a Chain response must never carry a zero block id. When a topo index cannot be
// read the list stops there, so every id sent is a real block and position i still means topoheight start+i.

import (
	"fmt"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func r28d_ids(n int64, bad int64) (func() int64, func(int64) (crypto.Hash, error)) {
	tip := func() int64 { return n - 1 }
	at := func(i int64) (h crypto.Hash, err error) {
		if i == bad {
			return h, fmt.Errorf("cannot read topo record at index %d", i)
		}
		h[0], h[1], h[31] = byte(i), byte(i>>8), 0x5a
		return h, nil
	}
	return tip, at
}

func TestR28dChainBlockListNoZeroHash(t *testing.T) {
	var zero [32]byte
	tip, at := r28d_ids(100, 40)
	list := chain_block_list(nil, 10, tip, at, 512)
	for i, h := range list {
		if h == zero {
			t.Fatalf("position %d (topo %d) carries a zero block id", i, 10+i)
		}
		want, _ := at(int64(10 + i))
		if h != [32]byte(want) {
			t.Fatalf("position %d is not topo %d", i, 10+i)
		}
	}
	if len(list) != 30 {
		t.Fatalf("list has %d ids, want the 30 readable ones before the unreadable index 40", len(list))
	}
}

func TestR28dChainBlockListUnchangedWithoutErrors(t *testing.T) {
	tip, at := r28d_ids(2000, -1)
	if got := len(chain_block_list(nil, 0, tip, at, 512)); got != 513 { // the inline loop's bound: len <= MAX_BLOCKS
		t.Fatalf("got %d ids, want 513 (unchanged MAX_BLOCKS bound)", got)
	}
	if got := len(chain_block_list(nil, 1990, tip, at, 512)); got != 10 {
		t.Fatalf("got %d ids from 1990, want 10 (stops at the tip)", got)
	}
}
