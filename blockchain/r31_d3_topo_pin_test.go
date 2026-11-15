package blockchain

// r31 dimension 3 (DF-error-paths-08099dc668 / 198eb9bc91 / 9fa4007162 / de87aa300b, triaged): storetopo.go discards
// the error of Read in binarySearchHeight and LocatePruneTopo. This file is consensus-visible (Is_Block_Topological_order
// decides "already in chain" in Add_Complete_Block), so the code is NOT changed (consensus guard S1); this test PINS
// today's behaviour: the searches read one index past the last record (endIndex = Count, high = count), that Read fails
// and its zero record steers the search the right way, so the newest height and the prune point are still found.

import (
	"testing"
)

func r31_topo(t *testing.T, n int64, pruned_below int64) *storetopofs {
	t.Helper()
	s := &storetopofs{}
	if err := s.Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.topomapping.Close() })
	for i := int64(0); i < n; i++ {
		var blid [32]byte
		blid[0], blid[1] = byte(i), byte(i>>8)
		sv := uint64(1)
		if i >= pruned_below {
			sv = uint64(2 + i)
		}
		if err := s.Write(i, blid, sv, i); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestR31TopoSearchPinsDiscardedReads(t *testing.T) {
	s := r31_topo(t, 300, 0)
	if _, err := s.Read(s.Count()); err == nil {
		t.Fatal("a Read one past the last record must fail (the discarded error this test pins)")
	}
	for _, h := range []int64{0, 1, 150, 298, 299} {
		blids, topos := s.binarySearchHeight(h)
		if len(blids) != 1 || len(topos) != 1 || topos[0] != h || blids[0][0] != byte(h) {
			t.Fatalf("height %d: blids %d topos %v", h, len(blids), topos)
		}
	}
	if blids, _ := s.binarySearchHeight(5000); len(blids) != 0 {
		t.Fatal("a height above the chain has no block")
	}

	old := pruned_till
	defer func() { pruned_till = old }()
	pruned_till = -1
	p := r31_topo(t, 300, 120) // topos 0..119 share state version 1 (pruned history), the rest rise from 122
	if got := p.LocatePruneTopo(); got != 119 {
		t.Fatalf("prune topo %d, want 119", got)
	}
}
