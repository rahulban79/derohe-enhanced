package main

import (
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
)

func reset_pair(t testing.TB) {
	t.Cleanup(func() {
		atomic.StoreInt32(&pair_enabled, 0)
		astropair.SuffixSort = nil
		astrobwtv3.SuffixSort = nil
		fast_sorter = dsa.SuffixArray
		atomic.StoreInt32(&fast_sort_disabled, 0)
	})
}

func TestInstallPairSelfTest(t *testing.T) {
	reset_fast_sort(t)
	reset_pair(t)
	install_fast_sort("auto")
	if got := install_pair_hash("off"); atomic.LoadInt32(&pair_enabled) != 0 {
		t.Fatalf("--pair=off enabled pairing: %s", got)
	}
	if got := install_pair_hash("auto"); atomic.LoadInt32(&pair_enabled) != 1 {
		t.Fatalf("a correct pair path was not enabled: %s", got)
	}
	// a sorter that is wrong without knowing it, given to the pair directly (no sampled verification): the
	// self-test must refuse to enable pairing
	astrobwtv3.SuffixSort = broken_sorter
	if got := install_pair_hash("auto"); atomic.LoadInt32(&pair_enabled) != 0 {
		t.Fatalf("a broken pair sorter passed the self-test: %s", got)
	}
	// broken in lane B only (every second sort call): the self-test must check the second hash too
	calls := 0
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		if calls++; calls%2 == 0 {
			return broken_sorter(text, sa)
		}
		return dsa.SuffixArray(text, sa)
	}
	if got := install_pair_hash("auto"); atomic.LoadInt32(&pair_enabled) != 0 {
		t.Fatalf("a lane-B-only broken sorter passed the self-test: %s", got)
	}
}

// TestHashPairPanicFallsBack: a panic inside a pair disables pairing, and both nonces still get their true hashes.
func TestHashPairPanicFallsBack(t *testing.T) {
	reset_fast_sort(t)
	reset_pair(t)
	install_fast_sort("auto")
	install_pair_hash("auto")
	in := selftest_inputs()
	astrobwtv3.SuffixSort = nil
	ra, rb := astrobwtv3.AstroBWTv3(in[0]), astrobwtv3.AstroBWTv3(in[1])
	astrobwtv3.SuffixSort = verified_sort
	astropair.SuffixSort = func(text []byte, sa []int32) bool { panic("injected") }
	s := astropair.NewScratch()
	ha, hb := hash_pair(in[0], in[1], s)
	if ha != ra || hb != rb {
		t.Fatalf("fallback hashes wrong")
	}
	if atomic.LoadInt32(&pair_enabled) != 0 {
		t.Fatal("pairing still enabled after a recovered panic")
	}
}
