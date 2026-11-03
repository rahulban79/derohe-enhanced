package main

// Paired hashing (cmd/dero-miner/astropair): each CPU mining thread hashes two consecutive nonces per iteration so the
// two final SHA-256 passes run interleaved on the core's SHA unit. Same guards as the descriptor sort:
//
//   1. startup self-test: every pair of corpus inputs must hash identically to astrobwtv3.AstroBWTv3 with the
//      built-in sort, or pairing is never enabled;
//   2. both lanes sort through verified_sort, so the sampled suffix-array check and its kill switch still apply;
//   3. a panic inside a pair produces no hash (astropair.Hash2 returns ok=false); the thread re-hashes both nonces
//      with astrobwtv3.AstroBWTv3 and pairing is disabled for the rest of the run.

import (
	"fmt"
	"sync/atomic"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

var pair_enabled int32 // 1 while mineblock may use astropair.Hash2
var pair_reason atomic.Value

// install_pair_hash runs after install_fast_sort and returns a label for the logs.
func install_pair_hash(mode string) string {
	atomic.StoreInt32(&pair_enabled, 0)
	if mode == "off" {
		return "off (--pair=off)"
	}
	if !astropair.HasAsm {
		return "off (no SHA-256 instructions on this CPU)"
	}
	astropair.SuffixSort = astrobwtv3.SuffixSort // the guarded descriptor sort, or nil = built-in SA-IS per lane

	hook := astrobwtv3.SuffixSort
	astrobwtv3.SuffixSort = nil // reference hashes use the consensus code path exactly as derod does
	in := selftest_inputs()
	ref := make([][32]byte, len(in))
	for i := range in {
		ref[i] = astrobwtv3.AstroBWTv3(in[i])
	}
	astrobwtv3.SuffixSort = hook

	s := astropair.NewScratch()
	before := atomic.LoadUint64(&astropair.RecoveredPanics)
	for i := range in {
		j := (i + 1) % len(in) // neighbours, wrapping so the last input is paired with the first
		ha, hb, ok := astropair.Hash2(in[i], in[j], s)
		if !ok || ha != ref[i] || hb != ref[j] {
			logger.Error(nil, "paired-hash self-test FAILED; hashing one nonce at a time", "pair", fmt.Sprintf("%d,%d", i, j), "ok", ok)
			return "off (self-test failed)"
		}
	}
	if atomic.LoadUint64(&astropair.RecoveredPanics) != before {
		return "off (self-test panicked)"
	}
	atomic.StoreInt32(&pair_enabled, 1)
	return fmt.Sprintf("on (self-test passed on %d pairs)", len(in))
}

func disable_pair_hash(why string) {
	if atomic.CompareAndSwapInt32(&pair_enabled, 1, 0) {
		pair_reason.Store(why)
		logger.Error(fmt.Errorf("%s", why), "paired hashing DISABLED, hashing one nonce at a time")
	}
}

// hash_pair returns the PoW hashes of a and b: paired when enabled, else (or after a recovered panic) one at a time.
func hash_pair(a, b []byte, s *astropair.Scratch) (ha, hb [32]byte) {
	if atomic.LoadInt32(&pair_enabled) == 1 {
		var ok bool
		if ha, hb, ok = astropair.Hash2(a, b, s); ok {
			return ha, hb
		}
		disable_pair_hash("astropair.Hash2 recovered a panic; the pair was re-hashed singly")
	}
	return astrobwtv3.AstroBWTv3(a), astrobwtv3.AstroBWTv3(b)
}

func pair_status() string {
	if atomic.LoadInt32(&pair_enabled) == 1 {
		return "pair=on"
	}
	if r, _ := pair_reason.Load().(string); r != "" {
		return "pair=off (" + r + ")"
	}
	return "pair=off"
}
