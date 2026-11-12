package main

// The descriptor suffix sort (cmd/dero-miner/dsa, third-party MIT code, see THIRD_PARTY_NOTICES.md) replaces the built-in
// SA-IS — 77% of a hash on this machine's profile — through astrobwtv3.SuffixSort. A suffix array is unique, so a
// correct sorter gives the identical hash; three independent guards make an incorrect one harmless:
//
//   1. startup self-test: every corpus input must hash identically with and without it, or it is never installed;
//   2. sampled verification: one sorted text in FAST_SORT_CHECK_EVERY is checked to BE the suffix array
//      (permutation + strictly increasing adjacent suffixes, dsa.Verify); a failure disables the fast path;
//   3. recovered panics: AstroBWTv3 recovers a panic by returning a random failing hash; any new one disables it.
//
// Disabling falls back to the built-in sort for every later hash: work continues, only slower.

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
	"github.com/deroproject/derohe/cmd/dero-miner/dsac"
)

const FAST_SORT_CHECK_EVERY = 1024 // Verify costs ~1.6x a sort: 1/256 cost 0.52% of hashrate, 1/1024 0.13%

var fast_sort_disabled int32
var fast_sort_calls, fast_sort_checked, fast_sort_fallbacks uint64
var fast_sort_reason atomic.Value

// fast_sorter_overridden lets tests keep a substituted sorter across install_fast_sort
var fast_sorter_overridden bool

// fast_sorter is the sorter under guard; tests substitute a broken one to prove each guard catches it
var fast_sorter = default_sorter()

// native_sort is descriptor.c (cmd/dero-miner/dsac, darwin/arm64 cgo build): the same algorithm as the Go
// port, measured +22.5% per whole hash (Round 16, contended, 8 interleaved pairs). A C decline (any non-zero rc)
// falls through to the Go port, and a Go decline to SA-IS, so the chain can only lose speed, never correctness.
func native_sort(text []byte, sa []int32) bool {
	return dsac.SuffixArray(text, sa) || dsa.SuffixArray(text, sa)
}

func default_sorter() func([]byte, []int32) bool {
	if dsac.Available {
		return native_sort
	}
	return dsa.SuffixArray
}

// sorter_for maps --sort to the sorter under guard: auto/native = C when compiled in (else Go), descriptor/go = Go.
func sorter_for(mode string) (func([]byte, []int32) bool, string) {
	switch mode {
	case "descriptor", "go":
		return dsa.SuffixArray, "Go"
	default:
		if dsac.Available {
			return native_sort, "native C"
		}
		return dsa.SuffixArray, "Go"
	}
}

func verified_sort(text []byte, sa []int32) bool {
	if atomic.LoadInt32(&fast_sort_disabled) == 1 {
		return false
	}
	if !fast_sorter(text, sa) {
		atomic.AddUint64(&fast_sort_fallbacks, 1)
		return false
	}
	if atomic.AddUint64(&fast_sort_calls, 1)%FAST_SORT_CHECK_EVERY == 0 {
		atomic.AddUint64(&fast_sort_checked, 1)
		if !dsa.Verify(text, sa) {
			disable_fast_sort("a sampled suffix array failed verification")
			return false // this hash falls back to SA-IS, so it is still correct
		}
	}
	return true
}

func disable_fast_sort(why string) {
	if atomic.CompareAndSwapInt32(&fast_sort_disabled, 0, 1) {
		fast_sort_reason.Store(why)
		logger.Error(fmt.Errorf("%s", why), "descriptor sort DISABLED, falling back to the built-in SA-IS")
	}
}

// self-test inputs: a fixed vector recipe plus edge nonces, hashed with OUR consensus code
func selftest_inputs() [][]byte {
	var in [][]byte
	for i := 0; i < 48; i++ {
		var b [48]byte
		b[0] = 1
		for k := 8; k <= 42; k++ {
			b[k] = byte(k*7 + 11)
		}
		b[43], b[44], b[45] = byte(i), byte(i>>8), byte(i>>16)
		in = append(in, b[:])
	}
	for _, v := range []byte{0x00, 0xff, 0x55} {
		b := make([]byte, 48)
		for i := range b {
			b[i] = v
		}
		in = append(in, b)
	}
	return in
}

// apply_merge_variant (r30 rft §8 L-C2): DERO_DSA_MERGE=bf selects the native sort's branch-free two-list merge
// (bit-exact, TestR30MergeVariantBitExact); unset or "r29" keeps the r29 merge. Default OFF: its gain is claimed only
// after the quiet-window ABBA (harness/pipeline/quiet_window.py step b237-abba). Called before install_fast_sort so
// the self-test runs on the variant that mines. Returns the label the 'suffix sort' line carries as "merge".
func apply_merge_variant(getenv func(string) string) string {
	switch v := getenv("DERO_DSA_MERGE"); v {
	case "", "r29":
		dsac.SetMergeVariant(0)
		return "r29"
	case "bf":
		if !dsac.Available {
			return "r29 (DERO_DSA_MERGE=bf ignored: no native sort in this build)"
		}
		dsac.SetMergeVariant(1)
		return "bf (r30 L-C2, unmeasured: pending the quiet-window ABBA)"
	default:
		dsac.SetMergeVariant(0)
		return fmt.Sprintf("r29 (DERO_DSA_MERGE=%q ignored: want bf or r29)", v)
	}
}

// install_fast_sort decides the sorter for this run; it returns a label for the logs.
func install_fast_sort(mode string) string {
	if mode == "sais" {
		return "built-in SA-IS (--sort=sais)"
	}
	impl := "test"
	if !fast_sorter_overridden {
		fast_sorter, impl = sorter_for(mode)
	}
	before := atomic.LoadUint64(&astrobwtv3.RecoveredPanics)
	for i, in := range selftest_inputs() {
		astrobwtv3.SuffixSort = nil
		ref := astrobwtv3.AstroBWTv3(in)
		var checked bool
		astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
			ok := fast_sorter(text, sa)
			if ok && !dsa.Verify(text, sa) { // the self-test verifies EVERY array, not a sample
				ok = false
			} else if ok {
				checked = true
			}
			return ok
		}
		got := astrobwtv3.AstroBWTv3(in)
		astrobwtv3.SuffixSort = nil
		if got != ref || !checked {
			logger.Error(nil, "descriptor sort self-test FAILED; mining with the built-in SA-IS", "input", i)
			return "built-in SA-IS (descriptor self-test failed)"
		}
	}
	if atomic.LoadUint64(&astrobwtv3.RecoveredPanics) != before {
		logger.Error(nil, "descriptor sort self-test caused a recovered panic; mining with the built-in SA-IS")
		return "built-in SA-IS (descriptor self-test panicked)"
	}
	astrobwtv3.SuffixSort = verified_sort
	go watch_recovered_panics(before)
	return fmt.Sprintf("descriptor sort, %s (self-test passed on %d inputs; 1 in %d verified while mining)", impl, len(selftest_inputs()), FAST_SORT_CHECK_EVERY)
}

func watch_recovered_panics(base uint64) {
	// time.Tick here leaked its ticker once this returns: go.mod's go 1.17 keeps GODEBUG asynctimerchan=1, so the
	// Go 1.23 rule that collects unreferenced tickers does not apply and the runtime timer fired forever
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if atomic.LoadUint64(&astrobwtv3.RecoveredPanics) != base {
			disable_fast_sort("AstroBWTv3 recovered a panic (a hash was falsified)")
			return
		}
	}
}

func fast_sort_status() string {
	if astrobwtv3.SuffixSort == nil {
		return "sort=SA-IS"
	}
	if atomic.LoadInt32(&fast_sort_disabled) == 1 {
		r, _ := fast_sort_reason.Load().(string)
		return "sort=SA-IS (descriptor disabled: " + r + ")"
	}
	return fmt.Sprintf("sort=descriptor verified=%d fallbacks=%d", atomic.LoadUint64(&fast_sort_checked), atomic.LoadUint64(&fast_sort_fallbacks))
}
