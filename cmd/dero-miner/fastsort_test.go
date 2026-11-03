package main

import (
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

// broken_sorter returns a valid permutation in the wrong order and claims success: the worst case, a sorter that
// is wrong without knowing it
func broken_sorter(text []byte, sa []int32) bool {
	for i := range sa {
		sa[i] = int32(len(sa) - 1 - i)
	}
	return len(sa) > 1
}

func reset_fast_sort(t testing.TB) {
	t.Cleanup(func() {
		astrobwtv3.SuffixSort = nil
		fast_sorter = default_sorter()
		fast_sorter_overridden = false
		atomic.StoreInt32(&fast_sort_disabled, 0)
		atomic.StoreUint64(&fast_sort_calls, 0)
	})
}

func TestInstallFastSortSelfTest(t *testing.T) {
	reset_fast_sort(t)
	if got := install_fast_sort("sais"); astrobwtv3.SuffixSort != nil {
		t.Fatalf("--sort=sais installed a hook (%s)", got)
	}
	got := install_fast_sort("auto")
	if astrobwtv3.SuffixSort == nil {
		t.Fatalf("a correct descriptor sort was not installed: %s", got)
	}
	astrobwtv3.SuffixSort = nil
	fast_sorter = broken_sorter
	fast_sorter_overridden = true
	if got := install_fast_sort("auto"); astrobwtv3.SuffixSort != nil {
		t.Fatalf("a broken sorter passed the self-test: %s", got)
	}
}

func TestVerifiedSortDisablesBrokenSorter(t *testing.T) {
	reset_fast_sort(t)
	fast_sorter = broken_sorter
	astrobwtv3.SuffixSort = verified_sort
	in := selftest_inputs()
	astrobwtv3.SuffixSort = nil
	var refs [][32]byte
	for _, b := range in {
		refs = append(refs, astrobwtv3.AstroBWTv3(b))
	}
	astrobwtv3.SuffixSort = verified_sort
	for i := 0; i < 2*FAST_SORT_CHECK_EVERY && atomic.LoadInt32(&fast_sort_disabled) == 0; i++ {
		astrobwtv3.AstroBWTv3(in[i%len(in)])
	}
	if atomic.LoadInt32(&fast_sort_disabled) != 1 {
		t.Fatalf("sampled verification never disabled a broken sorter")
	}
	for i, b := range in { // once disabled every hash is the reference hash again
		if astrobwtv3.AstroBWTv3(b) != refs[i] {
			t.Fatalf("input %d: hash differs after the fast path was disabled", i)
		}
	}
}

func TestSorterForModes(t *testing.T) {
	reset_fast_sort(t)
	for _, m := range []string{"auto", "native", "go", "descriptor"} {
		got := install_fast_sort(m)
		if astrobwtv3.SuffixSort == nil {
			t.Fatalf("--sort=%s: no sorter installed (%s)", m, got)
		}
		astrobwtv3.SuffixSort = nil
		t.Logf("--sort=%s: %s", m, got)
	}
}
