package main

import (
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/dsac"
)

// Round 30 (rft §7 B239, memory control): the split mode's CPU sort path makes no Go heap allocation per hash. A
// mining thread sorts ~5,400 texts a second; one allocation each is ~5,400 objects/s/thread for the GC to trace
// (live r29: 16 STW pauses in ~15 min, heap 63.8 MB, harness/runtime/r30_objective_read_20261108.txt), so any change
// that adds one shows up here first. The C sort's scratch is one __thread arena per OS thread (descriptor.c header),
// which is malloc'd once, outside the Go heap, and not counted.
func TestR30SplitSortPathZeroAlloc(t *testing.T) {
	if !dsac.Available {
		t.Skip("the native descriptor sort is built only for darwin/arm64 with cgo")
	}
	oldPair, oldFast := astropair.SuffixSort, fast_sorter
	t.Cleanup(func() { astropair.SuffixSort, fast_sorter = oldPair, oldFast })
	fast_sorter = dsac.SuffixArray
	astropair.SuffixSort = verified_sort // the live binding (gpu_split.go / pairhash.go)
	s := astropair.NewScratch()
	var in [48]byte
	in[0] = 1
	dst := make([]byte, astrobwtv3.MAX_LENGTH+64)
	n := astropair.Stage1Text(in[:], dst, s)
	text := dst[:n]
	in[44] = 7
	dst2 := make([]byte, astrobwtv3.MAX_LENGTH+64)
	text2 := dst2[:astropair.Stage1Text(in[:], dst2, s)]
	sa := make([]int32, astrobwtv3.MAX_LENGTH+1)
	if !astropair.SortOnly(text, sa) { // warm: the C arena for this thread
		t.Fatal("the descriptor sort declined a real stage-1 text")
	}
	if a := testing.AllocsPerRun(200, func() { astropair.SortOnly(text, sa) }); a != 0 {
		t.Fatalf("SortOnly (GPU-SHA split path) allocates %.2f objects per hash, want 0", a)
	}
	if a := testing.AllocsPerRun(200, func() { astropair.SortSum2(text, text2, s) }); a != 0 {
		t.Fatalf("SortSum2 (CPU-SHA split path) allocates %.2f objects per pair, want 0", a)
	}
}
