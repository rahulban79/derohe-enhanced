package main

import (
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

// The split bench must time a CORRECT sort: the SHA-256 of the suffix array it leaves behind equals the consensus
// FinishHashFromData of the same stage-1 text, and with a working sorter nothing is declined.
func TestSplitBenchSortsCorrectly(t *testing.T) {
	reset_fast_sort(t)
	old := astropair.SuffixSort
	t.Cleanup(func() { astropair.SuffixSort = old })
	install_fast_sort("auto")
	if astrobwtv3.SuffixSort == nil {
		t.Skip("no descriptor sort on this build")
	}
	var in [48]byte
	for i := range in {
		in[i] = byte(7*i + 3)
	}
	texts := split_bench_texts_of(in, 6)
	astropair.SuffixSort = astrobwtv3.SuffixSort
	sa := make([]int32, gsplit.MaxText+1)
	for i, text := range texts {
		if len(text) < 1 || len(text) > gsplit.MaxText {
			t.Fatalf("text %d length %d outside 1..%d", i, len(text), gsplit.MaxText)
		}
		if d := split_sort_texts(texts[i:i+1], 1, sa, func(int) {}); d != 0 {
			t.Fatalf("text %d: a working sorter declined", i)
		}
		got := sha256.Sum256(unsafe.Slice((*byte)(unsafe.Pointer(&sa[0])), 4*len(text)))
		hook := astrobwtv3.SuffixSort
		astrobwtv3.SuffixSort = nil // the consensus path, as derod computes it
		want := astrobwtv3.FinishHashFromData(text, uint32(len(text)))
		astrobwtv3.SuffixSort = hook
		if got != want {
			t.Fatalf("text %d: split bench sort hash %x != consensus %x", i, got[:8], want[:8])
		}
		// and the text is the WHOLE stage-1 text of input i: its hash is the consensus AstroBWTv3 of that input
		blob, want_blob := split_bench_blob(in, i), in
		binary.BigEndian.PutUint32(want_blob[39:43], uint32(i))
		if blob != want_blob {
			t.Fatalf("split_bench_blob(%d) is not the seed with nonce %d", i, i)
		}
		astrobwtv3.SuffixSort = nil
		full := astrobwtv3.AstroBWTv3(blob[:])
		astrobwtv3.SuffixSort = hook
		if full != want {
			t.Fatalf("text %d is not the stage-1 text of its input (%x != %x)", i, want[:8], full[:8])
		}
	}
}

// A declined sort is finished on the CPU (like gsplit's cpuFinish), so the bench is charged for it, and counted.
func TestSplitBenchChargesDeclinedSorts(t *testing.T) {
	old := astropair.SuffixSort
	t.Cleanup(func() { astropair.SuffixSort = old })
	astropair.SuffixSort = nil // every SortOnly declines
	_, texts := split_bench_inputs(3)
	var finished []int
	sa := make([]int32, gsplit.MaxText+1)
	if d := split_sort_texts(texts, 7, sa, func(k int) { finished = append(finished, k) }); d != 7 || len(finished) != 7 {
		t.Fatalf("declined %d finished %d, want 7 and 7", d, len(finished))
	}
	for i, k := range finished { // each declined text is charged as ITS input (cpuFinish hashes the 48-byte blob)
		if k != i%3 {
			t.Fatalf("declined sort %d charged as input %d, want %d", i, k, i%3)
		}
	}
}

// H2: --bench --gpu-mode=split dispatches to split_bench, nothing else does
func TestSplitBenchDispatch(t *testing.T) {
	if !split_bench_requested(map[string]interface{}{"--gpu-mode": "split"}) {
		t.Fatal("--gpu-mode=split did not select the split bench")
	}
	for _, m := range []interface{}{nil, "full", ""} {
		if split_bench_requested(map[string]interface{}{"--gpu-mode": m}) {
			t.Fatalf("--gpu-mode=%v selected the split bench", m)
		}
	}
}

// Without paired hashing split mode cannot run (start_gpu_split refuses), so the bench must refuse too rather than
// print a number for a mode the miner would never use.
func TestSplitBenchNeedsPairedHashing(t *testing.T) {
	prev := atomic.LoadInt32(&pair_enabled)
	t.Cleanup(func() { atomic.StoreInt32(&pair_enabled, prev) })
	atomic.StoreInt32(&pair_enabled, 0)
	if split_bench(1, 1) {
		t.Fatal("split bench ran without paired hashing")
	}
}
