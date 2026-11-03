package main

// MLP (memory-level parallelism) probe — throwaway.
// Question: on ONE M1 P-core, does the SAIS-like dependent-load pattern leave load
// bandwidth unused? If K independent dependent-chains run much faster in aggregate
// than 1 chain, the core has idle MLP -> interleaving N hashes per core (intra-thread
// ILP) could raise per-core hashrate. If K-way ~= 1-way, the core already saturates.
import (
	"fmt"
	"runtime"
	"time"
)

const N = 1 << 16 // 65536 int32 = 256KB, ~ the SAIS working set
const ITERS = 200_000_000

func makeArr() []int32 {
	a := make([]int32, N)
	// pseudo-random permutation-ish so each load address depends on the previous value
	x := uint32(12345)
	for i := range a {
		x = x*1664525 + 1013904223
		a[i] = int32(x & (N - 1))
	}
	return a
}

// k independent dependent-load chains, interleaved in the loop body.
func chains(a []int32, k int) float64 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	idx := make([]int32, k)
	for i := range idx {
		idx[i] = int32((i * 7919) & (N - 1))
	}
	perChain := ITERS / k
	start := time.Now()
	for step := 0; step < perChain; step++ {
		for c := 0; c < k; c++ {
			idx[c] = a[idx[c]]
		}
	}
	el := time.Since(start).Seconds()
	var sink int32
	for _, v := range idx {
		sink += v
	}
	_ = sink
	totalLoads := float64(perChain) * float64(k)
	return totalLoads / el / 1e6 // Mloads/sec
}

func main() {
	a := makeArr()
	fmt.Printf("MLP probe: %d int32 (%.0f KB) working set, dependent gather chains\n", N, float64(N*4)/1024)
	chains(a, 1) // warmup
	fmt.Printf("%6s %16s %14s\n", "k-way", "Mloads/sec", "speedup")
	base := 0.0
	for _, k := range []int{1, 2, 3, 4, 6, 8, 12, 16} {
		r := chains(a, k)
		if k == 1 {
			base = r
		}
		fmt.Printf("%6d %16.1f %13.2fx\n", k, r, r/base)
	}
}
