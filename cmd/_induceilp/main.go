package main

// Faithful PoC (throwaway): does interleaving K independent lanes of the REAL
// induceL_8_32 access pattern (sais.go:822-853) capture the idle MLP?
// Body mirrors the real loop: seq read sa[i]; data-dependent random reads text[k],
// text[k-1]; carried bucket pointer b; data-dependent random write sa[b]; branch.
// 1-way vs K-way interleaved, measured on real-sized state. Decides go/no-go on the
// heroic bit-identical K-way SAIS rewrite BEFORE building it.
import (
	"fmt"
	"runtime"
	"time"
)

const N = 68000 // ~ real AstroBWTv3 data_len

type lane struct {
	text   []byte
	sa     []int32
	bucket []int32
	b      int32
	cB     byte
}

func mkLane(seed uint32) *lane {
	l := &lane{text: make([]byte, N+2), sa: make([]int32, N), bucket: make([]int32, 256)}
	x := seed
	for i := range l.text {
		x = x*1664525 + 1013904223
		l.text[i] = byte(x >> 16)
	}
	// plausible sa: indices with ~50% flagged (<=0) like the real induce input
	for i := range l.sa {
		x = x*1664525 + 1013904223
		v := int32((x >> 8) % N)
		if x&1 == 0 {
			v = -v
		}
		l.sa[i] = v
	}
	for i := range l.bucket {
		l.bucket[i] = int32((int(seed)*7 + i*257) % N)
	}
	l.cB = 0
	l.b = l.bucket[0]
	return l
}

// one iteration of the real induceL_8_32 body for lane l at position i
func step(l *lane, i int) {
	j := int(l.sa[i])
	if j <= 0 {
		return
	}
	k := j - 1
	c1 := l.text[k]
	if k > 0 {
		if c0 := l.text[k-1]; c0 < c1 {
			k = -k
		}
	}
	if l.cB != c1 {
		l.bucket[l.cB] = l.b
		l.cB = c1
		l.b = l.bucket[c1]
	}
	if l.b >= 0 && int(l.b) < N {
		l.sa[l.b] = int32(k)
	}
	l.b++
}

func runK(k, passes int) float64 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	lanes := make([]*lane, k)
	for c := 0; c < k; c++ {
		lanes[c] = mkLane(uint32(c*2654435761 + 12345))
	}
	start := time.Now()
	for p := 0; p < passes; p++ {
		// interleave: for each i, do all K lanes' body -> K independent random
		// text[k] reads + sa[b] writes outstanding at once (fills MLP)
		for i := 0; i < N; i++ {
			for c := 0; c < k; c++ {
				step(lanes[c], i)
			}
		}
	}
	el := time.Since(start).Seconds()
	var sink int32
	for _, l := range lanes {
		sink += l.sa[0] + l.b
	}
	_ = sink
	totalInduce := float64(passes) * float64(N) * float64(k) // induce-iterations done
	return totalInduce / el / 1e6                            // M induce-iters/sec (throughput)
}

func main() {
	fmt.Printf("Induce-loop ILP PoC: real induceL_8_32 body, N=%d, single P-core\n", N)
	runK(1, 20) // warmup
	fmt.Printf("%6s %18s %12s %14s\n", "K", "M-induce-iters/s", "speedup", "per-lane")
	base := 0.0
	for _, k := range []int{1, 2, 3, 4, 6, 8} {
		passes := 240 / k
		if passes < 20 {
			passes = 20
		}
		r := runK(k, passes)
		if k == 1 {
			base = r
		}
		fmt.Printf("%6d %18.1f %11.2fx %14.1f\n", k, r, r/base, r/float64(k))
	}
	fmt.Println("\nspeedup = aggregate induce throughput at K lanes vs 1 lane on one core.")
	fmt.Println(">1.3x at K=2..4 => the heroic K-way SAIS rewrite is worth building.")
}
