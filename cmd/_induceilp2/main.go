package main

// v2: hand-inlined K=1/2/4 induce-loop interleave (best case for ILP: no call
// overhead, no lane-array indirection). If even this doesn't beat K=1, the K-way
// SAIS rewrite is refuted. Mirrors induceL_8_32 (sais.go:822-853).
import (
	"fmt"
	"time"
)

const N = 68000

func mkText(seed uint32) []byte {
	t := make([]byte, N+2)
	x := seed
	for i := range t {
		x = x*1664525 + 1013904223
		t[i] = byte(x >> 16)
	}
	return t
}
func mkSA(seed uint32) []int32 {
	s := make([]int32, N)
	x := seed ^ 0x9e3779b9
	for i := range s {
		x = x*1664525 + 1013904223
		v := int32((x >> 8) % N)
		if x&1 == 0 {
			v = -v
		}
		s[i] = v
	}
	return s
}

//go:noinline
func induce1(text []byte, sa []int32, bucket []int32) {
	var b int32 = bucket[0]
	var cB byte
	for i := 0; i < N; i++ {
		j := int(sa[i])
		if j <= 0 {
			continue
		}
		k := j - 1
		c1 := text[k]
		if k > 0 && text[k-1] < c1 {
			k = -k
		}
		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[c1]
		}
		if b >= 0 && int(b) < N {
			sa[b] = int32(k)
		}
		b++
	}
}

//go:noinline
func induce2(t0 []byte, s0 []int32, bk0 []int32, t1 []byte, s1 []int32, bk1 []int32) {
	var b0, b1 int32 = bk0[0], bk1[0]
	var c0B, c1B byte
	for i := 0; i < N; i++ {
		// lane 0
		j0 := int(s0[i])
		if j0 > 0 {
			k0 := j0 - 1
			cc0 := t0[k0]
			if k0 > 0 && t0[k0-1] < cc0 {
				k0 = -k0
			}
			if c0B != cc0 {
				bk0[c0B] = b0
				c0B = cc0
				b0 = bk0[cc0]
			}
			if b0 >= 0 && int(b0) < N {
				s0[b0] = int32(k0)
			}
			b0++
		}
		// lane 1 (independent memory -> loads can overlap lane 0's in the OoO window)
		j1 := int(s1[i])
		if j1 > 0 {
			k1 := j1 - 1
			cc1 := t1[k1]
			if k1 > 0 && t1[k1-1] < cc1 {
				k1 = -k1
			}
			if c1B != cc1 {
				bk1[c1B] = b1
				c1B = cc1
				b1 = bk1[cc1]
			}
			if b1 >= 0 && int(b1) < N {
				s1[b1] = int32(k1)
			}
			b1++
		}
	}
}

func main() {
	fmt.Printf("Induce ILP PoC v2 (hand-inlined), N=%d, one P-core, 3 runs each\n", N)
	t0, t1, t2, t3 := mkText(1), mkText(2), mkText(3), mkText(4)
	bk := func() []int32 { b := make([]int32, 256); for i := range b { b[i] = int32((i*257 + 11) % N) }; return b }

	const P = 60
	for run := 1; run <= 3; run++ {
		// K=1: do P passes of one lane
		s0 := mkSA(1)
		st := time.Now()
		for p := 0; p < P; p++ {
			induce1(t0, s0, bk())
		}
		e1 := time.Since(st).Seconds()
		r1 := float64(P) * N / e1 / 1e6

		// K=2: P/2 passes of 2 lanes -> same total induce-iters
		a0, a1 := mkSA(1), mkSA(2)
		st = time.Now()
		for p := 0; p < P/2; p++ {
			induce2(t0, a0, bk(), t1, a1, bk())
		}
		e2 := time.Since(st).Seconds()
		r2 := float64(P/2) * 2 * N / e2 / 1e6

		// K=4: two induce2 calls back-to-back per pass, P/4 passes
		b0, b1, b2, b3 := mkSA(1), mkSA(2), mkSA(3), mkSA(4)
		st = time.Now()
		for p := 0; p < P/4; p++ {
			induce2(t0, b0, bk(), t1, b1, bk())
			induce2(t2, b2, bk(), t3, b3, bk())
		}
		e4 := time.Since(st).Seconds()
		r4 := float64(P/4) * 4 * N / e4 / 1e6

		_ = t2
		_ = t3
		fmt.Printf("  run%d  K1=%.1f  K2=%.1f (%.2fx)  K4=%.1f (%.2fx)  M-iters/s\n",
			run, r1, r2, r2/r1, r4, r4/r1)
	}
	fmt.Println("verdict: if K2/K4 speedup <= ~1.05x, the K-way SAIS interleave is REFUTED.")
}
