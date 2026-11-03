package main

import (
	"os"
	"regexp"
	"runtime"
	"sync/atomic"
	"testing"
)

// r21 splitpipe: an unlocked mining goroutine yields once every cgo_yield_every cgo sorts (pairs count 2), a locked
// one never does.
func TestCgoYielderCadence(t *testing.T) {
	y := cgo_yielder{}
	yields := 0
	for i := 0; i < 10*cgo_yield_every; i++ {
		if y.sorted(1) {
			yields++
			if (i+1)%cgo_yield_every != 0 {
				t.Fatalf("yielded after sort %d, want every %d", i+1, cgo_yield_every)
			}
		}
	}
	if yields != 10 {
		t.Fatalf("%d yields in %d sorts, want 10", yields, 10*cgo_yield_every)
	}
	y = cgo_yielder{}
	n := 0
	for i := 0; i < 2*cgo_yield_every; i++ {
		if y.sorted(2) {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("pairs: %d yields in %d sorts, want 4", n, 4*cgo_yield_every)
	}
	l := cgo_yielder{locked: true}
	for i := 0; i < 4*cgo_yield_every; i++ {
		if l.sorted(1) {
			t.Fatal("a locked goroutine yielded (two thread handoffs per Gosched)")
		}
	}
	if cgo_yield_every*200 >= 10000/2 { // ~200 us per sort: stay far inside forcePreemptNS (10 ms), even on an E-core
		t.Fatalf("cgo_yield_every %d too large for the 10 ms preemption window", cgo_yield_every)
	}
	if new_cgo_yielder().locked != should_lock_mining_thread(runtime.GOOS, cpu_qos) {
		t.Fatal("new_cgo_yielder ignores whether the goroutine is locked")
	}
}

// Every cgo-sorting mining loop counts its sorts into the yielder (source invariant: the loops are not unit-callable).
func TestMiningLoopsYield(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{
		`se\.TryWork\(pscratch\); k > 0 \{\n\t+atomic\.AddUint64\(&counter, uint64\(k\)\)\n\t+yield\.sorted\(k\)`,
		`ha, hb := hash_pair\(work\[:\], work2\[:\], pscratch\)\n\t+atomic\.AddUint64\(&counter, 2\)\n\t+yield\.sorted\(2\)`,
		`powhash := astrobwtv3\.AstroBWTv3\(work\[:\]\)\n\t+atomic\.AddUint64\(&counter, 1\)\n\t+yield\.sorted\(1\)`,
		`lock_mining_thread\(\)\n\tyield := new_cgo_yielder\(\)`,
	} {
		if !regexp.MustCompile(re).Match(src) {
			t.Errorf("mining loop does not yield: %s", re)
		}
	}
	b, err := os.ReadFile("splitbench.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`finish\(k\)\n\t+\}\n\t+yield\.sorted\(1\)`).Match(b) {
		t.Error("split bench does not yield like the mining loop")
	}
}

// The yield really hands the P over: on one P, a runnable goroutine gets to run within cgo_yield_every sorts, long
// before async preemption (10 ms) would let it.
func TestCgoYielderHandsOverP(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for round := 0; round < 3; round++ {
		var ran atomic.Bool
		go ran.Store(true)
		y := cgo_yielder{}
		i := 0
		for ; i < 100000 && !ran.Load(); i++ {
			y.sorted(1)
		}
		// a yield may pick this goroutine again (the scheduler takes the global run queue first every 61st tick), so
		// allow a few yields; without the yield it would need async preemption (10 ms, far beyond 100000 calls)
		if !ran.Load() || i > 4*cgo_yield_every {
			t.Fatalf("round %d: the other goroutine ran=%v after %d sorts, want within %d", round, ran.Load(), i, 4*cgo_yield_every)
		}
	}
}
