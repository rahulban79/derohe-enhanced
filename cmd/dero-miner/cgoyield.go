package main

// Round 21 splitpipe: keep the Go scheduler from taking a mining thread's P during every cgo sort.
//
// In --gpu-mode=split a mining thread's whole job is one ~180 us cgo call (the native descriptor sort) per hash, and
// the full-hash path makes one per hash too. The runtime treats a cgo call as a syscall; sysmon takes the P away from
// a thread in a syscall (runtime/proc.go retake) when either
//   (1) the goroutine has run on the same schedtick for forcePreemptNS (10 ms). preemptone cannot preempt a goroutine
//       that is inside the syscall, and a mining goroutine is inside the sort ~99% of the time, so it is almost never
//       rescheduled: after its first 10 ms EVERY later sort loses the P, for the life of the goroutine; or
//   (2) no P is idle (--mining-threads == GOMAXPROCS, the default) and the call lasted one sysmon tick (>= 20 us).
// A thread that returns from C without its P takes the slow path (exitsyscall -> exitsyscallTryGetP): sched.lock and,
// because every P looked idle, a pthread_cond_signal to wake sysmon. Profiled under benchlock (gsplit
// TestSplitOverheadAB, 6 threads, contended box): 18.7% of all process CPU samples were in that slow path
// (notewakeup 14.0 s + sched.lock spin 4.7 s of 100.3 s).
//
// Fix, scheduler-only (no hash/consensus change): a mining goroutine yields (runtime.Gosched) every cgo_yield_every
// sorts, which bumps its schedtick well inside the 10 ms window and removes cause (1). Measured (gsplit
// TestYieldExperiment, sort-only, 6 goroutines, interleaved, getrusage): +5.0/+6.9/+5.5% H/cpu-s at GOMAXPROCS=6 and
// +7.6/+5.1/+4.8% at GOMAXPROCS=8; two spare Ps WITHOUT the yield gave -0.6/+1.1/-1.9% (noise), so cause (2) is not
// worth a GOMAXPROCS change. dero-miner --bench, 6 threads, 6 interleaved base/new pairs: split x1.056 median
// (1.035..1.075, every pair > 1), full hash x1.018 (3 pairs, 1.017..1.028). Locked goroutines (CPU affinity on linux/windows, --cpu-qos on darwin) never yield here:
// a Gosched there costs the two thread handoffs r17 measured.

import "runtime"

// cgo_yield_every sorts between yields: 8 x ~200 us ~ 1.6 ms, far inside forcePreemptNS (10 ms) even on an E-core
// (~2.3x slower), at ~1 us per Gosched (<0.1%).
const cgo_yield_every = 8

// cgo_yielder counts a mining goroutine's cgo sorts and yields every cgo_yield_every of them.
type cgo_yielder struct {
	n      int
	locked bool // the goroutine is LockOSThread'ed: never yield
}

func new_cgo_yielder() cgo_yielder {
	return cgo_yielder{locked: should_lock_mining_thread(runtime.GOOS, cpu_qos)}
}

// sorted records k cgo sorts and reports whether it yielded.
func (y *cgo_yielder) sorted(k int) bool {
	if y.locked {
		return false
	}
	if y.n += k; y.n < cgo_yield_every {
		return false
	}
	y.n = 0
	runtime.Gosched()
	return true
}
