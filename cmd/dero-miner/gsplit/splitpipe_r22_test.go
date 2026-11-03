package gsplit

// Round 22 splitpipe: runtime GPU duty cap (SetGPUMax, for the miner's --gpu-max=auto tuner), the throttle/collect
// cost counters, and the GPU SHA skipped for a batch whose job went stale while it was being sorted.

import (
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

// A batch whose job goes stale after some of its pairs were sorted: the rest is dropped, and op 2 (the GPU SHA of the
// whole batch) is not run, so none of its stale hashes is reported; the engine keeps mining the new job.
func TestStaleBatchSkipsGPUSHA(t *testing.T) {
	r := newRig(t, true, 8, 2, 0)
	e := r.e
	e.Start()
	defer e.Close()
	if !waitFor(func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.ready) >= 1 }, 10*time.Second) {
		t.Fatal("nothing staged")
	}
	s := astropair.NewScratch()
	if k := e.TryWork(s); k != 2 { // one epoch-0 pair sorted
		t.Fatalf("TryWork = %d, want 2", k)
	}
	r.epoch.Store(1)
	if k := e.TryWork(s); k != 0 && k != 2 { // finds epoch 0 stale: drops the rest (op 2 skipped), maybe sorts an epoch-1 pair
		t.Fatalf("TryWork = %d", k)
	}
	if n := r.mine(2, 32); n < 32 {
		t.Fatalf("mined %d after the job change", n)
	}
	st := e.Stats()
	if st.StaleSHASkipped < 2 {
		t.Fatalf("StaleSHASkipped = %d, want >= 2 (the sorted epoch-0 pair): %+v", st.StaleSHASkipped, st)
	}
	time.Sleep(50 * time.Millisecond) // any op 2 of the stale batch would have been collected by now
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.got {
		if f.tag.(int64) != 1 {
			t.Fatal("a hash of the stale epoch-0 batch was reported (its GPU SHA ran)")
		}
	}
	if len(r.got) == 0 {
		t.Fatal("no epoch-1 hash reported")
	}
}

// SetGPUMax moves the duty cap the debt is charged at, clamps to 1..100, and 100 forgives the outstanding debt.
func TestSetGPUMaxRuntime(t *testing.T) {
	r := newRigCfg(t, true, 8, 2, 0, func(c *Config) { c.GPUMax = 50 })
	e := r.e
	defer e.Close()
	if e.GPUMax() != 50 || e.Stats().GPUMax != 50 {
		t.Fatalf("GPUMax = %d", e.GPUMax())
	}
	e.charge(1000)
	if d := e.debt.Load(); d != 2000 { // r22 merge, duty bucket: 1000 ns busy at 50% costs 2000 ns of wall time
		t.Fatalf("debt at 50%% = %d, want 2000", d)
	}
	if p := e.SetGPUMax(80); p != 80 {
		t.Fatalf("SetGPUMax(80) = %d", p)
	}
	e.charge(800)
	if d := e.debt.Load(); d != 3000 { // + 800*100/80 = 1000
		t.Fatalf("debt after 800 ns at 80%% = %d, want 3000", d)
	}
	if p := e.SetGPUMax(250); p != 100 || e.debt.Load() != 0 {
		t.Fatalf("SetGPUMax(250) = %d, debt %d: want 100 and the debt forgiven", p, e.debt.Load())
	}
	e.charge(5000)
	if d := e.debt.Load(); d != 0 {
		t.Fatalf("debt at 100%% = %d", d)
	}
	if p := e.SetGPUMax(0); p != 1 {
		t.Fatalf("SetGPUMax(0) = %d, want 1", p)
	}
}

// The feeder's throttle sleeps and the reply loop's collect time are counted. r22 merge: the duty bucket banks up to
// dutyBurstNs of credit and the soft GPU reports 7 us per buffer, so the test owes 20 ms up front (the mechanism under
// test is the counting of the feeder's wait, not the soft GPU's duty).
func TestThrottleAndCollectCounted(t *testing.T) {
	r := newRigCfg(t, true, 64, 3, 0, func(c *Config) { c.GPUMax = 50 })
	e := r.e
	e.debt.Store(int64(20 * time.Millisecond))
	e.Start()
	if n := r.mine(2, 1024); n < 1024 {
		t.Fatalf("mined %d", n)
	}
	e.Close()
	st := e.Stats()
	if st.ThrottleUs == 0 || st.CollectUs == 0 {
		t.Fatalf("ThrottleUs %d CollectUs %d after %d batches at --gpu-max 50", st.ThrottleUs, st.CollectUs, st.Batches)
	}
	r2 := newRig(t, true, 64, 3, 0) // GPUMax 100: never throttled
	r2.e.Start()
	if n := r2.mine(2, 512); n < 512 {
		t.Fatalf("mined %d", n)
	}
	r2.e.Close()
	if st := r2.e.Stats(); st.ThrottleUs != 0 {
		t.Fatalf("ThrottleUs = %d at --gpu-max 100", st.ThrottleUs)
	}
}

// r22 merge (splitpipe SP22-3 review fix): finish()'s pre-SHA re-check uses Config.StaleQuiet, so the miner's
// per-reason stale counters (driven by Stale) see each drop once. A batch whose last pair finishes after its job went
// stale is skipped through StaleQuiet, and Stale is not consulted.
func TestFinishStaleRecheckIsQuiet(t *testing.T) {
	var quiet, loud int
	r := newRigCfg(t, true, 8, 2, 0, func(c *Config) {
		c.Stale = func(tag interface{}) bool { loud++; return true }
		c.StaleQuiet = func(tag interface{}) bool { quiet++; return true }
	})
	e := r.e
	defer e.Close()
	b := e.batches[0]
	b.n = 8
	b.work.Tag = int64(0)
	b.done.Store(6)
	b.dropped.Store(0)
	e.finish(b, 2)
	if quiet != 1 || loud != 0 {
		t.Fatalf("finish consulted StaleQuiet %d times and Stale %d times; want 1 and 0", quiet, loud)
	}
	if st := e.Stats(); st.StaleSHASkipped != 8 {
		t.Fatalf("StaleSHASkipped = %d, want 8", st.StaleSHASkipped)
	}
	// nil StaleQuiet falls back to Stale (engines built without it keep the r22 splitpipe behaviour)
	e.cfg.StaleQuiet = nil
	b2 := e.batches[1]
	b2.n = 8
	b2.work.Tag = int64(0)
	b2.done.Store(6)
	e.finish(b2, 2)
	if loud != 1 {
		t.Fatalf("fallback: Stale consulted %d times, want 1", loud)
	}
}
