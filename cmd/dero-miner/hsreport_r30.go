package main

// Round 30 (rft §7 B26, B27): what the TOTAL line and /metrics report as the hashrate, and the P/E CPU split.
//
// B26: in --gpu-mode=split a CPU thread adds the texts it sorted to `counter` in TryWork (miner.go), but when the job
// went stale while the batch was being sorted the engine skips the GPU's final SHA for the whole batch
// (gsplit.Engine.finish, StaleSHASkipped): those texts were never hashed and can make no share. `counter` stays as it
// is (dero_miner_hashes_total is a monotonic counter consumers rate()), and a separate miner-level counter,
// stale_sha_skipped, is kept monotonic across engine restarts; every hashrate the miner REPORTS (TOTAL H/s, H/cpu-s,
// the 15 s prompt and dero_miner_hashrate_15s, the expectation window) is effective = counter - stale_sha_skipped,
// with the label hs_excludes=stale_sha_skipped on the line and a HELP line on the metric. The raw figure stays on the
// line as H/s_raw. Live r29: 173,928 of 83,380,548 = 0.21 % (harness/runtime/r30_objective_read_20261108.txt).
//
// B27: proc_pid_rusage v6 splits the process's CPU time into P-core and E-core time (pecpu_darwin.go). The TOTAL line
// carries p_cores / e_cores (CPU-seconds per wall second on each kind) and /metrics
// dero_miner_cpu_seconds_total{core="p"|"e"}, so the live law H = r_P * p_cores + r_E * e_cores is fitted from the
// miner's own windows (harness/intel/hashrate_objective.py live_law) instead of assumed (R23b r_P 5,950, r_E
// 1,650-2,260: a bound, not a reading).

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

// stale_sha_tracker folds the engine's StaleSHASkipped (which restarts at 0 with every new engine) into one monotonic
// miner-level total. Keyed by the engine's identity so a new engine that already climbed past the old value between
// two observations is still counted from 0.
type stale_sha_tracker struct {
	mu    sync.Mutex
	id    uintptr
	last  uint64
	total uint64
}

func (t *stale_sha_tracker) observe(id uintptr, v uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id != t.id || v < t.last { // a new engine (or a reset): its whole count is new
		t.id, t.last = id, 0
	}
	t.total += v - t.last
	t.last = v
	return t.total
}

var stale_sha = &stale_sha_tracker{}
var stale_sha_skipped_total uint64 // atomic copy for /metrics: the newest observe()

// stale_sha_now observes the live engine (if any) and returns the miner-level total.
func stale_sha_now() uint64 {
	var id uintptr
	var st gsplit.Stats
	if e := current_split(); e != nil {
		id, st = engine_id(e), e.Stats()
	}
	return stale_sha_from(id, st)
}

// stale_sha_from folds one engine reading (identity id, its Stats) into the miner-level total and publishes it for
// /metrics; id 0 (no engine) leaves the total standing. Split from stale_sha_now so a test drives it with a Stats value.
func stale_sha_from(id uintptr, st gsplit.Stats) uint64 {
	if id == 0 { // no engine: the total stands
		return atomic.LoadUint64(&stale_sha_skipped_total)
	}
	v := st.StaleSHASkipped
	tot := stale_sha.observe(id, v)
	atomic.StoreUint64(&stale_sha_skipped_total, tot)
	return tot
}

// total_window_step is the TOTAL line's window arithmetic (miner.go status loop, r30 B26): counter c and the
// miner-level stale total st now, against the previous window's last_total / last_stale. dc = counted hashes,
// ds = stale-SHA-skipped hashes in the window (0 if the total ever went backwards), eff = dc - ds (never below 0),
// next_stale = the last_stale the next window starts from (always st: carried even when ds was clamped). Pure.
func total_window_step(c, last_total, st, last_stale uint64) (dc, ds, eff, next_stale uint64) {
	dc = c - last_total
	ds = st - last_stale
	if st < last_stale {
		ds = 0
	}
	eff = effective_hashes(dc, ds)
	next_stale = st
	return dc, ds, eff, next_stale
}

// effective_hashes: hashes the miner actually completed = counted - stale_sha_skipped (never below 0). Pure.
func effective_hashes(counted, stale uint64) uint64 {
	if stale >= counted {
		return 0
	}
	return counted - stale
}

// effective_share: the fraction of a window's counted hashes that were completed (1 when nothing was counted). The
// phase clock books counted hashes, so the window's expected shares are scaled by it rather than re-booked. Pure.
func effective_share(eff, counted uint64) float64 {
	if counted == 0 || eff >= counted {
		return 1
	}
	return float64(eff) / float64(counted)
}

// hs_fields: the TOTAL line's hashrate fields for a window of dc counted hashes, ds of them stale-SHA-skipped, over
// el seconds. H/s excludes the skipped texts and says so (hs_excludes); H/s_raw is the old figure. Pure.
func hs_fields(dc, ds uint64, el float64) []interface{} {
	if el <= 0 {
		return []interface{}{"H/s", "-", "H/s_raw", "-", "stale_sha_skipped", ds, "hs_excludes", "stale_sha_skipped"}
	}
	return []interface{}{"H/s", fmt.Sprintf("%.0f", float64(effective_hashes(dc, ds))/el),
		"H/s_raw", fmt.Sprintf("%.0f", float64(dc)/el), "stale_sha_skipped", ds, "hs_excludes", "stale_sha_skipped"}
}

// pe_sample is one reading of pe_cpu_time.
type pe_sample struct {
	total, p time.Duration
	ok       bool
}

func pe_now() pe_sample {
	t, p, ok := pe_cpu_time()
	return pe_sample{t, p, ok}
}

// pe_fields: p_cores and e_cores over a window (CPU-seconds on each core kind per wall second) and p_frac, the P share
// of the window's CPU time. "-" when either reading failed or nothing ran. Pure.
func pe_fields(a, b pe_sample, el float64) []interface{} {
	dt, dp := b.total-a.total, b.p-a.p
	if !a.ok || !b.ok || el <= 0 || dt <= 0 || dp < 0 || dp > dt {
		return []interface{}{"p_cores", "-", "e_cores", "-", "p_frac", "-"}
	}
	de := dt - dp
	return []interface{}{"p_cores", fmt.Sprintf("%.2f", dp.Seconds()/el), "e_cores", fmt.Sprintf("%.2f", de.Seconds()/el),
		"p_frac", fmt.Sprintf("%.3f", float64(dp)/float64(dt))}
}

// mach_ticks_ns converts mach absolute-time ticks to a Duration without overflowing for any realistic CPU time. Pure.
func mach_ticks_ns(ticks uint64, numer, denom uint32) time.Duration {
	if denom == 0 {
		return 0
	}
	q, r := ticks/uint64(denom), ticks%uint64(denom)
	return time.Duration(q*uint64(numer) + r*uint64(numer)/uint64(denom))
}

// engine_id: a stable identity for an engine pointer (its address); 0 for nil. Caveat (r30 verifier): an address can be
// reused by a later engine once the old one is collected; observe() then treats the new engine as the old one and, while
// its count is still below the old engine's last value, resets correctly (v < t.last); only a new engine at the same
// address that already climbed past the old value before its first observation is under-counted by the old value.
// Engines are replaced only on a GPU restart (each lives for minutes to days), so the address is kept.
func engine_id(e *gsplit.Engine) uintptr {
	if e == nil {
		return 0
	}
	return uintptr(unsafe.Pointer(e))
}
