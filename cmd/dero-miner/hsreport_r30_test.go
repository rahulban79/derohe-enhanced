package main

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

func kv(fields []interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	for i := 0; i+1 < len(fields); i += 2 {
		m[fields[i].(string)] = fields[i+1]
	}
	return m
}

// B26: the miner-level stale_sha_skipped total only grows, across an engine restart (new id, count from 0) and a
// new engine that already climbed past the old engine's value before the first observation.
func TestR30StaleSHATrackerMonotonic(t *testing.T) {
	var tr stale_sha_tracker
	steps := []struct {
		id   uintptr
		v    uint64
		want uint64
	}{{1, 10, 10}, {1, 25, 25}, {1, 25, 25}, {2, 4, 29}, {2, 9, 34}, {3, 100, 134}, {3, 50, 184}}
	for i, s := range steps {
		if got := tr.observe(s.id, s.v); got != s.want {
			t.Fatalf("step %d observe(%d, %d) = %d, want %d", i, s.id, s.v, got, s.want)
		}
	}
}

// B26: TOTAL H/s excludes the never-hashed texts and carries the label; H/s_raw keeps the old figure.
func TestR30HsFieldsExcludeStale(t *testing.T) {
	f := kv(hs_fields(150000, 1500, 15))
	if f["H/s"] != "9900" || f["H/s_raw"] != "10000" || f["stale_sha_skipped"] != uint64(1500) || f["hs_excludes"] != "stale_sha_skipped" {
		t.Fatalf("hs_fields = %v", f)
	}
	if f := kv(hs_fields(10, 20, 1)); f["H/s"] != "0" {
		t.Fatalf("more skipped than counted must read 0, got %v", f)
	}
	if effective_hashes(100, 7) != 93 || effective_hashes(5, 9) != 0 {
		t.Fatal("effective_hashes")
	}
	if effective_share(90, 100) != 0.9 || effective_share(0, 0) != 1 || effective_share(5, 3) != 1 {
		t.Fatal("effective_share")
	}
}

// B26 + B27: /metrics exports the miner-level counter, the effective total, the HELP label and the P/E split.
func TestR30MetricsExportStaleAndPE(t *testing.T) {
	var b bytes.Buffer
	write_miner_metrics(&b, miner_metrics{hashes: 1000, stale_sha_skipped: 30, pe_ok: true, cpu_p: 3 * time.Second, cpu_e: 500 * time.Millisecond})
	s := b.String()
	for _, want := range []string{"dero_miner_stale_sha_skipped_total 30", "dero_miner_hashes_effective_total 970",
		"dero_miner_hashes_total 1000", "excluding stale_sha_skipped",
		`dero_miner_cpu_seconds_total{core="p"} 3.000`, `dero_miner_cpu_seconds_total{core="e"} 0.500`} {
		if !strings.Contains(s, want) {
			t.Fatalf("metrics lack %q:\n%s", want, s)
		}
	}
	b.Reset()
	write_miner_metrics(&b, miner_metrics{})
	if strings.Contains(b.String(), "dero_miner_cpu_seconds_total") {
		t.Fatal("no P/E reading must export no P/E series")
	}
}

// B27: the window's P/E split from two samples; '-' when a reading failed or is inconsistent.
func TestR30PEFields(t *testing.T) {
	a := pe_sample{total: 10 * time.Second, p: 8 * time.Second, ok: true}
	b := pe_sample{total: 10*time.Second + 18*15*time.Second, p: 8*time.Second + 16*15*time.Second, ok: true}
	f := kv(pe_fields(a, b, 15))
	if f["p_cores"] != "16.00" || f["e_cores"] != "2.00" || f["p_frac"] != "0.889" {
		t.Fatalf("pe_fields = %v", f)
	}
	for _, bad := range []pe_sample{{ok: false}, {total: a.total, p: a.p, ok: true}, {total: b.total, p: b.total + time.Second, ok: true}} {
		if f := kv(pe_fields(a, bad, 15)); f["p_cores"] != "-" || f["e_cores"] != "-" {
			t.Fatalf("pe_fields(%v) = %v, want '-'", bad, f)
		}
	}
}

func TestR30MachTicks(t *testing.T) {
	if mach_ticks_ns(3, 125, 3) != 125 || mach_ticks_ns(1<<62, 125, 3) <= 0 || mach_ticks_ns(5, 1, 0) != 0 {
		t.Fatal("mach_ticks_ns")
	}
	if mach_ticks_ns(24_000_000, 125, 3) != time.Second {
		t.Fatalf("24 M ticks = %v, want 1s", mach_ticks_ns(24_000_000, 125, 3))
	}
}

// B27: on darwin the kernel's split is real: CPU burnt here shows up, P <= total, and total agrees with getrusage.
func TestR30PECPUTimeReal(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("P/E split is darwin-only")
	}
	t0, p0, ok := pe_cpu_time()
	r0 := process_cpu_time()
	if !ok {
		t.Fatal("proc_pid_rusage v6 failed on darwin")
	}
	x := 0.0
	// burn until the PROCESS got 200 ms of CPU (bounded by 20 s wall): on a saturated box at nice 15 a wall-clock burn
	// gets only part of a core (race run 2026-11-08: 171 ms of CPU in a 300 ms burn)
	for end := time.Now().Add(20 * time.Second); process_cpu_time()-r0 < 200*time.Millisecond && time.Now().Before(end); {
		for i := 0; i < 100000; i++ {
			x += float64(i) * 0.5
		}
	}
	_ = x
	t1, p1, _ := pe_cpu_time()
	r1 := process_cpu_time()
	dt, dr := t1-t0, r1-r0
	if dt < 150*time.Millisecond || p1 < p0 || p1-p0 > dt || p1 > t1 {
		t.Fatalf("pe total %v (P %v) for a 200 ms CPU burn (getrusage %v)", dt, p1-p0, dr)
	}
	if d := dt - dr; d > dr/5 || -d > dr/5 {
		t.Fatalf("pe total %v vs getrusage %v: units are wrong", dt, dr)
	}
}

// B26 source check: the status loop reports effective hashes and scales the expectation (it runs inside main).
func TestR30StatusLoopReportsEffective(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{"dc, ds, eff, next_stale := total_window_step(c, last_total, stale_sha_now(), last_stale)",
		"fields := hs_fields(dc, ds, el.Seconds())", "last_stale = cpuNow, peNow, next_stale",
		"contention_fields(eff, cpuNow-last_total_cpu", "exp *= effective_share(eff, dc)", "run_hashes += eff",
		"effective_hashes(atomic.LoadUint64(&counter), stale_sha_now())", "pe_fields(last_pe, peNow"} {
		if !strings.Contains(s, want) {
			t.Fatalf("miner.go lacks %q", want)
		}
	}
}

// B26 behaviour (r30 verifier): the TOTAL window arithmetic. ds is st - last_stale (not its negation), a total that
// went backwards gives ds 0, and next_stale carries st so the next window counts only its own skipped texts.
func TestR30TotalWindowStep(t *testing.T) {
	// window 1: 1,000 counted, stale total 0 -> 30
	dc, ds, eff, ns := total_window_step(1000, 0, 30, 0)
	if dc != 1000 || ds != 30 || eff != 970 || ns != 30 {
		t.Fatalf("window 1: dc %d ds %d eff %d next %d, want 1000 30 970 30", dc, ds, eff, ns)
	}
	// window 2 starts from window 1's carry: 900 more counted, stale total 30 -> 50 = 20 in the window
	dc, ds, eff, ns = total_window_step(1900, 1000, 50, ns)
	if dc != 900 || ds != 20 || eff != 880 || ns != 50 {
		t.Fatalf("window 2: dc %d ds %d eff %d next %d, want 900 20 880 50", dc, ds, eff, ns)
	}
	// window 3: stale total unchanged -> ds 0, eff = dc
	dc, ds, eff, ns = total_window_step(2500, 1900, 50, ns)
	if dc != 600 || ds != 0 || eff != 600 || ns != 50 {
		t.Fatalf("window 3: dc %d ds %d eff %d next %d, want 600 0 600 50", dc, ds, eff, ns)
	}
	// a total below the carry (never expected: the tracker is monotonic) clamps ds to 0 and carries the new st
	dc, ds, eff, ns = total_window_step(3000, 2500, 40, ns)
	if ds != 0 || eff != 500 || ns != 40 {
		t.Fatalf("backwards: ds %d eff %d next %d, want 0 500 40", ds, eff, ns)
	}
	// a five-window run: the sum of ds equals the final stale total (each skipped text is counted exactly once)
	var last_total, last_stale, sum_ds uint64
	for i, st := range []uint64{7, 7, 19, 40, 41} {
		var d uint64
		_, d, _, last_stale = total_window_step(uint64(i+1)*500, last_total, st, last_stale)
		last_total = uint64(i+1) * 500
		sum_ds += d
	}
	if sum_ds != 41 {
		t.Fatalf("sum of window ds %d, want 41 (the final stale total)", sum_ds)
	}
}

// B26 behaviour (r30 verifier): stale_sha_now's fold observes the engine's StaleSHASkipped as it is (not scaled),
// publishes it for /metrics, and an absent engine (id 0) leaves the total standing.
func TestR30StaleSHAFrom(t *testing.T) {
	saved, savedTot := stale_sha, atomic.LoadUint64(&stale_sha_skipped_total)
	defer func() { stale_sha = saved; atomic.StoreUint64(&stale_sha_skipped_total, savedTot) }()
	stale_sha = &stale_sha_tracker{}
	atomic.StoreUint64(&stale_sha_skipped_total, 0)
	if got := stale_sha_from(7, gsplit.Stats{StaleSHASkipped: 100}); got != 100 {
		t.Fatalf("stale_sha_from(7, 100) = %d, want 100", got)
	}
	if got := atomic.LoadUint64(&stale_sha_skipped_total); got != 100 {
		t.Fatalf("published total %d, want 100", got)
	}
	if got := stale_sha_from(0, gsplit.Stats{StaleSHASkipped: 999}); got != 100 {
		t.Fatalf("no engine: total %d, want 100 (stands)", got)
	}
	if got := stale_sha_from(7, gsplit.Stats{StaleSHASkipped: 130}); got != 130 {
		t.Fatalf("stale_sha_from(7, 130) = %d, want 130", got)
	}
	if got := stale_sha_from(8, gsplit.Stats{StaleSHASkipped: 6}); got != 136 {
		t.Fatalf("new engine 8 at 6: total %d, want 136", got)
	}
	// no engine running in the test process: stale_sha_now returns the standing total
	if current_split() == nil {
		if got := stale_sha_now(); got != 136 {
			t.Fatalf("stale_sha_now with no engine = %d, want 136", got)
		}
	}
}
