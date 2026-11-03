package main

// --gpu-mode=split (Round 18): the GPU computes AstroBWTv3 stage 1 (and the final SHA-256) for batches of nonces into
// POSIX shared memory, and every CPU mining thread takes staged texts before hashing on its own (cmd/dero-miner/gsplit).
// Default stays --gpu-mode=full (the r17 full-hash worker, mineblock_gpu) until split is proven on the live host.
//
// Guards, in addition to gsplit's (bit-exact self-test through the real kernels, GPU length bounds, sampled CPU audit,
// panic -> CPU re-hash, verified_sort):
//   - every winning share is re-hashed with astrobwtv3.AstroBWTv3 before it is submitted (as mineblock_gpu does); a
//     disagreement is never submitted and disables split mode;
//   - a failed start or self-test falls back to --gpu-mode=full, so --gpu never silently stops using the GPU;
//   - a server that dies while mining (EOF, the macOS GPU watchdog) is reaped and relaunched with back-off and must pass
//     the bit-exact self-test again before staging resumes (gsplit respawn); only wrong results disable split mode.

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	rand "crypto/rand"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
	"github.com/deroproject/derohe/rpc"
)

// split geometry: 4096-nonce GPU commands, 4 in the ring (5.9 GB of POSIX shm), 2 command buffers in flight.
// Round 18 GPU-capacity probe (CPU side free, --gpu-max 90, contended host): 4096/4/2 50.4k staged H/s, 4096/4/4 52.5k,
// 4096/6/3 50.9k, 4096/4/1 33.8k, 2048/6/3 28.0k; no watchdog retries at 90%. DERO_GSPLIT=batch,depth,inflight overrides.
// r23b (r22 kernels, proxies with <= 8.3 ms command buffers next to the live miner): the final SHA is under-occupied at
// 4096 threads (per-hash 0.88 us -> 0.61 at 8192, 0.51 at 16384, L=4860 words) while stage 1 is already resident-bound
// (0.37 -> 0.42 us); pipeline proxy vs 4096x2: 8192x2 x1.34 / x1.47, 8192x3 x1.52 / x1.74 (two runs, medians; IQRs
// 1.17-1.94 and 0.88-2.23). Live, the GPU charges 10.7 us of busy wall time per staged hash at 4096,4,2 (a ~89.7k H/s
// ceiling at --gpu-max=96), but the CPU sort binds first whenever the box is contended, so a larger geometry pays
// only on a quiet box (ESTIMATE +5-8%, up to the ~100k CPU ceiling). Kept at 4096,4,2 until a live A/B
// (8192,4,2 = 11.8 GB of shm; 8192,5,3 = 14.7 GB).
// r23c (gpuflow, proxies next to the live miner, verified): only the batch helps. 8192,3,2 cuts GPU busy per hash
// to x0.72-0.82 (8.8 GB of shm; ceiling ~114k staged, ESTIMATE); 8192,5,3 is no better than 8192,4,2 and holds batches
// x2.3 longer; inflight 3, depth alone, a warp-specialised final SHA and cross-batch SHA coalescing all lost. Stale rises
// ~1.25% -> ~1.9% (model) and the stage-1 cost grows with trip count, so the default stays until a quiet-box live ABBA
// of DERO_GSPLIT=8192,3,2 (+2.9-3.7% ESTIMATE).
var split_geom = [3]int{4096, 4, 2}

// Round 19 GPU sort (gsplit Config.GPUSort): DERO_GSPLIT_SORT=lanes,chunk,inflight,minready (or "1" for the defaults
// below) also suffix-sorts staged batches on the GPU while the CPU threads have staged work waiting. OFF by default: on
// the live M1 Ultra the GPU is already ~99% busy with stage 1 + the final SHA (ioreg Device Utilization, 2026-10-24), so
// GPU sort time is taken from stage 1; it pays only where the GPU has headroom the CPU sort cannot use.
// r21 re-measure (r20 kernels, GPU ~92-93% busy at ~70k staged, CPU backlog ~68% of each minute): the real-GPU op 3
// ran 287 GPU-sorted SA/s while the live staged rate fell ~6-7k H/s and cpu_idle_tries jumped 12k -> 147k/min (the CPU
// starved: the sort took GPU time from stage 1). Still a net loss, so still OFF by default; when enabled, the A/B probe
// below pauses it automatically wherever that holds.
// r23 (CPU-starved box, GPU 63-87% busy): op 3 still does not pay where the GPU has headroom. Real-GPU op 3 under
// the live miner gave 840 (2 lanes) to 1,161 (8 lanes) sorted texts per command-buffer GPU-second, against ~79-91k
// staged hashes per GPU-busy second (11-12.7 us each), so even all of a 30% headroom buys at most ~0.25-0.35k H/s,
// and 8 lanes ran buffers up to 141 ms. An automatic "GPU idle + CPU starved" switch is therefore not shipped.
var split_sort_default = [4]int{2, 32, 1, 1}

// r21 gpusort: with the GPU sort on, the engine A/B-probes it (ABBA windows, sort paused vs allowed, compared on the
// miner's TOTAL hash counter) at start and hourly, and pauses it whenever it is a net loss. DERO_GSPLIT_SORT_PROBE is
// the window in seconds (default 60; "0" = no probe: the sort stays allowed whenever the CPU has a backlog).
const split_sort_probe_default = 60 * time.Second

func parse_split_sort_probe(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return split_sort_probe_default, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > 3600 {
		return split_sort_probe_default, fmt.Errorf("want 0..3600 seconds, got %q", s)
	}
	return time.Duration(v) * time.Second, nil
}

// parse_split_sort: "" or "0" = off.
func parse_split_sort(s string) (bool, [4]int, error) {
	g := split_sort_default
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return false, g, nil
	}
	if s == "1" {
		return true, g, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return false, g, fmt.Errorf("want lanes,chunk,inflight,minready")
	}
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 1 {
			return false, g, fmt.Errorf("bad %q", p)
		}
		g[i] = v
	}
	if g[0] > 8 || g[1] < 8 || g[1] > 512 {
		return false, g, fmt.Errorf("lanes must be 1..8, chunk 8..512")
	}
	return true, g, nil
}

const split_marker = 0xfe // last blob byte of split-mode nonces (CPU threads use their tid, the full GPU worker 0xff)

var split_engine unsafe.Pointer // *gsplit.Engine while split mode runs (atomic)

func current_split() *gsplit.Engine { return (*gsplit.Engine)(atomic.LoadPointer(&split_engine)) }

// splitJob is the Tag of a staged batch: the job it was cut from and its parsed difficulty.
type splitJob struct {
	job     rpc.GetBlockTemplate_Result
	diff    big.Int
	tgt     powTarget // r22: diff's target, computed once per batch (split_found runs per hash on the reply loop)
	counter int64
	fresh   int64 // atomic: a later job_counter at which split_stale found this job still worth sorting (memo)
}

// meets: the job's difficulty check (the precomputed target; CheckPowHashBig for a splitJob not made by split_next)
func (sj *splitJob) meets(h [32]byte) bool {
	if sj.tgt.set {
		return sj.tgt.meets(h)
	}
	return CheckPowHashBig(h, &sj.diff)
}

// split_stale_height / split_stale_final count split_stale verdicts that dropped a batch's unclaimed texts, by reason
// (r21 forensics): a newer height is being mined, or the same height flipped from normal to final work. One verdict
// normally drops one batch; threads racing on the same batch may each count one.
var split_stale_height, split_stale_final uint64

// split_bin: --gpu may name gpu_split_server itself or the full-hash server next to it.
func split_bin(gpuBin string) string {
	if filepath.Base(gpuBin) == "gpu_split_server" {
		return gpuBin
	}
	return filepath.Join(filepath.Dir(gpuBin), "gpu_split_server")
}

func parse_split_geom(s string) ([3]int, error) {
	g := split_geom
	if s == "" {
		return g, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return g, fmt.Errorf("want batch,depth,inflight")
	}
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 1 {
			return g, fmt.Errorf("bad %q", p)
		}
		g[i] = v
	}
	if g[0]%2 != 0 || g[1] < 2 || g[2] > 16 {
		return g, fmt.Errorf("batch must be even, depth >= 2, inflight <= 16")
	}
	return g, nil
}

// split_next cuts work for the GPU from the current job (nil while there is no valid job).
func split_next(random_buf *[12]byte) (gsplit.Work, bool) {
	mutex.RLock()
	myjob := job
	jc := job_counter
	mutex.RUnlock()
	var w gsplit.Work
	if !decode_job_blob(&w.Blob, myjob.Blockhashing_blob) || w.Blob[0]&0xf != 1 { // r21: no panic on a long blob
		return w, false
	}
	copy(w.Blob[block.MINIBLOCK_SIZE-12:], random_buf[:])
	w.Blob[block.MINIBLOCK_SIZE-1] = split_marker
	sj := &splitJob{job: myjob, counter: jc}
	if _, ok := sj.diff.SetString(myjob.Difficulty, 10); !ok || sj.diff.Sign() <= 0 { // r22: 0 would panic per hash
		return w, false
	}
	sj.tgt = newPowTarget(&sj.diff)
	w.Tag = sj
	return w, true
}

// split_stale: drop the unclaimed nonces of a batch when every share they could produce is an orphan: its height is
// finished (a newer height is being mined), or the daemon flipped the same height from normal to final work, i.e. it
// already holds the 9 normal miniblocks a block can carry (blockchain/miner_block.go:337-339 keeps the first 9 that
// arrived). The second case is r21 forensics: r20 only dropped on a new height, so after every normal->final flip the
// CPU threads (the binding resource since r20) still sorted the whole ring of normal texts. All 5 likely_stale split
// shares in the r19+r20 miner log (heights 7822908, 7823273, 7823288, 7823608, 7823691) were orphaned (slots_full).
// Template refreshes at the same height keep their staged work (mineblock_gpu also submits it). The verdict is
// shareLikelyStale, the same rule the share accounting uses; a job found fresh at a job_counter is not re-checked
// (no global lock per pair) until the next job arrives.
func split_stale(tag interface{}) bool { return split_stale_verdict(tag, true) }

// split_stale_quiet is split_stale without the reason counters (r22 merge, splitpipe SP22-3 review fix): the engine's
// finish() re-checks a batch before its GPU SHA, and that second look at an already-counted event must not count
// again (split_stale_height/final keep their r21 meaning: one verdict per drop).
func split_stale_quiet(tag interface{}) bool { return split_stale_verdict(tag, false) }

func split_stale_verdict(tag interface{}, count bool) bool {
	sj := tag.(*splitJob)
	if jc := atomic.LoadInt64(&job_counter); jc == sj.counter || jc == atomic.LoadInt64(&sj.fresh) {
		return false
	}
	mutex.RLock()
	cur := job
	jc := atomic.LoadInt64(&job_counter) // job and job_counter change together under mutex
	mutex.RUnlock()
	if !shareLikelyStale(sj.job, cur) {
		atomic.StoreInt64(&sj.fresh, jc)
		return false
	}
	if !count {
		return true
	}
	if cur.Height != sj.job.Height {
		atomic.AddUint64(&split_stale_height, 1)
	} else {
		atomic.AddUint64(&split_stale_final, 1)
	}
	return true
}

// split_found checks one split hash against its job's difficulty; a win is re-hashed on the CPU, then submitted.
func split_found(tag interface{}, blob []byte, h [32]byte) {
	sj := tag.(*splitJob)
	if !sj.meets(h) { // CheckPowHashBig's verdict (powtarget.go); a win is re-checked with it below
		return
	}
	if cpu := astrobwtv3.AstroBWTv3(blob); cpu != h || !CheckPowHashBig(cpu, &sj.diff) {
		atomic.AddUint64(&gpu_mismatch, 1)
		logger.Error(nil, "split hash disagrees with the CPU; not submitting", "split", fmt.Sprintf("%x", h), "cpu", fmt.Sprintf("%x", cpu))
		if e := current_split(); e != nil {
			e.Disable("a winning split hash disagreed with the CPU re-hash")
		}
		return
	}
	atomic.AddUint64(&gpu_minis, 1)
	mutex.RLock()
	cur := job
	mutex.RUnlock()
	stale := shareLikelyStale(sj.job, cur)
	if stale {
		atomic.AddUint64(&gpu_stale, 1)
	}
	logger.V(1).Info("GPU-split found DERO miniblock (submitting)", "difficulty", sj.job.Difficulty, "height", sj.job.Height, "likely_stale", stale)
	submitShare(sj.job.JobID, fmt.Sprintf("%x", blob), 'G')
}

// start_gpu_split starts split mode and runs its self-test; it must run before the mining threads start (the
// reference hashes switch astrobwtv3.SuffixSort off, as install_pair_hash does). false: use --gpu-mode=full.
func start_gpu_split(gpuBin string) bool {
	if atomic.LoadInt32(&pair_enabled) != 1 {
		logger.Error(nil, "gpu split mode needs paired hashing (--pair=auto with SHA instructions); using --gpu-mode=full")
		return false
	}
	g, err := parse_split_geom(os.Getenv("DERO_GSPLIT"))
	if err != nil {
		logger.Error(err, "DERO_GSPLIT ignored")
		g = split_geom
	}
	sortOn, sg, err := parse_split_sort(os.Getenv("DERO_GSPLIT_SORT"))
	if err != nil {
		logger.Error(err, "DERO_GSPLIT_SORT ignored (GPU sort off)")
		sortOn = false
	}
	probe, err := parse_split_sort_probe(os.Getenv("DERO_GSPLIT_SORT_PROBE"))
	if err != nil {
		logger.Error(err, "DERO_GSPLIT_SORT_PROBE ignored (default probe)")
	}
	var random_buf [12]byte
	rand.Read(random_buf[:])
	bin := split_bin(gpuBin)
	check_gpu_binary(bin)
	e, err := gsplit.New(gsplit.Config{Bin: bin, Batch: g[0], Depth: g[1], Inflight: g[2], GPUSHA: true, GPUMax: gpu_duty_pct(),
		AuditEvery: 4096,
		GPUSort:    sortOn, SortLanes: sg[0], SortChunk: sg[1], SortInflight: sg[2], SortMinReady: sg[3],
		SortProbe: probe, ProbeCount: split_total, Counted: split_count, // the miner's TOTAL counter, incl. GPU-sorted hashes
		Next:       func() (gsplit.Work, bool) { return split_next(&random_buf) },
		Stale:      split_stale,
		StaleQuiet: split_stale_quiet, // finish()'s pre-SHA re-check: not a new drop, not counted (r22 merge)
		Found:      split_found,
		Reference: func(blob []byte) [32]byte {
			return astrobwtv3.AstroBWTv3(blob) // the self-test overrides this with the consensus path (below)
		},
		Logf: func(f string, a ...interface{}) { logger.Error(nil, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		logger.Error(err, "gpu split mode cannot start; using --gpu-mode=full", "bin", bin)
		return false
	}
	hook := astrobwtv3.SuffixSort
	astrobwtv3.SuffixSort = nil // self-test references on the consensus code path, exactly as derod verifies
	err = e.SelfTest(256, astropair.NewScratch())
	astrobwtv3.SuffixSort = hook
	if err != nil {
		logger.Error(err, "gpu split self-test FAILED; using --gpu-mode=full (would submit rejected shares)")
		e.Close()
		return false
	}
	atomic.StorePointer(&split_engine, unsafe.Pointer(e))
	e.Start()
	logger.Info("GPU split mode ACTIVE — self-test passed on 256 nonces (bit-exact AstroBWTv3)", "batch", g[0], "depth", g[1], "inflight", g[2], "bin", bin,
		"gpu_sort", split_sort_status(e, sortOn))
	go report_split(e)
	return true
}

func split_sort_status(e *gsplit.Engine, configured bool) string {
	if !configured {
		return "off"
	}
	if e.Sorting() {
		return "on"
	}
	return "disabled: " + e.Stats().SortOff
}

func report_split(e *gsplit.Engine) {
	var last gsplit.Stats
	t0 := time.Now()
	for range time.Tick(60 * time.Second) {
		s := e.Stats()
		el := time.Since(t0).Seconds()
		t0 = time.Now()
		logger.Info("GPU split", split_fields(s, last, el)...)
		last = s
		if s.Disabled != "" {
			return
		}
	}
}

// split_count adds hashes the split engine finished entirely on the GPU (GPU-sorted batches: no TryWork returns them)
// to the miner's TOTAL counter; split_total reads that counter for the GPU-sort A/B probe (r21 merge, gpusort-4 fix).
func split_count(n int) { atomic.AddUint64(&counter, uint64(n)) }

func split_total() uint64 { return atomic.LoadUint64(&counter) }

// split_fields builds the 'GPU split' log line for one window of el seconds. cpu_idle_tries (TryWork found nothing
// staged: GPU-bound), feeder_ring_full_ms (the feeder waited on a full ring, which with GPU SHA also happens while every
// batch is on the GPU) and feeder_cpu_backlog_ms (the part of that wait during which staged texts were waiting for the
// CPU threads: CPU-bound, r20) are per-window regime signals. dropped_stale, cpu_finished and audited are cumulative,
// as are stale_drops_height and stale_drops_final (split_stale verdicts by reason, r21).
//
// gpu_us_per_hash is the SUM of the command buffers' spans per hash (overlapping op 1/op 2 buffers count twice, r20
// gpukernels-8); gpu_busy_us_per_hash and gpu_busy_pct (r21) are the wall-clock union the --gpu-max debt is charged on:
// gpu_busy_pct is the GPU's real duty in the window, so 100 - gpu_busy_pct is its headroom.
//
// r22: gpu_max is the GPU duty cap in force (the tuner may move it); feeder_throttle_ms is how long the feeder slept
// paying the --gpu-max duty bucket in the window (r22 merge: the bucket charges busy*100/cap and credits wall time, so
// the realised duty holds the cap up to the work already queued; gsplit/duty.go); collect_ms is the reply loop's time
// reporting GPU-SHA hashes (a ring slot is freed only after it); stale_sha_skipped (cumulative) counts hashes whose
// GPU SHA was skipped because their job went stale while the batch was being sorted.
// gpu_s1_ms_per_cb and gpu_sha_ms_per_cb (r22 gpukernels) are the window's mean span of one stage-1 (op 1) and one
// final-SHA (op 2) command buffer: the live per-kernel GPU profile, read without touching the GPU. Each buffer carries
// one batch, so with the GPU latency-bound the staged rate is about batch x buffers in flight / (s1 + sha span).
func split_fields(s, last gsplit.Stats, el float64) []interface{} {
	us, busy := 0.0, 0.0
	if d := s.Hashed - last.Hashed; d > 0 {
		us = float64(s.GPUus-last.GPUus) / float64(d)
		busy = float64(s.GPUBusyUs-last.GPUBusyUs) / float64(d)
	}
	s1ms, shams := 0.0, 0.0
	if d := s.S1Cmds - last.S1Cmds; d > 0 {
		s1ms = float64(s.S1us-last.S1us) / float64(d) / 1000
	}
	if d := s.SHACmds - last.SHACmds; d > 0 {
		shams = float64(s.SHAus-last.SHAus) / float64(d) / 1000
	}
	if el <= 0 {
		el = 1
	}
	return []interface{}{"staged_H/s", fmt.Sprintf("%.0f", float64(s.Hashed-last.Hashed)/el), "dropped_stale", s.Dropped,
		"cpu_finished", s.CPUFinished, "audited", s.Audited, "gpu_us_per_hash", fmt.Sprintf("%.1f", us),
		"gpu_busy_us_per_hash", fmt.Sprintf("%.1f", busy), "gpu_busy_pct", fmt.Sprintf("%.1f", float64(s.GPUBusyUs-last.GPUBusyUs)/(el*1e4)),
		"gpu_s1_ms_per_cb", fmt.Sprintf("%.1f", s1ms), "gpu_sha_ms_per_cb", fmt.Sprintf("%.1f", shams),
		"cpu_idle_tries", s.IdleTries - last.IdleTries, "feeder_ring_full_ms", (s.FeedWaitUs - last.FeedWaitUs) / 1000,
		"feeder_cpu_backlog_ms", (s.FeedWaitBacklogUs - last.FeedWaitBacklogUs) / 1000,
		"stale_drops_height", atomic.LoadUint64(&split_stale_height), "stale_drops_final", atomic.LoadUint64(&split_stale_final),
		"gpu_cpu_mismatch", atomic.LoadUint64(&gpu_mismatch), "restarts", s.Restarts, "audit_faults", s.AuditFaults, "disabled", s.Disabled, "cpu", fast_sort_status(),
		"gpu_sorted_H/s", fmt.Sprintf("%.0f", float64(s.GPUSorted-last.GPUSorted)/el), "gpu_sort_fails", s.SortFails, "gpu_sort_off", s.SortOff,
		"gpu_sort_probe", s.SortProbe,
		"gpu_max", s.GPUMax, "feeder_throttle_ms", (s.ThrottleUs - last.ThrottleUs) / 1000, "collect_ms", (s.CollectUs - last.CollectUs) / 1000,
		"stale_sha_skipped", s.StaleSHASkipped}
}
