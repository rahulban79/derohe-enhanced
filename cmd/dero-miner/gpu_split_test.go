package main

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
	"github.com/deroproject/derohe/rpc"
)

func TestParseSplitGeom(t *testing.T) {
	if g, err := parse_split_geom(""); err != nil || g != split_geom {
		t.Fatal("default")
	}
	if g, err := parse_split_geom("4096, 4,2"); err != nil || g != [3]int{4096, 4, 2} {
		t.Fatal(g, err)
	}
	for _, bad := range []string{"3,4,2", "2048,1,2", "2048,6,17", "2048,6", "a,b,c", "2048,0,3"} {
		if _, err := parse_split_geom(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if split_bin("gpu-miner-poc/gpu_hash_sais") != "gpu-miner-poc/gpu_split_server" || split_bin("x/gpu_split_server") != "x/gpu_split_server" {
		t.Fatal("split_bin")
	}
}

func setJob(t *testing.T, h uint64, blob []byte, diff string) {
	t.Helper()
	mutex.Lock()
	job = rpc.GetBlockTemplate_Result{Height: h, Blockhashing_blob: hex.EncodeToString(blob), Difficulty: diff, JobID: "j"}
	mutex.Unlock()
	atomic.AddInt64(&job_counter, 1)
}

func TestSplitNextAndStale(t *testing.T) {
	blob := make([]byte, 48)
	for i := range blob {
		blob[i] = byte(i + 1)
	}
	blob[0] = 0x41
	setJob(t, 10, blob, "1000")
	var rb = [12]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	w, ok := split_next(&rb)
	if !ok || w.Blob[47] != split_marker || w.Blob[36] != 9 || w.Blob[0] != 0x41 || w.Blob[35] != blob[35] {
		t.Fatalf("split_next: ok=%v blob=%x", ok, w.Blob)
	}
	if split_stale(w.Tag) {
		t.Fatal("fresh job stale")
	}
	setJob(t, 10, blob, "1000") // template refresh at the same height: keep the staged work
	if split_stale(w.Tag) {
		t.Fatal("same-height refresh treated as stale")
	}
	setJob(t, 11, blob, "1000")
	if !split_stale(w.Tag) {
		t.Fatal("older height not stale")
	}
	bad := append([]byte(nil), blob...)
	bad[0] = 0x42 // version 2
	setJob(t, 12, bad, "1000")
	if _, ok := split_next(&rb); ok {
		t.Fatal("unknown version accepted")
	}
	setJob(t, 12, blob, "not-a-number")
	if _, ok := split_next(&rb); ok {
		t.Fatal("bad difficulty accepted")
	}
}

// A winning split hash is submitted only when the CPU re-hash agrees; a disagreeing one is counted and dropped.
func TestSplitFoundGuards(t *testing.T) {
	blob := make([]byte, 48)
	blob[0] = 0x41
	h := astrobwtv3.AstroBWTv3(blob)
	sj := &splitJob{}
	sj.diff.SetInt64(1) // every hash wins
	m0, g0 := atomic.LoadUint64(&gpu_mismatch), atomic.LoadUint64(&gpu_minis)
	split_found(sj, blob, h)
	if atomic.LoadUint64(&gpu_minis) != g0+1 || atomic.LoadUint64(&gpu_mismatch) != m0 {
		t.Fatal("correct win not counted")
	}
	wrong := h
	wrong[31] ^= 1
	split_found(sj, blob, wrong)
	if atomic.LoadUint64(&gpu_minis) != g0+1 || atomic.LoadUint64(&gpu_mismatch) != m0+1 {
		t.Fatal("disagreeing win was not rejected")
	}
	hard := &splitJob{}
	hard.diff.Set(new(big.Int).Lsh(big.NewInt(1), 255))
	split_found(hard, blob, wrong) // not a win: no re-hash, nothing counted
	if atomic.LoadUint64(&gpu_mismatch) != m0+1 {
		t.Fatal("non-win re-hashed")
	}
}

// r19 splitcpu-2: the 'GPU split' line carries per-window regime counters.
func TestSplitFieldsRegimeSignal(t *testing.T) {
	last := gsplit.Stats{Hashed: 100, IdleTries: 10, FeedWaitUs: 1000, FeedWaitBacklogUs: 3000, GPUus: 1000, GPUBusyUs: 500}
	s := gsplit.Stats{Hashed: 700, IdleTries: 25, FeedWaitUs: 51000, FeedWaitBacklogUs: 10000, GPUus: 13000, GPUBusyUs: 30000500}
	f := split_fields(s, last, 60)
	got := map[string]interface{}{}
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = f[i+1]
	}
	if got["cpu_idle_tries"] != uint64(15) || got["feeder_ring_full_ms"] != uint64(50) || got["staged_H/s"] != "10" ||
		got["feeder_cpu_backlog_ms"] != uint64(7) || got["gpu_us_per_hash"] != "20.0" || got["gpu_busy_us_per_hash"] != "50000.0" ||
		got["gpu_busy_pct"] != "50.0" {
		t.Fatalf("regime fields wrong: %v", got)
	}
}

// r21 forensics: after the daemon flips a height from normal to final work (it holds the 9 normal miniblocks a block
// can carry), staged texts cut from the normal job are dropped instead of sorted; final-job texts and same-height
// refreshes are kept, and the verdicts are counted by reason.
func TestSplitStaleDropsNormalAfterFinalFlip(t *testing.T) {
	normal := make([]byte, 48)
	normal[0] = 0x41 // version 1, no flags
	final := append([]byte(nil), normal...)
	final[0] = 0x71 // + HighDiff(0x10) + Final(0x20)
	var rb [12]byte
	h0, f0 := atomic.LoadUint64(&split_stale_height), atomic.LoadUint64(&split_stale_final)

	setJob(t, 20, normal, "1000")
	wn, ok := split_next(&rb)
	if !ok {
		t.Fatal("split_next normal")
	}
	sn := wn.Tag.(*splitJob)
	setJob(t, 20, normal, "1000") // same-height normal refresh: keep, and remember the verdict for this job_counter
	if split_stale(wn.Tag) {
		t.Fatal("same-height normal refresh treated as stale")
	}
	if atomic.LoadInt64(&sn.fresh) != atomic.LoadInt64(&job_counter) {
		t.Fatal("fresh verdict not memoised at the current job_counter")
	}
	if split_stale(wn.Tag) { // memo path
		t.Fatal("memoised verdict flipped")
	}

	setJob(t, 20, final, "9000") // the daemon now wants the final miniblock of height 20
	if !split_stale(wn.Tag) {
		t.Fatal("normal texts kept after the normal->final flip (every share would be orphaned slots_full)")
	}
	if atomic.LoadUint64(&split_stale_final) != f0+1 || atomic.LoadUint64(&split_stale_height) != h0 {
		t.Fatalf("reason counters: final %d->%d height %d->%d", f0, atomic.LoadUint64(&split_stale_final), h0, atomic.LoadUint64(&split_stale_height))
	}

	wf, ok := split_next(&rb)
	if !ok {
		t.Fatal("split_next final")
	}
	setJob(t, 20, final, "9000") // final refresh at the same height: keep
	if split_stale(wf.Tag) {
		t.Fatal("final texts dropped on a same-height final refresh")
	}

	setJob(t, 21, normal, "1000") // block 20 exists: both are stale, counted as height
	if !split_stale(wf.Tag) || !split_stale(wn.Tag) {
		t.Fatal("older height not stale")
	}
	if atomic.LoadUint64(&split_stale_height) != h0+2 || atomic.LoadUint64(&split_stale_final) != f0+1 {
		t.Fatal("height verdicts not counted by reason")
	}
	f := split_fields(gsplit.Stats{}, gsplit.Stats{}, 60)
	got := map[string]interface{}{}
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = f[i+1]
	}
	if got["stale_drops_final"] != atomic.LoadUint64(&split_stale_final) || got["stale_drops_height"] != atomic.LoadUint64(&split_stale_height) {
		t.Fatalf("log line lacks the reason counters: %v", got)
	}
}

func TestParseSplitSort(t *testing.T) {
	for _, off := range []string{"", "0", " "} {
		if on, _, err := parse_split_sort(off); on || err != nil {
			t.Fatalf("%q: on=%v err=%v", off, on, err)
		}
	}
	if on, g, err := parse_split_sort("1"); !on || err != nil || g != split_sort_default {
		t.Fatal("1", g, err)
	}
	if on, g, err := parse_split_sort("3, 64,2,2"); !on || err != nil || g != [4]int{3, 64, 2, 2} {
		t.Fatal(g, err)
	}
	for _, bad := range []string{"2,32,1", "9,32,1,1", "2,4,1,1", "2,513,1,1", "2,32,0,1", "a,b,c,d"} {
		if on, _, err := parse_split_sort(bad); on || err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseSplitSortProbe(t *testing.T) {
	if d, err := parse_split_sort_probe(""); err != nil || d != split_sort_probe_default {
		t.Fatal(d, err)
	}
	if d, err := parse_split_sort_probe(" 0 "); err != nil || d != 0 {
		t.Fatal(d, err)
	}
	if d, err := parse_split_sort_probe("90"); err != nil || d != 90*time.Second {
		t.Fatal(d, err)
	}
	for _, bad := range []string{"-1", "x", "3601"} {
		if d, err := parse_split_sort_probe(bad); err == nil || d != split_sort_probe_default {
			t.Fatalf("%q accepted (%v)", bad, d)
		}
	}
}

// r21 merge (gpusort-4 fix): GPU-sorted hashes reach the miner's TOTAL counter (display, /metrics, the sort probe).
func TestSplitCountsGPUSortedHashes(t *testing.T) {
	c0 := split_total()
	split_count(7)
	if split_total() != c0+7 || atomic.LoadUint64(&counter) != c0+7 {
		t.Fatal("split_count does not add to the TOTAL counter")
	}
	atomic.AddUint64(&counter, ^uint64(6)) // undo
	src, err := os.ReadFile("gpu_split.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "ProbeCount: split_total, Counted: split_count,") {
		t.Fatal("start_gpu_split does not wire Counted/ProbeCount to the TOTAL counter")
	}
}

// r22 merge (splitpipe SP22-3 review fix): the engine's finish() re-check uses split_stale_quiet, which gives the same
// verdict as split_stale but leaves split_stale_height/final alone, so a dropped batch that reaches finish() is counted
// once (the r21 meaning: one verdict per drop).
func TestSplitStaleQuietDoesNotCount(t *testing.T) {
	blob := make([]byte, 48)
	blob[0] = 0x41
	var rb [12]byte
	setJob(t, 30, blob, "1000")
	w, ok := split_next(&rb)
	if !ok {
		t.Fatal("split_next")
	}
	setJob(t, 31, blob, "1000") // a new height: the staged work is stale
	h0, f0 := atomic.LoadUint64(&split_stale_height), atomic.LoadUint64(&split_stale_final)
	if !split_stale(w.Tag) { // TryWork's verdict: drops the batch, counted once
		t.Fatal("older height not stale")
	}
	if !split_stale_quiet(w.Tag) || !split_stale_quiet(w.Tag) { // finish()'s re-checks
		t.Fatal("quiet verdict differs from split_stale")
	}
	if h := atomic.LoadUint64(&split_stale_height); h != h0+1 || atomic.LoadUint64(&split_stale_final) != f0 {
		t.Fatalf("stale_height %d -> %d after one drop and two quiet re-checks, want +1", h0, h)
	}
	src, err := os.ReadFile("gpu_split.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "StaleQuiet: split_stale_quiet,") {
		t.Fatal("start_gpu_split does not hand split_stale_quiet to the engine")
	}
}

// r22 gpukernels: the 'GPU split' line carries the window's mean stage-1 and final-SHA command-buffer spans (the live
// per-kernel profile); a window without buffers of a kind reports 0, never a division by zero.
func TestSplitFieldsPerKernelSpans(t *testing.T) {
	last := gsplit.Stats{Hashed: 100, S1us: 1000, S1Cmds: 1, SHAus: 2000, SHACmds: 1}
	s := gsplit.Stats{Hashed: 8292, S1us: 1000 + 2*30500, S1Cmds: 3, SHAus: 2000 + 2*41250, SHACmds: 3}
	got := map[string]interface{}{}
	f := split_fields(s, last, 60)
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = f[i+1]
	}
	if got["gpu_s1_ms_per_cb"] != "30.5" || got["gpu_sha_ms_per_cb"] != "41.2" {
		t.Fatalf("per-kernel spans: s1 %v sha %v", got["gpu_s1_ms_per_cb"], got["gpu_sha_ms_per_cb"])
	}
	f = split_fields(s, s, 60)
	got = map[string]interface{}{}
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = f[i+1]
	}
	if got["gpu_s1_ms_per_cb"] != "0.0" || got["gpu_sha_ms_per_cb"] != "0.0" {
		t.Fatalf("empty window: s1 %v sha %v", got["gpu_s1_ms_per_cb"], got["gpu_sha_ms_per_cb"])
	}
}
