package main

// Round 30 quiet-window instruments (rft §7 B25, B236 (a), B237, L-C2; harness/pipeline/quiet_window.py runs them
// under benchlock --heavy with the live miner stopped). Each is env-gated and SKIPS in the pipeline: a bench on a
// busy box is not evidence (rft §5). They print one machine-readable line per arm/window, prefixed R30SORTRATE /
// R30DSAPROF, which the runner parses into harness/runtime/r30_ceiling_*.json records.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/dsac"
)

func r30env(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return d
}

// r30_sort_window sorts staged texts on T threads for win and returns one record: sorts, wall, CPU (P/E split).
func r30_sort_window(T int, win time.Duration, texts [][][]byte, arm string) map[string]interface{} {
	var stop int32
	var n atomic.Int64
	var wg sync.WaitGroup
	pe0 := pe_now()
	c0 := process_cpu_time()
	t0 := time.Now()
	for w := 0; w < T; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			runtime.LockOSThread()
			threadaffinity()
			sa := make([]int32, 256*384)
			k := 0
			for atomic.LoadInt32(&stop) == 0 {
				tx := texts[w][k%len(texts[w])]
				if astropair.SortOnly(tx, sa) {
					n.Add(1)
				}
				k++
			}
		}(w)
	}
	time.Sleep(win)
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
	wall := time.Since(t0).Seconds()
	cpu := (process_cpu_time() - c0).Seconds()
	pe1 := pe_now()
	rec := map[string]interface{}{"arm": arm, "threads": T, "sorts": n.Load(), "wall_s": wall, "cpu_s": cpu,
		"sorts_per_s": float64(n.Load()) / wall, "merge_variant": dsac.MergeVariant(), "qos": cpu_qos}
	if cpu > 0 {
		rec["sorts_per_cpu_s"] = float64(n.Load()) / cpu
	}
	if pe0.ok && pe1.ok && pe1.total > pe0.total {
		dp, dt := (pe1.p - pe0.p).Seconds(), (pe1.total - pe0.total).Seconds()
		rec["p_cpu_s"], rec["e_cpu_s"], rec["p_frac"] = dp, dt-dp, dp/dt
	}
	return rec
}

// TestR30SortRateBench (DERO_SORTRATE_BENCH=1): the split CPU sort's capacity. Env: DERO_SORTRATE_T threads (default
// all cores), DERO_SORTRATE_WIN seconds per window (default 20), DERO_SORTRATE_ROUNDS (default 3), DERO_SORTRATE_ARMS
// (default "r29"; "r29,bf" = the L-C2 merge ABBA: the arm order alternates A B B A ... so each arm takes each position
// equally often). Under `taskpolicy -b` with T=4 it is the B25 pinned E-core bench: the record's p_frac (proc_pid_rusage
// v6) says whether it really ran on the E-cores (the R23 QOS_BACKGROUND run never could). One line per window:
// R30SORTRATE {json}.
func TestR30SortRateBench(t *testing.T) {
	if os.Getenv("DERO_SORTRATE_BENCH") != "1" {
		t.Skip("set DERO_SORTRATE_BENCH=1 (quiet window only: harness/pipeline/quiet_window.py)")
	}
	T, win, rounds := r30env("DERO_SORTRATE_T", runtime.NumCPU()), time.Duration(r30env("DERO_SORTRATE_WIN", 20))*time.Second, r30env("DERO_SORTRATE_ROUNDS", 3)
	arms := strings.Split(os.Getenv("DERO_SORTRATE_ARMS"), ",")
	if arms[0] == "" {
		arms = []string{"r29"}
	}
	defer dsac.SetMergeVariant(dsac.MergeVariant())
	reset_fast_sort(t)
	oldPair := astropair.SuffixSort
	t.Cleanup(func() { astropair.SuffixSort = oldPair })
	install_fast_sort("auto")
	install_pair_hash("auto")
	if astropair.SuffixSort == nil {
		t.Fatal("no descriptor sort on this build: the bench would measure SA-IS")
	}
	texts := make([][][]byte, T)
	for i := range texts {
		_, texts[i] = split_bench_inputs(split_bench_texts)
	}
	for r := 0; r < rounds; r++ {
		order := append([]string(nil), arms...)
		if r%2 == 1 { // ABBA: reverse every other round
			for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
				order[i], order[j] = order[j], order[i]
			}
		}
		for _, a := range order {
			env := map[string]string{"DERO_DSA_MERGE": a}
			apply_merge_variant(func(k string) string { return env[k] })
			rec := r30_sort_window(T, win, texts, a)
			rec["round"] = r
			b, _ := json.Marshal(rec)
			fmt.Printf("R30SORTRATE %s\n", b)
		}
	}
}

const r30ProfMain = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <mach/mach_time.h>
#include DSA_SRC
static uint8_t* g_buf; static size_t g_len; static int g_reps;
typedef struct { unsigned long long prof[6]; int texts, fails; } Out;
static void* work(void* arg) {
    Out* o = (Out*)arg;
    int32_t* sa = malloc(sizeof(int32_t) * 256 * 384);
    for (int r = 0; r < g_reps; r++)
        for (size_t p = 0; p + 4 <= g_len;) {
            uint32_t n; memcpy(&n, g_buf + p, 4); p += 4;
            if (dsa_descriptor_suffix_array(g_buf + p, sa, (int32_t)n)) o->fails++;
            p += n; o->texts++;
        }
    memcpy(o->prof, dsa_prof, sizeof o->prof);
    free(sa);
    return NULL;
}
int main(int argc, char** argv) {
    int T = atoi(argv[2]); g_reps = atoi(argv[3]); dsa_set_merge_variant(atoi(argv[4]));
    FILE* f = fopen(argv[1], "rb"); if (!f) return 2;
    g_buf = malloc(1 << 26); g_len = fread(g_buf, 1, 1 << 26, f); fclose(f);
    pthread_t th[64]; Out o[64]; memset(o, 0, sizeof o);
    unsigned long long w0 = mach_absolute_time();
    for (int i = 0; i < T; i++) pthread_create(&th[i], NULL, work, &o[i]);
    for (int i = 0; i < T; i++) pthread_join(th[i], NULL);
    unsigned long long w1 = mach_absolute_time();
    unsigned long long s[6] = {0}; int texts = 0, fails = 0;
    for (int i = 0; i < T; i++) { for (int k = 0; k < 6; k++) s[k] += o[i].prof[k]; texts += o[i].texts; fails += o[i].fails; }
    printf("%d %d %d %llu %llu %llu %llu %llu %llu %llu\n", T, texts, fails, w1 - w0, s[0], s[1], s[2], s[3], s[4], s[5]);
    return 0;
}
`

// r30_prof_shares turns the summed phase ticks into shares of the profiled total (runs, walk, radix, merge, tail;
// coll is nested inside merge). Pure, so the KAT can feed it numbers.
func r30_prof_shares(v []uint64) map[string]float64 {
	names := []string{"runs", "walk", "radix", "merge", "tail"}
	var tot uint64
	for i := range names {
		tot += v[i]
	}
	out := map[string]float64{}
	if tot == 0 {
		return out
	}
	for i, n := range names {
		out[n] = float64(v[i]) / float64(tot)
	}
	out["coll_in_merge"] = 0
	if v[3] > 0 {
		out["coll_in_merge"] = float64(v[5]) / float64(v[3])
	}
	return out
}

// TestR30DSAProfile (DERO_DSAPROF_BENCH=1; rft §7 B237, L-C14): the per-phase profile of the r29+ descriptor sort at
// DERO_DSAPROF_T threads (default "1,15"), DSA_PROF built with per-thread counters (DSA_PROF_TLS=__thread), on
// DERO_DSAPROF_TEXTS real stage-1 texts (default 256) x DERO_DSAPROF_REPS (default 8), merge variant
// DERO_DSAPROF_MERGE (0|1). One line per thread count: R30DSAPROF {json} with the phase shares; B237's rule is to try
// the merge variant only if merge >= 35 % of the sort.
func TestR30DSAProfile(t *testing.T) {
	if os.Getenv("DERO_DSAPROF_BENCH") != "1" {
		t.Skip("set DERO_DSAPROF_BENCH=1 (quiet window only: harness/pipeline/quiet_window.py)")
	}
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("clang not on PATH")
	}
	src, _ := filepath.Abs(filepath.Join("dsac", "descriptor.c"))
	dir := t.TempDir()
	_, texts := split_bench_inputs(r30env("DERO_DSAPROF_TEXTS", 256))
	var buf []byte
	for _, tx := range texts {
		buf = append(buf, byte(len(tx)), byte(len(tx)>>8), byte(len(tx)>>16), byte(len(tx)>>24))
		buf = append(buf, tx...)
	}
	corpus := filepath.Join(dir, "corpus.bin")
	if err := os.WriteFile(corpus, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	mainC := filepath.Join(dir, "prof_main.c")
	os.WriteFile(mainC, []byte(r30ProfMain), 0o600)
	bin := filepath.Join(dir, "prof")
	cmd := exec.Command(cc, "-O3", "-mcpu=apple-m1", "-Wno-c23-extensions", "-DDSA_PROF", "-DDSA_PROF_TLS=__thread",
		`-DDSA_SRC="`+src+`"`, "-I", filepath.Dir(src), mainC, "-o", bin, "-lpthread")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("DSA_PROF build failed: %v\n%s", err, out)
	}
	tl := os.Getenv("DERO_DSAPROF_T")
	if tl == "" {
		tl = "1,15"
	}
	merge := os.Getenv("DERO_DSAPROF_MERGE")
	if merge == "" {
		merge = "0"
	}
	for _, ts := range strings.Split(tl, ",") {
		out, err := exec.Command(bin, corpus, ts, strconv.Itoa(r30env("DERO_DSAPROF_REPS", 8)), merge).Output()
		if err != nil {
			t.Fatalf("DSA_PROF run (T=%s) failed: %v", ts, err)
		}
		f := strings.Fields(string(out))
		if len(f) != 10 {
			t.Fatalf("unexpected output %q", out)
		}
		v := make([]uint64, len(f))
		for i := range f {
			v[i], _ = strconv.ParseUint(f[i], 10, 64)
		}
		rec := map[string]interface{}{"threads": v[0], "texts": v[1], "fails": v[2], "wall_ticks": v[3],
			"ticks": v[4:10], "shares": r30_prof_shares(v[4:10]), "merge_variant": merge, "tick_hz": 24000000}
		if v[1] > 0 && v[3] > 0 {
			rec["texts_per_s"] = float64(v[1]) / (float64(v[3]) / 24e6)
		}
		b, _ := json.Marshal(rec)
		fmt.Printf("R30DSAPROF %s\n", b)
	}
}

// r30 L-C2: the miner's merge switch is OFF unless DERO_DSA_MERGE=bf says so; anything else keeps the r29 merge.
func TestR30MergeVariantDefaultOff(t *testing.T) {
	defer dsac.SetMergeVariant(dsac.MergeVariant())
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if l := apply_merge_variant(get); dsac.MergeVariant() != 0 || l != "r29" {
		t.Fatalf("unset: variant %d label %q, want 0 r29", dsac.MergeVariant(), l)
	}
	env["DERO_DSA_MERGE"] = "fast"
	if l := apply_merge_variant(get); dsac.MergeVariant() != 0 || !strings.Contains(l, "ignored") {
		t.Fatalf("garbage: variant %d label %q", dsac.MergeVariant(), l)
	}
	env["DERO_DSA_MERGE"] = "bf"
	l := apply_merge_variant(get)
	if dsac.Available && (dsac.MergeVariant() != 1 || !strings.Contains(l, "unmeasured")) {
		t.Fatalf("bf: variant %d label %q", dsac.MergeVariant(), l)
	}
	env["DERO_DSA_MERGE"] = "r29"
	if apply_merge_variant(get); dsac.MergeVariant() != 0 {
		t.Fatal("r29 did not switch the variant back off")
	}
}

// r30 B237: the profile shares are the phase ticks over the profiled total, coll as a share of merge.
func TestR30ProfShares(t *testing.T) {
	s := r30_prof_shares([]uint64{10, 20, 30, 40, 0, 20})
	if s["merge"] != 0.4 || s["radix"] != 0.3 || s["coll_in_merge"] != 0.5 || s["runs"] != 0.1 {
		t.Fatalf("shares %v", s)
	}
	if len(r30_prof_shares(make([]uint64, 6))) != 0 {
		t.Fatal("an empty profile must give no shares")
	}
}
