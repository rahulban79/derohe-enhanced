package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

// TestQoSContentionAB (DERO_QOS_BENCH=1; darwin): Round 23 contention experiment. Interleaved windows of T threads
// running the split CPU sort (astropair.SortOnly over stage-1 texts) under each --cpu-qos setting; prints sorts per
// wall-second and per CPU-second per arm. Env: DERO_QOS_T (default 4), DERO_QOS_WIN seconds (default 8),
// DERO_QOS_ROUNDS (default 3). Never runs in the pipeline: it competes for the CPU with whatever else runs.
func TestQoSContentionAB(t *testing.T) {
	if os.Getenv("DERO_QOS_BENCH") != "1" {
		t.Skip("set DERO_QOS_BENCH=1")
	}
	geti := func(k string, d int) int {
		if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
			return v
		}
		return d
	}
	T, win, rounds := geti("DERO_QOS_T", 4), time.Duration(geti("DERO_QOS_WIN", 8))*time.Second, geti("DERO_QOS_ROUNDS", 3)
	reset_fast_sort(t)
	oldPair := astropair.SuffixSort
	t.Cleanup(func() { astropair.SuffixSort = oldPair })
	install_fast_sort("auto")
	install_pair_hash("auto")
	if astropair.SuffixSort == nil {
		t.Skip("no descriptor sort on this build")
	}
	inputs := make([][][]byte, T)
	for i := range inputs {
		_, inputs[i] = split_bench_inputs(split_bench_texts)
	}
	arms := []int{0, 2, 1}
	names := map[int]string{0: "default", 1: "initiated", 2: "interactive"}
	wall := map[int][]float64{}
	cpus := map[int][]float64{}
	old := cpu_qos
	defer func() { cpu_qos = old }()
	for r := 0; r < rounds; r++ {
		order := arms
		if r%2 == 1 {
			order = []int{arms[2], arms[1], arms[0]}
		}
		for _, q := range order {
			cpu_qos = q
			var stop int32
			var n int64
			var wg sync.WaitGroup
			c0 := process_cpu_time()
			t0 := time.Now()
			for i := 0; i < T; i++ {
				wg.Add(1)
				go func(texts [][]byte) {
					defer wg.Done()
					lock_mining_thread()
					if should_lock_mining_thread(runtime.GOOS, cpu_qos) {
						defer runtime.UnlockOSThread()
					}
					sa := make([]int32, gsplit.MaxText+1)
					y := new_cgo_yielder()
					k := 0
					for atomic.LoadInt32(&stop) == 0 {
						astropair.SortOnly(texts[k%len(texts)], sa)
						k++
						y.sorted(1)
					}
					atomic.AddInt64(&n, int64(k))
				}(inputs[i])
			}
			time.Sleep(win)
			atomic.StoreInt32(&stop, 1)
			wg.Wait()
			el := time.Since(t0).Seconds()
			cs := (process_cpu_time() - c0).Seconds()
			wall[q] = append(wall[q], float64(n)/el)
			cpus[q] = append(cpus[q], float64(n)/cs)
			fmt.Printf("QOS round %d %-11s T=%d sorts/wall-s %8.0f sorts/cpu-s %6.0f cpu-cores %.2f\n", r, names[q], T, float64(n)/el, float64(n)/cs, cs/el)
		}
	}
	for _, q := range arms {
		fmt.Printf("QOS mean %-11s sorts/wall-s %8.0f sorts/cpu-s %6.0f\n", names[q], meanF(wall[q]), meanF(cpus[q]))
	}
}

func meanF(a []float64) float64 {
	s := 0.0
	for _, x := range a {
		s += x
	}
	if len(a) == 0 {
		return 0
	}
	return s / float64(len(a))
}

// TestDutyContentionAB (DERO_DUTY_BENCH=1): Round 23 A/B of the --cpu-max level on a contended box. Interleaved
// windows of T threads running the split CPU sort with cpu_throttle at each cap of DERO_DUTY_ARMS (default
// 100,90,80); prints sorts per wall-second, CPU cores and the duty sleep per arm. The arm order rotates every round
// so each cap takes every position equally often. r23: a first run favoured 90 over 100, a re-run did not reproduce
// it (ratios 1.017 and 0.926, 4 of 8 pairs): within noise on the contended box.
// r23b: an arm "c<pct>" runs the cap charged on the measured CPU share (cpushare.go: the sampler runs during the arm);
// a plain "<pct>" arm is the r22 wall-clock cap. At load 82-90, 6 threads: 90 = 0.861 of 100 (6 of 6 pairs).
func TestDutyContentionAB(t *testing.T) {
	if os.Getenv("DERO_DUTY_BENCH") != "1" {
		t.Skip("set DERO_DUTY_BENCH=1")
	}
	geti := func(k string, d int) int {
		if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
			return v
		}
		return d
	}
	T, win, rounds := geti("DERO_QOS_T", 4), time.Duration(geti("DERO_QOS_WIN", 8))*time.Second, geti("DERO_QOS_ROUNDS", 3)
	defer set_cpu_duty(set_cpu_duty(90))
	reset_fast_sort(t)
	oldPair := astropair.SuffixSort
	t.Cleanup(func() { astropair.SuffixSort = oldPair })
	install_fast_sort("auto")
	install_pair_hash("auto")
	if astropair.SuffixSort == nil {
		t.Skip("no descriptor sort on this build")
	}
	inputs := make([][][]byte, T)
	for i := range inputs {
		_, inputs[i] = split_bench_inputs(split_bench_texts)
	}
	type arm struct {
		pct   int
		share bool // r23b: charged on the measured CPU share
	}
	name := func(a arm) string {
		if a.share {
			return fmt.Sprintf("c%d", a.pct)
		}
		return fmt.Sprintf("%d", a.pct)
	}
	arms := []arm{{100, false}, {90, false}, {80, false}}
	if v := strings.TrimSpace(os.Getenv("DERO_DUTY_ARMS")); v != "" {
		arms = nil
		for _, f := range strings.Split(v, ",") {
			f = strings.TrimSpace(f)
			c := strings.HasPrefix(f, "c")
			if p, err := strconv.Atoi(strings.TrimPrefix(f, "c")); err == nil && p >= 1 && p <= 100 {
				arms = append(arms, arm{p, c})
			}
		}
	}
	if len(arms) == 0 {
		t.Fatal("DERO_DUTY_ARMS: no valid cap")
	}
	defer atomic.StoreInt64(&cpu_share_milli, 1000)
	wall := map[arm][]float64{}
	for r := 0; r < rounds; r++ {
		order := make([]arm, len(arms)) // rotation: every arm takes every position once per len(arms) rounds
		for i := range arms {
			order[i] = arms[(i+r)%len(arms)]
		}
		for _, a := range order {
			pct := a.pct
			set_cpu_duty(pct)
			atomic.StoreInt64(&cpu_share_milli, 1000)
			var quit chan struct{}
			if a.share {
				quit = make(chan struct{})
				go cpu_share_sampler(T, cpu_share_period, quit, time.Now, process_cpu_time)
			}
			time.Sleep(time.Second)
			var stop int32
			var n int64
			var wg sync.WaitGroup
			c0, s0 := process_cpu_time(), atomic.LoadInt64(&cpu_throttle_sleep_ns)
			t0 := time.Now()
			for i := 0; i < T; i++ {
				wg.Add(1)
				go func(texts [][]byte) {
					defer wg.Done()
					sa := make([]int32, gsplit.MaxText+1)
					y := new_cgo_yielder()
					k := 0
					ts := time.Now()
					for atomic.LoadInt32(&stop) == 0 {
						astropair.SortOnly(texts[k%len(texts)], sa)
						k++
						y.sorted(1)
						cpu_throttle(&ts)
					}
					atomic.AddInt64(&n, int64(k))
				}(inputs[i])
			}
			time.Sleep(win)
			atomic.StoreInt32(&stop, 1)
			wg.Wait()
			el := time.Since(t0).Seconds()
			cs := (process_cpu_time() - c0).Seconds()
			sl := float64(atomic.LoadInt64(&cpu_throttle_sleep_ns)-s0) / 1e9
			if quit != nil {
				close(quit)
			}
			wall[a] = append(wall[a], float64(n)/el)
			fmt.Printf("DUTY round %d cap %4s T=%d sorts/wall-s %7.0f cpu-cores %.2f duty-sleep %.1f%% of thread-wall cpu_share %.3f\n", r, name(a), T,
				float64(n)/el, cs/el, 100*sl/(el*float64(T)), float64(cpu_share())/1000)
		}
	}
	for _, a := range arms {
		fmt.Printf("DUTY mean cap %4s sorts/wall-s %.0f (ratio to cap %s %.3f)\n", name(a), meanF(wall[a]), name(arms[0]), meanF(wall[a])/meanF(wall[arms[0]]))
	}
}
