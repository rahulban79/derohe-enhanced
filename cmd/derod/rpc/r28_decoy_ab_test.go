package rpc

// r28 (rpc-metrics, dero-rft §7 B51): the slack 1 vs 2 A/B of the depth-corrected decoy sampler on the REAL mainnet
// balance tree. R24 shipped R24_DECOY_SLACK=2 on a modelled increment (+9.6 ms CPU per call against ~+4 ms for
// slack 1, ESTIMATE); R27 measured only the TOTAL live CPU per GetRandomAddress call (22.7 / 22.5 ms), which cannot
// be compared with that increment. This test runs the sampler's draw phase (the only part the slack changes) on an
// APFS clone of the balance store, ABBA-interleaved, with the B cache warm (as on a node: B lives 10 min per tree),
// and reports CPU per call, draws per call and the acceptance rate of each arm, and the pilot cost apart.
//
// OPT-IN (never in NEW_TESTS: S3 must not need a chain copy):
//   R28_DECOY_TREE=<dir of a COPY of mainnet/balances> [R28_DECOY_BLOCKS=8] [R28_DECOY_CALLS=50] [R28_DECOY_OUT=f.json]
//   python3 -I harness/pipeline/benchlock.py -- go test -run TestR28DecoySlackAB -count=1 -v ./cmd/derod/rpc/
// Never point it at the live datadir: graviton opens the store read-write.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/deroproject/graviton"

	"github.com/deroproject/derohe/config"
)

func r28_cpu() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func r28_env_int(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return d
}

type r28_arm struct {
	Slack      int     `json:"slack"`
	B          int     `json:"B"`
	Calls      int     `json:"calls"`
	CPUms      float64 `json:"cpu_ms_per_call"`
	Wallms     float64 `json:"wall_ms_per_call"`
	Draws      float64 `json:"draws_per_call"`
	Accepted   float64 `json:"accepted_per_call"`
	Short      int     `json:"calls_short_of_want"`
	PilotCPUms float64 `json:"pilot_cpu_ms"`
	PilotDraws int     `json:"pilot_draws"`
	block_cpu  []float64
}

func TestR28DecoySlackAB(t *testing.T) {
	dir := os.Getenv("R28_DECOY_TREE")
	if dir == "" {
		t.Skip("opt-in: R28_DECOY_TREE=<copy of mainnet/balances> (rft §7 B51)")
	}
	if fi, err := os.Stat(filepath.Join(dir, "version_root.bin")); err != nil || fi.Size() == 0 { // NewDiskStore CREATES an empty store
		t.Fatalf("%s is not a balance store copy (no version_root.bin): give an absolute path to a copy", dir)
	}
	store, err := graviton.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	blocks, calls := r28_env_int("R28_DECOY_BLOCKS", 8), r28_env_int("R28_DECOY_CALLS", 50)
	arms := map[int]*r28_arm{1: {Slack: 1}, 2: {Slack: 2}}
	caches := map[int]*r24_decoy_bcache{1: {now: time.Now}, 2: {now: time.Now}}
	for _, s := range []int{1, 2} { // pilot: estimates n once per tree (cached for R24_DECOY_B_TTL on a node)
		c0 := r28_cpu()
		_, st := r24_decoy_draws_slack(tree, config.BALANCE_TREE, caches[s], R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, r24_coin, s)
		arms[s].PilotCPUms = float64(r28_cpu()-c0) / 1e6
		arms[s].PilotDraws, arms[s].B = st.Pilot, st.B
		if st.B < 0 {
			t.Fatalf("slack %d: pilot failed (%+v)", s, st)
		}
	}
	order := []int{1, 2, 2, 1} // ABBA
	for blk := 0; blk < blocks; blk++ {
		for _, s := range order {
			a := arms[s]
			c0, w0 := r28_cpu(), time.Now()
			draws, acc := 0, 0
			for i := 0; i < calls; i++ {
				out, st := r24_decoy_draws_slack(tree, config.BALANCE_TREE, caches[s], R24_DECOY_WANT, R24_DECOY_DRAW_BUDGET, r24_coin, s)
				if !st.Cached || st.B != a.B {
					t.Fatalf("slack %d: B cache not warm (%+v)", s, st)
				}
				draws += st.Draws
				acc += len(out)
				if len(out) < R24_DECOY_WANT {
					a.Short++
				}
			}
			cpu, wall := float64(r28_cpu()-c0)/1e6/float64(calls), float64(time.Since(w0))/1e6/float64(calls)
			a.block_cpu = append(a.block_cpu, cpu)
			a.CPUms += cpu
			a.Wallms += wall
			a.Draws += float64(draws) / float64(calls)
			a.Accepted += float64(acc) / float64(calls)
			a.Calls += calls
		}
	}
	for _, a := range arms {
		n := float64(len(a.block_cpu))
		a.CPUms, a.Wallms, a.Draws, a.Accepted = a.CPUms/n, a.Wallms/n, a.Draws/n, a.Accepted/n
	}
	sd := func(v []float64, m float64) float64 {
		var s float64
		for _, x := range v {
			s += (x - m) * (x - m)
		}
		return math.Sqrt(s / float64(len(v)-1))
	}
	median := func(v []float64) float64 {
		w := append([]float64(nil), v...)
		sort.Float64s(w)
		if len(w)%2 == 1 {
			return w[len(w)/2]
		}
		return (w[len(w)/2-1] + w[len(w)/2]) / 2
	}
	m1, m2 := median(arms[1].block_cpu), median(arms[2].block_cpu)
	res := map[string]interface{}{"arms": arms, "blocks": blocks, "calls_per_block": calls, "order": "ABBA",
		"median_block_cpu_ms": map[int]float64{1: m1, 2: m2}, "increment_median_cpu_ms": m2 - m1,
		"cpu_us_per_draw":                      map[int]float64{1: 1000 * arms[1].CPUms / arms[1].Draws, 2: 1000 * arms[2].CPUms / arms[2].Draws},
		"draws_ratio_slack2_over_slack1":       arms[2].Draws / arms[1].Draws,
		"increment_cpu_ms_slack2_minus_slack1": arms[2].CPUms - arms[1].CPUms,
		"ratio_cpu_slack2_over_slack1":         arms[2].CPUms / arms[1].CPUms,
		"sd_block_cpu_ms":                      map[int]float64{1: sd(arms[1].block_cpu, arms[1].CPUms), 2: sd(arms[2].block_cpu, arms[2].CPUms)},
		"block_cpu_ms":                         map[int][]float64{1: arms[1].block_cpu, 2: arms[2].block_cpu}}
	b, _ := json.MarshalIndent(res, "", " ")
	t.Logf("%s", b)
	if out := os.Getenv("R28_DECOY_OUT"); out != "" {
		os.WriteFile(out, b, 0o644)
	}
}
