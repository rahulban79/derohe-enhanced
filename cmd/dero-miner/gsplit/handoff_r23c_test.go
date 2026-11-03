//go:build !windows
// +build !windows

package gsplit

// derohe r23c handoff: what one cpu_idle_try costs. An idle try makes the mining thread hash its own pair
// (cmd/dero-miner/miner.go: TryWork returned 0 -> hash_pair), so the CPU time it takes is 2 hashes at the CPU-own
// cost, against 2 sorts at the staged (GPU SHA) cost. Gated: GSPLIT_IDLECOST=1 (threads GSPLIT_IDLECOST_T, default 6;
// seconds per leg GSPLIT_IDLECOST_S, default 6; ABAB pairs GSPLIT_IDLECOST_R, default 6). Metered in process CPU time.

import (
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

func TestIdleTryCostAB(t *testing.T) {
	if os.Getenv("GSPLIT_IDLECOST") != "1" {
		t.Skip("set GSPLIT_IDLECOST=1 (run under benchlock): CPU cost of an own pair vs a staged pair")
	}
	T := envInts("GSPLIT_IDLECOST_T", "6")[0]
	S := envInts("GSPLIT_IDLECOST_S", "6")[0]
	R := envInts("GSPLIT_IDLECOST_R", "6")[0]
	texts := overheadTexts(64)
	rng := rand.New(rand.NewSource(23))
	blobs := make([][MsgLen]byte, 256)
	for i := range blobs {
		rng.Read(blobs[i][:])
		blobs[i][0] = blobs[i][0]&0xf0 | 1
	}
	var ratios []float64
	var as, bs []float64
	for r := 0; r < R; r++ {
		ha, ca := runLeg(T, time.Duration(S)*time.Second, func(s *astropair.Scratch, sa []int32, k int) int {
			if !astropair.SortOnly(texts[k%len(texts)], sa) || !astropair.SortOnly(texts[(k+1)%len(texts)], sa) {
				t.Error("sort declined")
			}
			return 2
		})
		hb, cb := runLeg(T, time.Duration(S)*time.Second, func(s *astropair.Scratch, sa []int32, k int) int {
			x, y := blobs[k%len(blobs)], blobs[(k+7)%len(blobs)]
			if _, _, ok := astropair.Hash2(x[:], y[:], s); !ok {
				t.Error("Hash2 panicked")
			}
			return 2
		})
		ra, rb := float64(ha)/ca.Seconds(), float64(hb)/cb.Seconds()
		as, bs = append(as, ra), append(bs, rb)
		ratios = append(ratios, ra/rb)
		t.Logf("pair %d: staged-sort %.0f H/cpu-s (%d in %.1f cpu-s) | own Hash2 %.0f H/cpu-s (%d in %.1f cpu-s) | cost own/staged %.3f",
			r, ra, ha, ca.Seconds(), rb, hb, cb.Seconds(), ra/rb)
	}
	med := func(x []float64) float64 { y := append([]float64(nil), x...); sort.Float64s(y); n := len(y); return (y[(n-1)/2] + y[n/2]) / 2 }
	t.Logf("MEDIAN staged %.0f H/cpu-s, own %.0f H/cpu-s, own/staged CPU cost per hash %.3f (pairs %v)", med(as), med(bs), med(ratios), ratios)
}

// derohe r23c handoff: the live line reads feeder_cpu_backlog_ms ~50 s AND cpu_idle_tries ~100k+ per 60 s. That is
// consistent only if an idle try never happens while a staged text is claimable: TryWork counts an idle try only after
// advance() found the current batch fully claimed AND the ready list empty under e.mu, and the backlog sample
// (cpuBacklog) reads the same two facts. This pins the property with one consumer (producers only ever ADD claimable
// work): whenever cpuBacklog() was true just before a TryWork call, the call must claim a pair.
func TestIdleTryNeverWhileClaimable(t *testing.T) {
	r := newRig(t, true, 8, 3, 0)
	e := r.e
	e.Start()
	defer e.Close()
	// let the whole ring stage first, so the consumer meets "current batch exhausted, next one ready"
	if !waitFor(func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.ready) >= 3 }, 20*time.Second) {
		t.Fatal("ring never fully staged")
	}
	s := astropair.NewScratch()
	backlogCalls, idle := 0, 0
	deadline := time.Now().Add(20 * time.Second)
	for backlogCalls < 64 || idle < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("not enough coverage: %d calls with a backlog, %d idle tries", backlogCalls, idle)
		}
		b := e.cpuBacklog()
		i0 := e.Stats().IdleTries
		k := e.TryWork(s)
		i1 := e.Stats().IdleTries
		if b {
			backlogCalls++
			if k == 0 {
				t.Fatalf("TryWork returned 0 while a staged text was claimable (idle tries %d -> %d)", i0, i1)
			}
		}
		if k == 0 {
			if i1 != i0+1 {
				t.Fatalf("TryWork returned 0 without counting an idle try (%d -> %d)", i0, i1)
			}
			idle++
			time.Sleep(200 * time.Microsecond) // as the miner does an own pair
		}
	}
	if e.Disabled() {
		t.Fatalf("engine disabled: %+v", e.Stats())
	}
}
