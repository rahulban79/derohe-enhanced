//go:build !windows
// +build !windows

package gsplit

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/deroproject/derohe/cmd/dero-miner/astropair"
)

func TestYieldExperiment(t *testing.T) {
	if os.Getenv("GSPLIT_YIELD_EXP") != "1" {
		t.Skip("experiment")
	}
	T := envInts("GSPLIT_OVERHEAD_T", "6")[0]
	S := envInts("GSPLIT_OVERHEAD_S", "5")[0]
	R := envInts("GSPLIT_OVERHEAD_R", "3")[0]
	texts := overheadTexts(64)
	sortLeg := func(every int) func(s *astropair.Scratch, sa []int32, k int) int {
		return func(s *astropair.Scratch, sa []int32, k int) int {
			astropair.SortOnly(texts[k%len(texts)], sa)
			if every > 0 && k%every == 0 {
				runtime.Gosched()
			}
			return 1
		}
	}
	type cfg struct {
		name  string
		procs int
		every int
	}
	cfgs := []cfg{{"procs=T plain", T, 0}, {"procs=T gosched/2", T, 2}, {"procs=T gosched/8", T, 8}, {"procs=T gosched/32", T, 32}}
	old := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(old)
	for r := 0; r < R; r++ {
		for _, c := range cfgs {
			runtime.GOMAXPROCS(c.procs)
			h, cs := runLeg(T, time.Duration(S)*time.Second, sortLeg(c.every))
			t.Logf("round %d %-22s %6.0f H/cpu-s (%d in %.1f cpu-s, %.0f H/s wall)", r, c.name, float64(h)/cs.Seconds(), h, cs.Seconds(), float64(h)/float64(S))
		}
	}
}
