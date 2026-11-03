package main

// r23c payouts: phase-exact expected shares (outcome.go expectedSharesPhased, phase_expect_window).

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestR23cExpectedSharesPhased(t *testing.T) {
	const D = 3_000_000
	// 9 regular jobs' worth (9D hashes at 1/D) + 9D final hashes at 1/(9D) = 9 + 1 = 10 shares: one block's worth
	if s := expectedSharesPhased(9*D, 9*D, 0, D); math.Abs(s-10) > 1e-9 {
		t.Fatalf("phased %f want 10", s)
	}
	// at the network's 50/50 split it equals the 5/(9 D) model
	if a, b := expectedSharesPhased(9*D, 9*D, 0, D), expectedShares(18*D, D); math.Abs(a-b) > 1e-9 {
		t.Fatalf("50/50 split %f != model %f", a, b)
	}
	// the live r23b run's split (89.1M regular, 105.5M final hashes): the model over-states by ~7 %
	reg, fin := uint64(89_103_236), uint64(105_488_216)
	p, m := expectedSharesPhased(reg, fin, 0, D), expectedShares(reg+fin, D)
	if r := m / p; r < 1.06 || r > 1.08 {
		t.Fatalf("model/phased %f, want ~1.072", r)
	}
	// unbooked hashes keep the model rate; D = 0 never divides
	if a, b := expectedSharesPhased(0, 0, 18*D, D), expectedShares(18*D, D); a != b {
		t.Fatalf("other %f != %f", a, b)
	}
	if expectedSharesPhased(1, 1, 1, 0) != 0 {
		t.Fatal("D=0 must not divide")
	}
}

// Every hash is priced exactly once, also when the phase clock books hashes before the delta that carries them.
func TestR23cPhaseExpectWindowExact(t *testing.T) {
	const D = 1000
	var w phase_expect_window
	total := 0.0
	// window 1: 100 hashes, the clock has booked 120 (90 regular, 30 final): 20 arrive in the next delta
	total += w.step(100, [2]uint64{90, 30}, D)
	// window 2: 100 hashes, the clock has 80 more regular (170 total), the 20 carried are already priced
	total += w.step(100, [2]uint64{170, 30}, D)
	// window 3: 50 hashes, none booked (no job yet: impossible after the first, but priced at the model rate)
	total += w.step(50, [2]uint64{170, 30}, D)
	want := (170.0+30.0/9)/D + expectedShares(50, D)
	if math.Abs(total-want) > 1e-12 {
		t.Fatalf("total %f want %f", total, want)
	}
	if w.slack != 0 {
		t.Fatalf("slack %d want 0", w.slack)
	}
	// a smaller total than before books nothing for that phase (the clock only adds)
	var v phase_expect_window
	v.step(10, [2]uint64{10, 0}, D)
	if got := v.step(5, [2]uint64{5, 5}, D); math.Abs(got-(5.0/9)/D) > 1e-12 {
		t.Fatalf("backwards total priced %g", got)
	}
}

// The status loop books from the phase clock: a final-only run expects 1/9 of a regular-only run's shares.
func TestR23cPhaseClockFeedsExpectation(t *testing.T) {
	const D = 1000
	var reg, fin phase_clock
	var wr, wf phase_expect_window
	now := time.Unix(1_793_555_000, 0)
	reg.observe(false, now, 0)
	fin.observe(true, now, 0)
	_, pr := reg.snapshot(now.Add(1e9), 9000)
	_, pf := fin.snapshot(now.Add(1e9), 9000)
	er, ef := wr.step(9000, pr, D), wf.step(9000, pf, D)
	if math.Abs(er-9) > 1e-9 || math.Abs(ef-1) > 1e-9 {
		t.Fatalf("regular %f (want 9) final %f (want 1)", er, ef)
	}
}

// The status loop prices its 15 s windows with the phase-exact expectation (source check: it runs inside main).
func TestR23cStatusLoopUsesPhasedExpectation(t *testing.T) {
	src, err := os.ReadFile("miner.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "exp := exp_window.step(c-last_total, ph, hash_rate)") || !strings.Contains(s, "exp_shares += exp ") {
		t.Fatal("the status loop no longer adds the phase-exact expectation")
	}
	if strings.Contains(s, "exp_shares += expectedShares(") {
		t.Fatal("the status loop still adds the 5/(9 D) model")
	}
}
