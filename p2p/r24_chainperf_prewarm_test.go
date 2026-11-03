package p2p

// r24 (chainperf): the sync prewarm computes a block's difficulty once (not once per first-wave worker), the overlap's
// prewarm time goes to its own counter, and a block the overlap prewarmed is not prewarmed (and counted) again (B34).

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func r24_known(crypto.Hash) int64 { return 5 }

func TestR24PrewarmDiffOncePerBlock(t *testing.T) {
	var diffs, verifies int32
	n := prewarm_pow_with(r24_known, ids_n(2), PREWARM_MINIBLOCKS, func() { atomic.AddInt32(&diffs, 1) }, nil,
		func(int) bool { atomic.AddInt32(&verifies, 1); return true })
	if n != PREWARM_MINIBLOCKS || int(verifies) != PREWARM_MINIBLOCKS {
		t.Fatalf("prewarmed %d, verified %d", n, verifies)
	}
	if diffs != 1 {
		t.Fatalf("difficulty warm-up ran %d times for one block, want exactly 1", diffs)
	}
	// nil diff (the prewarm_pow wrapper) is the r23c behaviour
	if prewarm_pow_with(r24_known, ids_n(2), PREWARM_MINIBLOCKS, nil, nil, func(int) bool { return true }) != PREWARM_MINIBLOCKS {
		t.Fatal("nil difficulty warm-up broke the prewarm")
	}
}

func TestR24PrewarmDiffEnvOff(t *testing.T) {
	saved := PREWARM_DIFF
	PREWARM_DIFF = false
	defer func() { PREWARM_DIFF = saved }()
	var diffs int32
	if prewarm_pow_with(r24_known, ids_n(2), PREWARM_MINIBLOCKS, func() { atomic.AddInt32(&diffs, 1) }, nil,
		func(int) bool { return true }) != PREWARM_MINIBLOCKS {
		t.Fatal("prewarm must still run with DERO_SYNC_PREWARM_DIFF=0")
	}
	if diffs != 0 {
		t.Fatal("DERO_SYNC_PREWARM_DIFF=0 must restore the r23c behaviour (no difficulty warm-up)")
	}
}

// forged inputs: a block the chain would reject before PoW (wrong miniblock count, unknown tip) must not buy a
// difficulty computation either; and a panicking difficulty (store read raced a re-store) is contained.
func TestR24PrewarmDiffForgedInputs(t *testing.T) {
	unknown := func(crypto.Hash) int64 { return -1 }
	for _, c := range []struct {
		name   string
		height func(crypto.Hash) int64
		n      int
	}{{"unknown tip", unknown, PREWARM_MINIBLOCKS}, {"16383 junk miniblocks", r24_known, 16383}, {"one miniblock", r24_known, 1}} {
		var diffs int32
		if r := prewarm_pow_with(c.height, ids_n(2), c.n, func() { atomic.AddInt32(&diffs, 1) }, nil,
			func(int) bool { return true }); r != 0 || diffs != 0 {
			t.Fatalf("%s: prewarmed %d, difficulty computed %d times", c.name, r, diffs)
		}
	}
	var verifies int32
	if prewarm_pow_with(r24_known, ids_n(2), PREWARM_MINIBLOCKS, func() { panic("could not find height for blid") }, nil,
		func(int) bool { atomic.AddInt32(&verifies, 1); return true }) != PREWARM_MINIBLOCKS || int(verifies) != PREWARM_MINIBLOCKS {
		t.Fatal("a panicking difficulty warm-up stopped the PoW prewarm")
	}
}

func TestR24PrewarmSecondsGoToTheirCounter(t *testing.T) {
	var got float64
	before := prewarm_seconds.Get()
	prewarm_pow_with(r24_known, ids_n(2), PREWARM_MINIBLOCKS, nil, func(s float64) { got += s },
		func(int) bool { time.Sleep(time.Millisecond); return true })
	if got <= 0 {
		t.Fatal("prewarm time was not reported to the given counter")
	}
	if prewarm_seconds.Get() != before {
		t.Fatal("an overlap prewarm's time leaked into p2p_sync_prewarm_seconds_total (B34)")
	}
}

func TestR24OverlapPrewarmedFlag(t *testing.T) {
	var none *prewarm_overlap
	if none.prewarmed() {
		t.Fatal("nil overlap reported a prewarm")
	}
	wait := prewarm_overlap_wait_seconds.Get()
	o := start_prewarm_overlap(func() bool { return true }, func() int { time.Sleep(2 * time.Millisecond); return PREWARM_MINIBLOCKS })
	o.finish()
	if !o.prewarmed() {
		t.Fatal("an overlap that prewarmed the next block did not say so: the loop would prewarm and count it twice")
	}
	if prewarm_overlap_wait_seconds.Get() <= wait {
		t.Fatal("finish() wait time not counted")
	}
	o = start_prewarm_overlap(func() bool { return true }, func() int { return 0 }) // prewarm_pow refused the block
	o.finish()
	if o.prewarmed() {
		t.Fatal("a refused prewarm must not make the loop skip its own prewarm")
	}
	o = start_prewarm_overlap(func() bool { return false }, func() int { t.Error("ran"); return 10 }) // tips never final
	o.finish()
	if o.prewarmed() {
		t.Fatal("a missed overlap must not make the loop skip its own prewarm")
	}
}

// the helpers above only matter if the sync loop and the overlap use them
func TestR24SyncLoopWiring(t *testing.T) {
	read := func(f string) string {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	s := read("chain_sync.go")
	// r24 merge: the skip is syncp2p's covered(blid) (hash-checked, all PoWs ran); the loop must keep the overlap after Add
	skip := strings.Index(s, "if syncing && prev.covered(bl.GetHash()) {")
	diff := strings.Index(s, "prewarm_pow_with(chain.Load_Block_Height, bl.Tips, len(bl.MiniBlocks), func() { chain.Get_Difficulty_At_Tips(bl.Tips) },\n\t\t\t\tprewarm_seconds.Add,")
	add := strings.Index(s, "return Add_Complete_Block_HF3(chain, &cbl) }()\n\t\tif ok {\n\t\t\trun.keep(overlap)")
	if skip < 0 || diff < skip || add < diff {
		t.Fatal("sync loop must skip a block the overlap prewarmed, warm its difficulty once, and record the overlap after Add")
	}
	o := read("sync_prewarm_overlap.go")
	if !strings.Contains(o, "func() { chain.Get_Difficulty_At_Tips(nb.Tips) },\n\t\t\t\tprewarm_overlap_seconds.Add,") {
		t.Fatal("the overlap must warm the difficulty once and report its time to p2p_sync_prewarm_overlap_seconds_total")
	}
}
