package p2p

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// r23c: the overlap prewarm starts only once every tip is final, runs at most once, and never outlives finish().

func TestR23cTipsFinalNeedsTopoRecord(t *testing.T) {
	tips := ids_n(2)
	h := map[crypto.Hash]int64{tips[0]: 7, tips[1]: 6}
	height := func(x crypto.Hash) int64 {
		if v, ok := h[x]; ok {
			return v
		}
		return -1
	}
	topo := map[int64]crypto.Hash{7: tips[0]}
	at := func(i int64) (crypto.Hash, bool) { v, ok := topo[i]; return v, ok }
	if tips_final(tips, height, at) {
		t.Fatal("tip 1 has a block entry but no topo record yet: not final")
	}
	topo[6] = crypto.Hash{9} // another block at that index (the tip lost the race, or a stale record)
	if tips_final(tips, height, at) {
		t.Fatal("topo record names another block: not final")
	}
	topo[6] = tips[1]
	if !tips_final(tips, height, at) {
		t.Fatal("both tips committed: final")
	}
	delete(h, tips[1])
	if tips_final(tips, height, at) {
		t.Fatal("tip without a block entry: not final")
	}
	if tips_final(nil, height, at) {
		t.Fatal("no tips: never final")
	}
}

func TestR23cOverlapRunsOnceWhenReady(t *testing.T) {
	var ready, runs int32
	o := start_prewarm_overlap(func() bool { return atomic.LoadInt32(&ready) == 1 }, func() int { atomic.AddInt32(&runs, 1); return 10 })
	time.Sleep(5 * PREWARM_OVERLAP_POLL)
	if atomic.LoadInt32(&runs) != 0 {
		t.Fatal("prewarm ran before the tips were final")
	}
	early := prewarm_overlap_early.Get()
	atomic.StoreInt32(&ready, 1)
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&runs) == 0 && time.Now().Before(deadline) {
		time.Sleep(PREWARM_OVERLAP_POLL)
	}
	if atomic.LoadInt32(&runs) != 1 {
		t.Fatal("prewarm did not start while Add_Complete_Block was still running")
	}
	o.finish()
	if r := atomic.LoadInt32(&runs); r != 1 {
		t.Fatalf("prewarm ran %d times", r)
	}
	if prewarm_overlap_early.Get() != early+1 {
		t.Fatal("early overlap not counted")
	}
}

func TestR23cOverlapFinishStopsPolling(t *testing.T) {
	var polls, runs int32
	o := start_prewarm_overlap(func() bool { atomic.AddInt32(&polls, 1); return false }, func() int { atomic.AddInt32(&runs, 1); return 0 })
	time.Sleep(4 * PREWARM_OVERLAP_POLL)
	missed := prewarm_overlap_missed.Get()
	done := make(chan struct{})
	go func() { o.finish(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("finish did not stop a goroutine whose tips never became final")
	}
	p := atomic.LoadInt32(&polls)
	time.Sleep(4 * PREWARM_OVERLAP_POLL)
	if atomic.LoadInt32(&polls) != p || atomic.LoadInt32(&runs) != 0 {
		t.Fatal("polling continued after finish, or a prewarm ran without final tips")
	}
	if prewarm_overlap_missed.Get() != missed+1 {
		t.Fatal("missed overlap not counted")
	}
}

func TestR23cOverlapFinishWaitsForRunningPrewarm(t *testing.T) {
	release := make(chan struct{})
	var started, ended int32
	o := start_prewarm_overlap(func() bool { return true }, func() int {
		atomic.StoreInt32(&started, 1)
		<-release
		atomic.StoreInt32(&ended, 1)
		return 10
	})
	for atomic.LoadInt32(&started) == 0 {
		time.Sleep(PREWARM_OVERLAP_POLL)
	}
	done := make(chan struct{})
	go func() { o.finish(); close(done) }()
	select {
	case <-done:
		t.Fatal("finish returned while the overlap prewarm was still verifying (two pools could then run at once)")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	if atomic.LoadInt32(&ended) != 1 {
		t.Fatal("prewarm did not complete")
	}
}

func TestR23cOverlapDisabledAndNilSafe(t *testing.T) {
	var o *prewarm_overlap
	o.finish() // nil-safe
	saved := PREWARM_OVERLAP
	PREWARM_OVERLAP = false
	defer func() { PREWARM_OVERLAP = saved }()
	if next_block_prewarm([]byte{1, 2, 3}) != nil {
		t.Fatal("DERO_SYNC_PREWARM_OVERLAP=0 must restore the r23b order (no overlap)")
	}
	raw := r23c_block_with_miniblocks(t, PREWARM_MINIBLOCKS)
	if next_block_prewarm(raw) != nil {
		t.Fatal("DERO_SYNC_PREWARM_OVERLAP=0 must restore the r23b order (no overlap), even for a prewarmable block")
	}
	PREWARM_OVERLAP = true
	if next_block_prewarm([]byte{1, 2, 3}) != nil {
		t.Fatal("an undecodable next block must not start an overlap")
	}
	if next_block_prewarm(r23c_block_with_miniblocks(t, 3)) != nil {
		t.Fatal("a block without the consensus miniblock count must not start an overlap")
	}
	o = next_block_prewarm(raw) // no chain in this test: the probe panics inside the goroutine and is contained
	if o == nil {
		t.Fatal("a prewarmable next block did not start an overlap")
	}
	o.finish()
}

func r23c_block_with_miniblocks(t *testing.T, n int) []byte {
	var bl block.Block
	bl.Major_Version, bl.Height, bl.Timestamp = 1, 9, 1000
	bl.Miner_TX.Version, bl.Miner_TX.TransactionType = 1, transaction.PREMINE
	bl.Tips = []crypto.Hash{{1}}
	for i := 0; i < n; i++ {
		var m block.MiniBlock
		m.Version, m.Height, m.PastCount, m.Timestamp = 1, 9, 1, uint16(i)
		m.Nonce[0] = uint32(i)
		bl.MiniBlocks = append(bl.MiniBlocks, m)
	}
	raw := bl.Serialize()
	var back block.Block
	if err := back.Deserialize(raw); err != nil || len(back.MiniBlocks) != n {
		t.Fatalf("fixture block does not round-trip: %v (%d miniblocks)", err, len(back.MiniBlocks))
	}
	return raw
}

func TestR23cOverlapPanicIsContained(t *testing.T) {
	o := start_prewarm_overlap(func() bool { panic("store read raced a re-store") }, func() int { return 0 })
	done := make(chan struct{})
	go func() { o.finish(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a panicking probe left finish blocked")
	}
}

// r23c (verify): the helpers above are only useful if the sync loop wires them: the next block's overlap must be
// started before this block's Add_Complete_Block_HF3 and finished (deferred, so even a panic stops the poller) by it.
func TestR23cOverlapWiredIntoSyncLoop(t *testing.T) {
	src, err := os.ReadFile("chain_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "overlap = next_block_prewarm(response.CBlocks[i+1].Block)")
	add := strings.Index(s, "err, ok := func() (error, bool) { defer overlap.finish(); return Add_Complete_Block_HF3(chain, &cbl) }()")
	if start < 0 || add < 0 || start > add {
		t.Fatal("sync loop must start the next block's overlap before Add_Complete_Block_HF3 and defer its finish()")
	}
}

func TestR23cOverlapFinishDeferredOnPanic(t *testing.T) {
	var polls int32
	o := start_prewarm_overlap(func() bool { atomic.AddInt32(&polls, 1); return false }, func() int { return 0 })
	func() {
		defer func() { recover() }()
		func() (error, bool) { defer o.finish(); panic("add path panicked") }()
	}()
	p := atomic.LoadInt32(&polls)
	time.Sleep(8 * PREWARM_OVERLAP_POLL)
	if atomic.LoadInt32(&polls) != p {
		t.Fatal("overlap kept polling after the add path panicked")
	}
}
