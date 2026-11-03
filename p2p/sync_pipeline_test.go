package p2p

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func ids_n(n int) (out []crypto.Hash) {
	for i := 0; i < n; i++ {
		var h crypto.Hash
		h[0], h[1] = byte(i), byte(i>>8)
		out = append(out, h)
	}
	return
}

// a fake peer: answers one CBlock per id carrying the id as its Block bytes, after a delay
func fake_fetch(delay time.Duration, calls *int32, maxinflight *int32) func([]crypto.Hash) (Objects, error) {
	var cur int32
	return func(ids []crypto.Hash) (o Objects, err error) {
		atomic.AddInt32(calls, 1)
		c := atomic.AddInt32(&cur, 1)
		for {
			m := atomic.LoadInt32(maxinflight)
			if c <= m || atomic.CompareAndSwapInt32(maxinflight, m, c) {
				break
			}
		}
		time.Sleep(delay)
		atomic.AddInt32(&cur, -1)
		for _, id := range ids {
			o.CBlocks = append(o.CBlocks, Complete_Block{Block: append([]byte{}, id[:]...)})
		}
		return
	}
}

func TestFetchPipelinedOrderAndBatching(t *testing.T) {
	for _, tc := range []struct{ n, batch, depth, calls int }{{10, 1, 1, 10}, {10, 4, 2, 3}, {9, 4, 4, 3}, {1, 4, 2, 1}, {0, 4, 2, 0}, {4096, 4, 2, 1024}} {
		var calls, maxin int32
		ids := ids_n(tc.n)
		var got []crypto.Hash
		var mu sync.Mutex
		n, err := fetch_pipelined(ids, tc.batch, tc.depth, fake_fetch(0, &calls, &maxin), func(o Objects) error {
			mu.Lock()
			defer mu.Unlock()
			for _, b := range o.CBlocks {
				var h crypto.Hash
				copy(h[:], b.Block)
				got = append(got, h)
			}
			return nil
		})
		if err != nil || n != tc.n || int(calls) != tc.calls || int(maxin) > tc.depth {
			t.Fatalf("%+v: err %v fetched %d calls %d maxinflight %d", tc, err, n, calls, maxin)
		}
		for i := range ids {
			if got[i] != ids[i] {
				t.Fatalf("%+v: out of order at %d", tc, i)
			}
		}
	}
}

// depth 2 must overlap transfer with processing: 8 batches, 20ms fetch + 20ms process each => ~180ms instead of 320ms
func TestFetchPipelinedOverlaps(t *testing.T) {
	var calls, maxin int32
	t0 := time.Now()
	_, err := fetch_pipelined(ids_n(8), 1, 2, fake_fetch(20*time.Millisecond, &calls, &maxin), func(Objects) error {
		time.Sleep(20 * time.Millisecond)
		return nil
	})
	el := time.Since(t0)
	if err != nil || el > 280*time.Millisecond || maxin != 2 {
		t.Fatalf("err %v elapsed %s maxinflight %d", err, el, maxin)
	}
}

func TestFetchPipelinedStopsOnErrors(t *testing.T) {
	boom := errors.New("boom")
	// fetch error on the 2nd batch (ids 2,3): nothing after it is processed
	processed := 0
	_, err := fetch_pipelined(ids_n(12), 2, 2, func(ids []crypto.Hash) (o Objects, err error) {
		if ids[0][0] == 2 {
			return o, boom
		}
		for range ids {
			o.CBlocks = append(o.CBlocks, Complete_Block{})
		}
		return
	}, func(o Objects) error { processed += len(o.CBlocks); return nil })
	if !errors.Is(err, boom) || processed != 2 {
		t.Fatalf("fetch error: err %v processed %d", err, processed)
	}
	// short answer (peer drops a block) is an error, not a silent skip
	_, err = fetch_pipelined(ids_n(4), 4, 1, func(ids []crypto.Hash) (o Objects, err error) {
		o.CBlocks = make([]Complete_Block, len(ids)-1)
		return
	}, func(Objects) error { t.Fatal("short response processed"); return nil })
	if err == nil {
		t.Fatal("short response accepted")
	}
	// process error stops the loop
	processed = 0
	_, err = fetch_pipelined(ids_n(8), 1, 3, fake_fetch(0, new(int32), new(int32)), func(Objects) error {
		processed++
		if processed == 3 {
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) || processed != 3 {
		t.Fatalf("process error: err %v processed %d", err, processed)
	}
	// a panicking transport is an error, not a crash
	_, err = fetch_pipelined(ids_n(2), 1, 1, func([]crypto.Hash) (Objects, error) { panic("x") }, func(Objects) error { return nil })
	if err == nil {
		t.Fatal("panic swallowed without error")
	}
}

func TestSyncBatchFitsFrame(t *testing.T) {
	if SYNC_BATCH < 1 || SYNC_BATCH > SYNC_BATCH_MAX || SYNC_DEPTH < 1 || SYNC_DEPTH > SYNC_DEPTH_MAX {
		t.Fatalf("batch %d depth %d", SYNC_BATCH, SYNC_DEPTH)
	}
	if env_int("NO_SUCH_VAR_X", 4, 1, 4) != 4 {
		t.Fatal("default")
	}
	t.Setenv("DERO_TEST_V", "99")
	if env_int("DERO_TEST_V", 4, 1, 4) != 4 {
		t.Fatal("clamp hi")
	}
	t.Setenv("DERO_TEST_V", "0")
	if env_int("DERO_TEST_V", 4, 1, 4) != 1 {
		t.Fatal("clamp lo")
	}
}

func TestPrewarmPow(t *testing.T) {
	known := func(crypto.Hash) int64 { return 5 }
	unknown := func(crypto.Hash) int64 { return -1 }
	tips := ids_n(2)
	var seen [10]int32
	verify := func(i int) bool { atomic.AddInt32(&seen[i], 1); return true }
	if n := prewarm_pow(known, tips, 10, verify); n != 10 {
		t.Fatalf("ran %d", n)
	}
	for i := range seen {
		if seen[i] != 1 {
			t.Fatalf("miniblock %d verified %d times", i, seen[i])
		}
	}
	if prewarm_pow(unknown, tips, 10, func(int) bool { t.Fatal("verified with an unknown tip"); return false }) != 0 {
		t.Fatal("unknown tip not skipped")
	}
	if prewarm_pow(known, tips, 1, func(int) bool { t.Fatal("single miniblock prewarmed"); return false }) != 0 {
		t.Fatal("n<2 not skipped")
	}
	// a panicking verifier must not escape
	if prewarm_pow(known, tips, PREWARM_MINIBLOCKS, func(int) bool { panic("x") }) != PREWARM_MINIBLOCKS {
		t.Fatal("panic case")
	}
	PREWARM_POW = false
	defer func() { PREWARM_POW = true }()
	if prewarm_pow(known, tips, 10, func(int) bool { t.Fatal("ran while disabled"); return false }) != 0 {
		t.Fatal("disable flag ignored")
	}
}

// Fix B (r18 merge): a block whose miniblock count is not the consensus count is never prewarmed (a peer could
// otherwise make us fan out one PoW goroutine per junk miniblock), and prewarm runs on a bounded worker pool.
func TestPrewarmPowRejectsNonConsensusCount(t *testing.T) {
	known := func(crypto.Hash) int64 { return 5 }
	tips := ids_n(2)
	if PREWARM_MINIBLOCKS != 10 {
		t.Fatalf("consensus miniblock count %d, Verify_MiniBlocks requires BLOCK_TIME-MINIBLOCK_HIGHDIFF+1 = 10", PREWARM_MINIBLOCKS)
	}
	for _, n := range []int{2, 3, 9, 11, 16383} {
		var calls int32
		if r := prewarm_pow(known, tips, n, func(int) bool { atomic.AddInt32(&calls, 1); return true }); r != 0 || calls != 0 {
			t.Fatalf("n=%d prewarmed (ran %d, %d verifies)", n, r, calls)
		}
	}
}

func TestPrewarmPowBoundedConcurrency(t *testing.T) {
	known := func(crypto.Hash) int64 { return 5 }
	saved := PREWARM_WORKERS
	PREWARM_WORKERS = 2
	defer func() { PREWARM_WORKERS = saved }()
	var cur, peak, total int32
	verify := func(int) bool {
		c := atomic.AddInt32(&cur, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if c <= p || atomic.CompareAndSwapInt32(&peak, p, c) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		atomic.AddInt32(&total, 1)
		return true
	}
	if n := prewarm_pow(known, ids_n(2), PREWARM_MINIBLOCKS, verify); n != PREWARM_MINIBLOCKS || int(total) != PREWARM_MINIBLOCKS {
		t.Fatalf("ran %d, verified %d", n, total)
	}
	if peak > 2 {
		t.Fatalf("%d concurrent verifies with PREWARM_WORKERS=2", peak)
	}
	if PREWARM_WORKERS < 1 || saved < 1 || saved != default_prewarm_workers() || (runtime.NumCPU() >= 8 && saved != runtime.NumCPU()/4) {
		t.Fatalf("default workers %d", saved)
	}
}

// Fix C (r18 merge): large blocks make sync fall back to one block per request, one request in flight, so a single
// 30 s call deadline never has to cover batch x depth large blocks; batching resumes after a streak of small blocks.
func TestSyncSizeTrackerShape(t *testing.T) {
	var tr sync_size_tracker
	if b, d := tr.shape(4, 2); b != 4 || d != 2 {
		t.Fatalf("fresh tracker shape %d,%d", b, d)
	}
	small := Objects{CBlocks: []Complete_Block{{Block: make([]byte, 1000)}}}
	large := Objects{CBlocks: []Complete_Block{{Block: make([]byte, 1000), Txs: [][]byte{make([]byte, SYNC_LARGE_BLOCK)}}}}
	tr.note(&small)
	if b, d := tr.shape(4, 2); b != 4 || d != 2 {
		t.Fatalf("small block changed shape to %d,%d", b, d)
	}
	tr.note(&large)
	if b, d := tr.shape(4, 2); b != 1 || d != 1 {
		t.Fatalf("large block (txs counted) did not force batch=1 depth=1: %d,%d", b, d)
	}
	for i := 0; i < SYNC_SMALL_STREAK-1; i++ {
		tr.note(&small)
	}
	if b, _ := tr.shape(4, 2); b != 1 {
		t.Fatalf("batching resumed before %d small blocks", SYNC_SMALL_STREAK)
	}
	tr.note(&small)
	if b, d := tr.shape(4, 2); b != 4 || d != 2 {
		t.Fatalf("batching did not resume: %d,%d", b, d)
	}
	tr.failed()
	if b, d := tr.shape(4, 2); b != 1 || d != 1 {
		t.Fatalf("failed batched fetch did not fall back: %d,%d", b, d)
	}
}

func TestFetchPipelinedAdaptsToLargeBlocks(t *testing.T) {
	var tr sync_size_tracker
	ids := ids_n(40)
	var mu sync.Mutex
	var sizes []int
	var cur, peak_after int32
	var large_seen int32
	fetch := func(b []crypto.Hash) (o Objects, err error) {
		c := atomic.AddInt32(&cur, 1)
		defer atomic.AddInt32(&cur, -1)
		if atomic.LoadInt32(&large_seen) == 1 && c > atomic.LoadInt32(&peak_after) {
			atomic.StoreInt32(&peak_after, c)
		}
		mu.Lock()
		sizes = append(sizes, len(b))
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		for _, id := range b {
			cb := Complete_Block{Block: append([]byte{}, id[:]...)}
			if id[0] >= 8 { // blocks from index 8 on are ~1 MB
				cb.Txs = [][]byte{make([]byte, 1<<20)}
			}
			o.CBlocks = append(o.CBlocks, cb)
		}
		return
	}
	var got int
	n, err := fetch_pipelined_adaptive(ids, func() (int, int) { return tr.shape(4, 2) }, fetch, func(o Objects) error {
		tr.note(&o)
		for i := range o.CBlocks {
			if complete_block_size(&o.CBlocks[i]) > SYNC_LARGE_BLOCK {
				atomic.StoreInt32(&large_seen, 1)
			}
		}
		got += len(o.CBlocks)
		return nil
	})
	if err != nil || n != 40 || got != 40 {
		t.Fatalf("n=%d got=%d err=%v", n, got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sizes[0] != 4 {
		t.Fatalf("did not start batched: %v", sizes)
	}
	// the request carrying the first large block is block 8..11 (third batch); at most depth (2) further batched
	// requests were already in flight when it was processed, everything after that must be single-block
	ones := 0
	for i := len(sizes) - 1; i >= 0 && sizes[i] == 1; i-- {
		ones++
	}
	if ones < 40-8-3*4 {
		t.Fatalf("did not fall back to single-block requests: %v", sizes)
	}
	if peak_after > 2 {
		t.Fatalf("%d requests in flight after large blocks", peak_after)
	}
}

// r20 review (SP-4): DERO_SYNC_PREWARM_WORKERS is clamped to 1..PREWARM_MINIBLOCKS (0 would stall prewarm, a huge
// value would fan out one goroutine per miniblock), and prewarm time reaches p2p_sync_prewarm_seconds_total.
func TestPrewarmWorkersEnvClampAndSeconds(t *testing.T) {
	for _, c := range []struct {
		env  string
		want int
	}{{"0", 1}, {"-3", 1}, {"99", PREWARM_MINIBLOCKS}, {"3", 3}} {
		t.Setenv("DERO_SYNC_PREWARM_WORKERS", c.env)
		if got := prewarm_workers_from_env(); got != c.want {
			t.Fatalf("DERO_SYNC_PREWARM_WORKERS=%s gave %d workers, want %d", c.env, got, c.want)
		}
	}
	t.Setenv("DERO_SYNC_PREWARM_WORKERS", "junk")
	if got := prewarm_workers_from_env(); got != default_prewarm_workers() {
		t.Fatalf("unparsable value gave %d, want the default %d", got, default_prewarm_workers())
	}

	before := prewarm_seconds.Get()
	known := func(crypto.Hash) int64 { return 5 }
	verify := func(int) bool { time.Sleep(time.Millisecond); return true }
	if n := prewarm_pow(known, ids_n(2), PREWARM_MINIBLOCKS, verify); n != PREWARM_MINIBLOCKS {
		t.Fatalf("prewarmed %d", n)
	}
	if prewarm_seconds.Get() <= before {
		t.Fatal("prewarm time was not added to p2p_sync_prewarm_seconds_total")
	}
}
