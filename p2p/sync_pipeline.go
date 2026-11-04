// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// Pipelined block fetch for sync_chain. Before this, sync asked for ONE block per Peer.GetObject and only sent the
// next request after the previous block had been verified and committed: every block cost a full request/response
// round trip (KCP flush interval + network RTT) PLUS the verification time, strictly in series.
//
// Here the blocks still reach the chain one at a time and in topological order, through the unchanged
// process_object_response -> Add_Complete_Block path (so consensus validation is byte-for-byte the same). Only the
// transport changes:
//   - batch: up to SYNC_BATCH block ids per GetObject (the request format always allowed a list; the server answers
//     every id in order or returns an error). SYNC_BATCH*max block size stays below the codec's 5*max frame limit.
//   - depth: up to SYNC_DEPTH requests in flight, so the next batch travels while the current one is verified.
// SYNC_BATCH=1 SYNC_DEPTH=1 reproduces the old behaviour exactly.

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

// a response frame may be at most 5*STARGATE_HE_MAX_BLOCK_SIZE (rpc_cbor_codec.go); a batch of full-size blocks
// must still fit, with one block of slack for the txs/common/cbor overhead
const SYNC_BATCH_MAX = 4
const SYNC_DEPTH_MAX = 4

var SYNC_BATCH = env_int("DERO_SYNC_BATCH", 4, 1, SYNC_BATCH_MAX)
var SYNC_DEPTH = env_int("DERO_SYNC_DEPTH", 2, 1, SYNC_DEPTH_MAX)

func init() {
	if uint64(SYNC_BATCH_MAX+1)*config.STARGATE_HE_MAX_BLOCK_SIZE > 5*config.STARGATE_HE_MAX_BLOCK_SIZE {
		panic("SYNC_BATCH_MAX full blocks would not fit one response frame")
	}
}

func env_int(name string, def, lo, hi int) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

type fetch_result struct {
	resp Objects
	err  error
}

// fetch_pipelined requests ids in batches with up to depth requests outstanding and hands each response to process
// strictly in request order. It stops at the first fetch error, short/mismatched response, or process error; requests
// still in flight then finish into buffered channels and are dropped. fetch is the transport (connection.call in
// production, a fake in tests).
func fetch_pipelined(ids []crypto.Hash, batch, depth int,
	fetch func(ids []crypto.Hash) (Objects, error), process func(Objects) error) (fetched int, err error) {
	return fetch_pipelined_adaptive(ids, func() (int, int) { return batch, depth }, fetch, process)
}

// fetch_pipelined_adaptive is fetch_pipelined whose batch size and depth are re-read from shape before every request,
// so a stream that turns into large blocks falls back to one block per request mid-way (see sync_size_tracker).
func fetch_pipelined_adaptive(ids []crypto.Hash, shape func() (batch, depth int),
	fetch func(ids []crypto.Hash) (Objects, error), process func(Objects) error) (fetched int, err error) {
	return fetch_pipelined_peek(ids, shape, fetch, func(o Objects, _ func() []byte) error { return process(o) })
}

// fetch_pipelined_peek is fetch_pipelined_adaptive whose process also gets peek (r24): peek returns the first block
// of the NEXT response if that response has already arrived complete and without error, else nil. It never blocks,
// never reorders anything and never hands a response to process early: the response it looked at is still the next
// one processed, exactly as before; only its first block's bytes may be read in advance (for the PoW prewarm).
func fetch_pipelined_peek(ids []crypto.Hash, shape func() (batch, depth int),
	fetch func(ids []crypto.Hash) (Objects, error), process func(Objects, func() []byte) error) (fetched int, err error) {
	type pending struct {
		ids []crypto.Hash
		ch  chan fetch_result
		got *fetch_result // r24: received early by peek
	}
	pos := 0
	issue := func(batch int) pending {
		if batch < 1 {
			batch = 1
		}
		end := pos + batch
		if end > len(ids) {
			end = len(ids)
		}
		b := ids[pos:end]
		pos = end
		ch := make(chan fetch_result, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					ch <- fetch_result{err: fmt.Errorf("fetch panic: %v", r)}
				}
			}()
			resp, err := fetch(b)
			ch <- fetch_result{resp: resp, err: err}
		}()
		return pending{ids: b, ch: ch}
	}
	fill := func(inflight []pending) []pending {
		for pos < len(ids) {
			batch, depth := shape()
			if depth < 1 {
				depth = 1
			}
			if len(inflight) >= depth {
				break
			}
			inflight = append(inflight, issue(batch))
		}
		return inflight
	}

	inflight := fill(nil)
	peek := func() []byte {
		if len(inflight) == 0 {
			return nil
		}
		p := &inflight[0]
		if p.got == nil {
			select {
			case r := <-p.ch:
				p.got = &r
			default:
				return nil // not here yet: never wait for it
			}
		}
		if p.got.err != nil || len(p.got.resp.CBlocks) != len(p.ids) || len(p.got.resp.CBlocks) == 0 {
			return nil // this response will be refused below anyway
		}
		return p.got.resp.CBlocks[0].Block
	}
	for len(inflight) > 0 {
		p := inflight[0]
		inflight = inflight[1:]
		t0 := time.Now()
		var r fetch_result
		if p.got != nil {
			r = *p.got
		} else {
			r = <-p.ch
		}
		metrics.Set.GetOrCreateFloatCounter("p2p_sync_wait_seconds_total").Add(time.Since(t0).Seconds())
		if r.err != nil {
			return fetched, r.err
		}
		if len(r.resp.CBlocks) != len(p.ids) {
			return fetched, short_answer_error{got: len(r.resp.CBlocks), want: len(p.ids)} // r25: typed (peer_observe.go), same text
		}
		// keep the pipe full before spending time on verification
		inflight = fill(inflight)
		t1 := time.Now()
		err = process(r.resp, peek)
		metrics.Set.GetOrCreateFloatCounter("p2p_sync_process_seconds_total").Add(time.Since(t1).Seconds())
		metrics.Set.GetOrCreateCounter("p2p_sync_blocks_fetched_total").Add(len(p.ids))
		metrics.Set.GetOrCreateCounter("p2p_sync_getobject_calls_total").Inc()
		if err != nil {
			return fetched, err
		}
		fetched += len(p.ids)
	}
	return fetched, nil
}

// One GetObject has one call deadline (call_timeout, 30 s) however many blocks it asks for. With batch x depth
// blocks in flight, ~1 MB blocks from a peer on a 32-segment KCP window would not arrive in time and the honest peer
// would be scored for a "timeout". So once a large block is seen (or a batched fetch fails), sync drops to one block
// per request and one request in flight until SYNC_SMALL_STREAK consecutive small blocks have arrived again.
const SYNC_LARGE_BLOCK = 64 << 10 // bytes of block + txs above which a block counts as large
const SYNC_SMALL_STREAK = 64      // small blocks needed before batching resumes

type sync_size_tracker struct {
	sync.Mutex
	conservative int // small blocks still to see before batching resumes; > 0 means batch=1 depth=1
}

var sync_sizes sync_size_tracker

func complete_block_size(cb *Complete_Block) (n int) {
	n = len(cb.Block)
	for _, tx := range cb.Txs {
		n += len(tx)
	}
	return
}

// note records the sizes of the blocks one response carried.
func (t *sync_size_tracker) note(o *Objects) {
	t.Lock()
	defer t.Unlock()
	for i := range o.CBlocks {
		if complete_block_size(&o.CBlocks[i]) > SYNC_LARGE_BLOCK {
			if t.conservative == 0 {
				metrics.Set.GetOrCreateCounter("p2p_sync_large_block_fallbacks_total").Inc()
			}
			t.conservative = SYNC_SMALL_STREAK
		} else if t.conservative > 0 {
			t.conservative--
		}
	}
}

// failed: a batched request did not complete; retry the next round one block at a time.
func (t *sync_size_tracker) failed() {
	t.Lock()
	t.conservative = SYNC_SMALL_STREAK
	t.Unlock()
}

func (t *sync_size_tracker) shape(batch, depth int) (int, int) {
	t.Lock()
	defer t.Unlock()
	if t.conservative > 0 {
		return 1, 1
	}
	return batch, depth
}

// the production transport for fetch_pipelined
func (connection *Connection) fetch_blocks(ids []crypto.Hash) (resp Objects, err error) {
	var orequest ObjectList
	for _, id := range ids {
		orequest.Block_list = append(orequest.Block_list, [32]byte(id))
	}
	fill_common(&orequest.Common)
	err = connection.call("Peer.GetObject", orequest, &resp)
	return
}

// PREWARM_POW (env DERO_SYNC_PREWARM=0 disables) verifies a synced block's miniblock PoWs in parallel just before
// Add_Complete_Block. A CPU profile of loopback sync (Round 18) put 60% of sync CPU in VerifyMiniblockPoW, which
// Add_Complete_Block runs serially over the block's 10 miniblocks while the node used ~0.7 of 20 cores.
// This calls the SAME consensus function, chain.VerifyMiniblockPoW (as chunk_server.go and rpc_notifications.go
// already do for propagated blocks), whose only side effect is caching a TRUE verdict under (tips, miniblock bytes).
// The verdict depends only on the miniblock and its tips' stored difficulty, which is immutable per block hash, so
// Add_Complete_Block's own call returns exactly what it would have computed. Blocks with a tip we do not have are
// skipped (Get_Difficulty_At_Tips would panic). Invalid PoW is not cached and is rejected by the chain as before.
var PREWARM_POW = os.Getenv("DERO_SYNC_PREWARM") != "0"

// PREWARM_MINIBLOCKS is the exact miniblock count Verify_MiniBlocks (blockchain/miniblocks_consensus.go) accepts.
// A block with any other count is rejected by the chain anyway, so it is never prewarmed: without this guard a peer
// could send a block carrying up to 16383 junk miniblocks and have us fan out one PoW goroutine for each before
// Add_Complete_Block rejected it (measured 2 GB / 4.4 s per such block).
const PREWARM_MINIBLOCKS = int(config.BLOCK_TIME - config.MINIBLOCK_HIGHDIFF + 1)

// PREWARM_WORKERS bounds prewarm concurrency: a quarter of the cores (the box is often also mining).
// r20: DERO_SYNC_PREWARM_WORKERS (1..PREWARM_MINIBLOCKS) overrides it; p2p_sync_prewarm_seconds_total measures the
// wall time sync spends waiting for prewarm, so the knob can be judged on a live node.
// The +3.1% measured with 10 workers (3 fixed-order loopback pairs) is within noise, so the default is unchanged.
var PREWARM_WORKERS = prewarm_workers_from_env()

func prewarm_workers_from_env() int {
	return env_int("DERO_SYNC_PREWARM_WORKERS", default_prewarm_workers(), 1, PREWARM_MINIBLOCKS)
}

// prewarm_seconds: wall time sync spent in prewarm_pow (p2p_sync_prewarm_seconds_total)
var prewarm_seconds = metrics.Set.NewFloatCounter("p2p_sync_prewarm_seconds_total")

func default_prewarm_workers() int {
	if w := runtime.NumCPU() / 4; w > 1 {
		return w
	}
	return 1
}

func prewarm_pow(height func(crypto.Hash) int64, tips []crypto.Hash, n int, verify func(i int) bool) (ran int) {
	return prewarm_pow_with(height, tips, n, nil, prewarm_seconds.Add, verify)
}

// prewarm_pow_into is prewarm_pow whose wall time is added to secs (r24, B34: the overlap's time is hidden behind
// Add_Complete_Block, so it goes to its own counter instead of the sync wait prewarm_seconds documents).
// r24 merge: a thin wrapper over prewarm_pow_with (chainperf), no difficulty warm-up.
func prewarm_pow_into(secs interface{ Add(float64) }, height func(crypto.Hash) int64, tips []crypto.Hash, n int, verify func(i int) bool) (ran int) {
	return prewarm_pow_with(height, tips, n, nil, secs.Add, verify)
}

// r24 (chainperf): PREWARM_DIFF (env DERO_SYNC_PREWARM_DIFF=0 disables) fills the chain's difficulty cache for the
// block's tips ONCE, concurrently with the PoW workers. Before r24 every worker of the first wave reached
// Get_Difficulty_At_Tips together, all missed the (tips -> difficulty) cache and each recomputed it from the store
// (a directory open + scan per Load_Block_Difficulty / Load_BL_FROM_ID): a loopback shadow CPU profile of r23c sync put
// 9.05 s of 27.74 s (32.6 %) in Get_Difficulty_At_Tips against 7.09 s for the PoW hashes themselves
// (r24 chainperf evidence/base_sync_cum.txt). The PoW hash comes first inside VerifyMiniblockPoW (2.29 ms median) and an uncached
// difficulty 0.63 ms (r24 clone, evidence/verify_cost_cloneA.json), so the workers normally find the cache filled.
// Consensus: unchanged. The call is the same chain.Get_Difficulty_At_Tips that VerifyMiniblockPoW and
// Add_Complete_Block make; its only side effect is caching the value it computes from immutable stored data (a
// block's height, difficulty and timestamp are fixed per block hash), so every later call returns what it would have
// computed anyway. A tip we do not have is refused before (unknown_tip), and a panic only means no cache entry.
var PREWARM_DIFF = os.Getenv("DERO_SYNC_PREWARM_DIFF") != "0"

// prewarm_pow_with is prewarm_pow with an optional difficulty warm-up (r24, nil = none) and the counter that its wall
// time goes to (r24, B34: the overlap's prewarm runs beside Add_Complete_Block, not on sync's critical path, so it has
// its own counter and p2p_sync_prewarm_seconds_total stays "time sync waited for prewarm").
func prewarm_pow_with(height func(crypto.Hash) int64, tips []crypto.Hash, n int, diff func(), seconds func(float64),
	verify func(i int) bool) (ran int) {
	if !PREWARM_POW || n != PREWARM_MINIBLOCKS || unknown_tip(height, tips) {
		return 0
	}
	t0 := time.Now()
	defer func() {
		if seconds != nil {
			seconds(time.Since(t0).Seconds())
		}
	}()
	workers := PREWARM_WORKERS
	if workers > n {
		workers = n
	}
	next := make(chan int, n)
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	if diff != nil && PREWARM_DIFF { // r24: one difficulty computation per block instead of one per first-wave worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { recover() }() // no cache entry; each VerifyMiniblockPoW computes it as before
			diff()
		}()
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				func() {
					defer func() { recover() }() // a failure here only means no cache entry; the chain re-verifies
					verify(i)
				}()
			}
		}()
	}
	wg.Wait()
	metrics.Set.GetOrCreateCounter("p2p_sync_pow_prewarmed_total").Add(n)
	return n
}
