// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r23c (chainperf): overlap the NEXT synced block's PoW prewarm with the tail of the current Add_Complete_Block.
//
// Measured on a loopback shadow catch-up (r23b campaign, 1000 blocks): sync spends ~12 ms/block in prewarm_pow and
// ~23 ms/block in Add_Complete_Block, strictly one after the other, and the next block's prewarm cannot start
// earlier because Get_Difficulty_At_Tips needs its tip (the block being added) in the store. Add_Complete_Block
// writes the block's final store entry (StoreBlock with its commit version) and then its topo record, and only
// then pays the topo fsync (storetopofs.Write -> File.Sync = F_FULLFSYNC on darwin, ~7-8 ms here) and the tips /
// mempool bookkeeping. So once every tip of block i+1 has its topo record, block i+1's prewarm can run while
// block i's fsync is still in flight.
//
// Consensus: unchanged, for the same reason as prewarm_pow. The only effect of VerifyMiniblockPoW is caching a TRUE
// verdict under (tips, miniblock bytes); that verdict depends only on the miniblock and on its tips' height,
// difficulty (both in the block's file NAME), timestamp and past (its file CONTENT, written before the topo record
// by the same goroutine). A read that races a re-store (DeleteBlock+WriteBlock) finds no file or a strict prefix of
// the same bytes: Load_Block_* then panics (recovered: no cache entry) or decodes the same leading fields. A FALSE
// verdict is never cached, so Add_Complete_Block re-verifies anything that was not prewarmed. At tip,
// chunk_server.go and rpc_notifications.go already call VerifyMiniblockPoW concurrently with Add_Complete_Block.
//
// Bounds: at most ONE overlap per response at a time, for the block that this loop would prewarm next anyway (same
// 10-miniblock rule, same PREWARM_WORKERS pool), and it only starts once the current block was committed, so a
// rejected block never buys its successor a prewarm. finish() always waits for it: no goroutine outlives the call.
// DERO_SYNC_PREWARM_OVERLAP=0 restores the r23b order exactly.

import (
	"os"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

var PREWARM_OVERLAP = os.Getenv("DERO_SYNC_PREWARM_OVERLAP") != "0"

// PREWARM_OVERLAP_POLL: one probe is one Load_Block_Height (LRU-cached) plus one 48-byte topo pread per tip
const PREWARM_OVERLAP_POLL = 250 * time.Microsecond

var (
	prewarm_overlap_early  = metrics.Set.NewCounter("p2p_sync_prewarm_overlap_early_total")  // started while Add_Complete_Block still ran
	prewarm_overlap_late   = metrics.Set.NewCounter("p2p_sync_prewarm_overlap_late_total")   // tips became final only as it returned
	prewarm_overlap_missed = metrics.Set.NewCounter("p2p_sync_prewarm_overlap_missed_total") // tips never final: no overlap prewarm
)

// r24 (B34): a block the overlap prewarmed was prewarmed a second time by the sync loop (all cache hits), so
// p2p_sync_pow_prewarmed_total counted it twice (live r23c: 1,040 = (88 fetched + 16 early) x 10) and
// p2p_sync_prewarm_seconds_total added the overlapped time to the wait it is documented to measure. The overlap now
// records which block it prewarmed and how many PoWs ran (ran, read only after finish), the loop skips a block the
// overlap fully covered (covered), and the overlap's own time goes to p2p_sync_prewarm_overlap_seconds_total.
var (
	prewarm_overlap_seconds = metrics.Set.NewFloatCounter("p2p_sync_prewarm_overlap_seconds_total") // r24: prewarm time hidden behind Add
	prewarm_overlap_skipped = metrics.Set.NewCounter("p2p_sync_prewarm_overlap_covered_total")      // r24: blocks the loop did not prewarm again
	prewarm_overlap_cross   = metrics.Set.NewCounter("p2p_sync_prewarm_overlap_cross_total")        // r24: overlaps for the NEXT response's first block
	// r24 (chainperf): the time finish() made sync wait for a running overlap prewarm
	prewarm_overlap_wait_seconds = metrics.Set.NewFloatCounter("p2p_sync_prewarm_overlap_wait_seconds_total")
)

type prewarm_overlap struct {
	stop chan struct{}
	done chan struct{}
	blid crypto.Hash // r24: the block this overlap prewarms (zero when unknown)
	ran  int         // r24: PoWs prewarm() ran; written before done is closed, read only after finish()
}

// covered reports whether this finished overlap prewarmed every miniblock of blid, so the sync loop's own
// prewarm_pow for it would only re-read the cache (r24, B34). nil-safe; call only after finish().
func (o *prewarm_overlap) covered(blid crypto.Hash) bool {
	return o != nil && o.blid == blid && blid != (crypto.Hash{}) && o.ran == PREWARM_MINIBLOCKS
}

// start_prewarm_overlap polls ready until it is true (then runs prewarm once) or until finish is called.
func start_prewarm_overlap(ready func() bool, prewarm func() int) *prewarm_overlap {
	o := &prewarm_overlap{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(o.done)
		defer func() { recover() }() // a failure only means no cache entry; the chain re-verifies
		t := time.NewTicker(PREWARM_OVERLAP_POLL)
		defer t.Stop()
		for {
			stopped := false
			select {
			case <-o.stop:
				stopped = true
			default:
			}
			if ready() {
				if stopped {
					prewarm_overlap_late.Inc()
				} else {
					prewarm_overlap_early.Inc()
				}
				o.ran = prewarm()
				return
			}
			if stopped {
				prewarm_overlap_missed.Inc()
				return
			}
			select {
			case <-o.stop:
			case <-t.C:
			}
		}
	}()
	return o
}

// finish stops the polling and waits for a prewarm that already started. nil-safe.
func (o *prewarm_overlap) finish() {
	if o == nil {
		return
	}
	t0 := time.Now()
	close(o.stop)
	<-o.done
	prewarm_overlap_wait_seconds.Add(time.Since(t0).Seconds())
}

// prewarmed reports, after finish(), whether the overlap prewarmed any of the next block's miniblocks (r24,
// chainperf). nil-safe. The sync loop's skip uses the stricter covered(blid) (r24 syncp2p: same block hash and all
// PREWARM_MINIBLOCKS ran). Consensus: unchanged either way, since Add_Complete_Block verifies every miniblock whose
// TRUE verdict is not cached.
func (o *prewarm_overlap) prewarmed() bool {
	return o != nil && o.ran > 0
}

// tips_final: every tip has its block entry (height) AND the topo record at that height names it, i.e.
// Add_Complete_Block got past that block's final StoreBlock. at returns the block id recorded at a topo index.
func tips_final(tips []crypto.Hash, height func(crypto.Hash) int64, at func(int64) (crypto.Hash, bool)) bool {
	if len(tips) == 0 {
		return false
	}
	for _, tip := range tips {
		h := height(tip)
		if h < 0 {
			return false
		}
		if id, ok := at(h); !ok || id != tip {
			return false
		}
	}
	return true
}

func topo_id_at(index int64) (crypto.Hash, bool) {
	r, err := chain.Store.Topo_store.Read(index)
	if err != nil {
		return crypto.Hash{}, false
	}
	return crypto.Hash(r.BLOCK_ID), true
}

// next_block_prewarm starts the overlap for the serialized block that follows in the same sync response
// (r24: or, through sync_run.peek, the first block of the next response when it has already arrived).
func next_block_prewarm(raw []byte) *prewarm_overlap {
	if !PREWARM_POW || !PREWARM_OVERLAP {
		return nil
	}
	var nb block.Block
	if nb.Deserialize(raw) != nil || len(nb.MiniBlocks) != PREWARM_MINIBLOCKS {
		return nil
	}
	o := start_prewarm_overlap(func() bool { return tips_final(nb.Tips, chain.Load_Block_Height, topo_id_at) },
		func() int {
			return prewarm_pow_with(chain.Load_Block_Height, nb.Tips, len(nb.MiniBlocks), func() { chain.Get_Difficulty_At_Tips(nb.Tips) },
				prewarm_overlap_seconds.Add, func(k int) bool {
					return chain.VerifyMiniblockPoW(&nb, nb.MiniBlocks[k])
				})
		})
	o.blid = nb.GetHash() // r24: written before anyone reads it (the goroutine never reads blid)
	return o
}

// sync_run carries prewarm state across the responses of one pipelined fetch (r24). Before r24 the first block of
// every response had no predecessor in its own response and so never got an overlap (r23c: ~25% of synced blocks).
// peek returns the first block of the next response if that response has ALREADY arrived (never waits; nil
// otherwise); prev is the overlap started during the previous block's add, possibly in the previous response.
type sync_run struct {
	peek func() []byte
	prev *prewarm_overlap
}

// next_overlap starts the overlap for the block after index i of cblocks: the next block of this response, or the
// first block of the next response if run can peek one. nil when there is none (r24).
func (run *sync_run) next_overlap(cblocks []Complete_Block, i int, start func([]byte) *prewarm_overlap) *prewarm_overlap {
	if i+1 < len(cblocks) {
		return start(cblocks[i+1].Block)
	}
	if run == nil || run.peek == nil {
		return nil
	}
	raw := run.peek()
	if raw == nil {
		return nil
	}
	o := start(raw)
	if o != nil {
		prewarm_overlap_cross.Inc()
	}
	return o
}

// take_prev returns and clears the overlap that was started for the block now being processed.
func (run *sync_run) take_prev() (o *prewarm_overlap) {
	if run != nil {
		o, run.prev = run.prev, nil
	}
	return
}

func (run *sync_run) keep(o *prewarm_overlap) {
	if run != nil {
		run.prev = o
	}
}
