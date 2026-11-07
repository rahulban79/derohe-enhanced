// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r28 (group p2p-config, ledger L24-21 / CP24-6): make the chunk-path PoW check at the tip measurable.
//
// feed_chunk verifies the 10 miniblocks of every new block one after the other (chunk_server.go) before the block is
// reconstructed. R24 proposed running them in parallel, as the sync prewarm does, and left it open because the rate
// at which these calls actually compute a PoW (instead of hitting blockchain's miniblock-PoW LRU) was never measured:
// a regular miniblock usually reached this node first through NotifyMiniBlock, which verifies it with the same tips
// (the cache key is tips + serialized miniblock) and inserts it into the miniblock pool; the final miniblock is never
// propagated alone (rpc_notifications.go refuses Final), so it is always computed here. If almost every regular
// check is a cache hit, a parallel loop saves nothing.
//
// The cache is inside blockchain/ (consensus guard S1: no change there), so this counts from p2p only:
//   - p2p_chunk_pow_blocks_total        blocks whose miniblocks the chunk path checked
//   - p2p_chunk_pow_checks_total        VerifyMiniblockPoW calls made by the chunk path
//   - p2p_chunk_pow_pool_seen_total     of those, miniblocks already in the miniblock pool before the call (they passed
//     VerifyMiniblockPoW in NotifyMiniBlock or the local miner path, so their verdict is cached unless the 8,192-entry
//     LRU evicted it): a deterministic proxy for a cache hit
//   - p2p_chunk_pow_slow_total          calls that took >= CHUNK_POW_SLOW: a PoW hash was computed (a cache hit is one
//     map lookup, microseconds; an AstroBWT hash measured 2.29 ms median, sync_pipeline.go): the timing proxy
//   - p2p_chunk_pow_verify_seconds_total  wall time of the whole loop, the most a parallel loop could save
// The two proxies cross-check each other: slow ≈ checks − pool_seen when the cache explains the timing.
//
// Behaviour: unchanged. The same chain.VerifyMiniblockPoW calls run in the same order, the first failure still
// penalizes the connection and returns ErrInvalidPoW; the pool lookup is a read (MiniBlocksCollection.IsCollision
// under its RLock) and happens before the call.

import (
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/metrics"
)

const CHUNK_POW_SLOW = time.Millisecond // at or above: the call computed a PoW hash

var (
	chunk_pow_blocks    = metrics.Set.NewCounter("p2p_chunk_pow_blocks_total")
	chunk_pow_checks    = metrics.Set.NewCounter("p2p_chunk_pow_checks_total")
	chunk_pow_pool_seen = metrics.Set.NewCounter("p2p_chunk_pow_pool_seen_total")
	chunk_pow_slow      = metrics.Set.NewCounter("p2p_chunk_pow_slow_total")
	chunk_pow_seconds   = metrics.Set.NewFloatCounter("p2p_chunk_pow_verify_seconds_total")
)

// chunk_pow_valid runs verify on every miniblock in order and stops at the first false (returns false), exactly as
// the loop it replaces; it counts each call, whether the miniblock was in the pool before the call (seen; nil =
// unknown, not counted) and whether the call was slow. now is time.Now outside tests.
func chunk_pow_valid(mbls []block.MiniBlock, seen func(block.MiniBlock) bool, verify func(block.MiniBlock) bool,
	now func() time.Time) bool {
	t0 := now()
	chunk_pow_blocks.Inc()
	defer func() { chunk_pow_seconds.Add(now().Sub(t0).Seconds()) }()
	for _, mbl := range mbls {
		if seen != nil && seen(mbl) {
			chunk_pow_pool_seen.Inc()
		}
		c0 := now()
		ok := verify(mbl)
		chunk_pow_checks.Inc()
		if now().Sub(c0) >= CHUNK_POW_SLOW {
			chunk_pow_slow.Inc()
		}
		if !ok {
			return false
		}
	}
	return true
}

// ChunkPowStats is the chunk-path PoW census for RPC/harness readers (the same numbers as /metrics).
type ChunkPowStats struct {
	Blocks   uint64  `json:"blocks"`
	Checks   uint64  `json:"checks"`
	PoolSeen uint64  `json:"pool_seen"`
	Slow     uint64  `json:"slow"`
	Seconds  float64 `json:"seconds"`
}

func Chunk_Pow_Stats() ChunkPowStats {
	return ChunkPowStats{Blocks: chunk_pow_blocks.Get(), Checks: chunk_pow_checks.Get(), PoolSeen: chunk_pow_pool_seen.Get(),
		Slow: chunk_pow_slow.Get(), Seconds: chunk_pow_seconds.Get()}
}
