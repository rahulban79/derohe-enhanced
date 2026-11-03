// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rpc

// DERO.GetFeeEstimate (r23): what fee gets a transaction into the next block, read from this node's mempool with the
// node's own selection rule. Read-only; nothing here is consensus-visible.
//
// How a block template picks transactions (blockchain/miner_block.go:228-247): Mempool_List_TX_SortedInfo orders the
// ready mempool by FeesPerByte DESCENDING, and the template takes them in that order until the next one would push
// the block past STARGATE_HE_MAX_BLOCK_SIZE - 102400 bytes (then it stops). FeesPerByte is an INTEGER division
// (blockchain/mempool/mempool.go:184, fees / size): a tx whose fee is smaller than its size in bytes ranks 0, like every
// other such tx, in no particular order. Paying more therefore changes a tx's place only in whole steps of one atomic
// unit per byte (1024 per KB, 51x the FEE_PER_KB floor of 20). The floor itself is Calculate_TX_fee
// (blockchain/tx_fees.go): FEE_PER_KB for every started KB.
//
// So the estimate is: while the ready pool fits in one block, the floor is enough (next_block_fee_per_byte 0); when it
// does not, a tx must rank above the first tx that no longer fits, i.e. pay (cutoff FeesPerByte + 1) per byte.
// It is an estimate: the template also skips txs for nonce, history and age reasons, and the pool moves.
//
// Cost: one pass over the ready mempool (the same listing a block template makes), at most once per
// FEE_ESTIMATE_TTL; callers in between get the cached pool summary (the size-dependent fee is computed per call).

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/txpolicy"
)

const FEE_ESTIMATE_TTL = time.Second

// BLOCK_TX_CAPACITY is the byte budget a template fills with transactions (miner_block.go:247).
const BLOCK_TX_CAPACITY = config.STARGATE_HE_MAX_BLOCK_SIZE - 102400

type GetFeeEstimate_Params struct {
	Size uint64 `json:"size"` // optional: a transaction size in bytes, to get fee_for_size
}

type GetFeeEstimate_Result struct {
	TopoHeight          int64  `json:"topoheight"`
	MinFeePerKB         uint64 `json:"min_fee_per_kb"`          // consensus floor, per started KB
	PoolTxs             int    `json:"pool_txs"`                // ready mempool txs (selectable at this height)
	PoolBytes           uint64 `json:"pool_bytes"`              // their total size
	BlockCapacityBytes  uint64 `json:"block_capacity_bytes"`    // bytes of txs one block template takes
	BlocksToClear       int64  `json:"blocks_to_clear"`         // ceil(pool_bytes / block_capacity_bytes)
	NextBlockFeePerByte uint64 `json:"next_block_fee_per_byte"` // 0: the floor gets into the next block
	PoolFeePerKBP10     uint64 `json:"pool_fee_per_kb_p10"`     // fee/KB of the ready pool (exact fee*1024/size)
	PoolFeePerKBP50     uint64 `json:"pool_fee_per_kb_p50"`
	PoolFeePerKBP90     uint64 `json:"pool_fee_per_kb_p90"`
	PoolFeePerByteZero  int    `json:"pool_fee_per_byte_zero"` // ready txs that rank 0 (fee < size in bytes)
	FeeForSize          uint64 `json:"fee_for_size,omitempty"` // when size is given: fee for the next block
	FloorForSize        uint64 `json:"floor_for_size,omitempty"`
	// r24: the node-local pool cap (glue/txpolicy). When the pool is full a tx is admitted only if it pays more per
	// byte than the lowest-paying tx in it; fee_for_size then also covers that (enter_fee_for_size).
	PoolMinedTxs    int    `json:"pool_mined_txs"` // r24: pooled txs that recent blocks already carry (not counted above)
	PoolCapBytes    uint64 `json:"pool_cap_bytes,omitempty"`
	PoolFull        bool   `json:"pool_full"`
	PoolMinFeePerKB uint64 `json:"pool_min_fee_per_kb,omitempty"`
	EnterFeeForSize uint64 `json:"enter_fee_for_size,omitempty"`
	Cached          bool   `json:"cached"`
	Status          string `json:"status"`
}

// fee_pool_entry is one ready mempool tx in selection order.
type fee_pool_entry struct {
	size, fee, per_byte uint64
}

// fee_summary computes everything that does not depend on the caller's size. entries must be in the node's
// selection order (FeesPerByte descending).
func fee_summary(entries []fee_pool_entry, capacity uint64) (r GetFeeEstimate_Result) {
	r.MinFeePerKB = config.FEE_PER_KB
	r.BlockCapacityBytes = capacity
	r.PoolTxs = len(entries)
	used := uint64(0)
	cut := -1
	per_kb := make([]uint64, 0, len(entries))
	for i, e := range entries {
		r.PoolBytes += e.size
		if cut < 0 {
			if used+e.size > capacity {
				cut = i
			} else {
				used += e.size
			}
		}
		if e.size > 0 {
			per_kb = append(per_kb, e.fee*1024/e.size)
		}
		if e.per_byte == 0 {
			r.PoolFeePerByteZero++
		}
	}
	if cut >= 0 {
		r.NextBlockFeePerByte = entries[cut].per_byte + 1
	}
	if capacity > 0 {
		r.BlocksToClear = int64((r.PoolBytes + capacity - 1) / capacity)
	}
	if len(per_kb) > 0 {
		sort.Slice(per_kb, func(i, j int) bool { return per_kb[i] < per_kb[j] })
		at := func(p int) uint64 { // nearest rank: the smallest value with at least p% of the pool at or below it
			i := (len(per_kb)*p + 99) / 100
			if i < 1 {
				i = 1
			}
			return per_kb[i-1]
		}
		r.PoolFeePerKBP10, r.PoolFeePerKBP50, r.PoolFeePerKBP90 = at(10), at(50), at(90)
	}
	return
}

// floor_fee is Calculate_TX_fee: FEE_PER_KB per started KB.
func floor_fee(size uint64) uint64 {
	kb := size / 1024
	if size%1024 != 0 {
		kb++
	}
	return kb * config.FEE_PER_KB
}

// fee_for_size: the floor while the pool fits, else enough to rank above the cutoff (per_byte * size), never below the
// floor.
func fee_for_size(next_per_byte, size uint64) uint64 {
	f := floor_fee(size)
	if need := next_per_byte * size; need > f {
		return need
	}
	return f
}

var fee_cache struct {
	sync.Mutex
	at  time.Time
	key [2]int64 // topoheight, mempool listing length
	r   GetFeeEstimate_Result
}

// fee_entries lists the ready mempool in selection order with each tx's exact fee.
// r24: without the txs the recent blocks already carry (recent_mined.go): they stay pooled until HouseKeeping, and the
// template skips them, so they never compete for the next block.
func fee_entries(pool *mempool.Mempool, mined map[crypto.Hash]bool) ([]fee_pool_entry, int) {
	sorted, dropped := drop_mined(pool.Mempool_List_TX_SortedInfo(), mined)
	out := make([]fee_pool_entry, 0, len(sorted))
	for _, s := range sorted {
		e := fee_pool_entry{size: s.Size, per_byte: s.FeesPerByte}
		if tx := pool.Mempool_Get_TX(s.Hash); tx != nil {
			e.fee = tx.Fees()
		} else {
			continue // left the pool since the listing
		}
		out = append(out, e)
	}
	return out, dropped
}

func GetFeeEstimate(ctx context.Context, p GetFeeEstimate_Params) (result GetFeeEstimate_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	if p.Size > config.STARGATE_HE_MAX_TX_SIZE {
		return result, fmt.Errorf("size must be at most %d bytes", config.STARGATE_HE_MAX_TX_SIZE)
	}
	topo := chain.Load_TOPO_HEIGHT()
	key := [2]int64{topo, int64(len(chain.Mempool.Mempool_List_TX()))}
	fee_cache.Lock()
	if !fee_cache.at.IsZero() && time.Since(fee_cache.at) < FEE_ESTIMATE_TTL && fee_cache.key == key {
		result = fee_cache.r
		result.Cached = true
	} else {
		entries, mined := fee_entries(chain.Mempool, RecentlyMined())
		result = fee_summary(entries, BLOCK_TX_CAPACITY)
		result.PoolMinedTxs = mined
		result.TopoHeight = topo
		fee_cache.r, fee_cache.key, fee_cache.at = result, key, time.Now()
	}
	fee_cache.Unlock()
	pol := txpolicy.Snapshot() // r24
	result.PoolCapBytes, result.PoolFull, result.PoolMinFeePerKB = pol.CapBytes, pol.Full, pol.MinFeePerKB
	if p.Size > 0 {
		result.FloorForSize = floor_fee(p.Size)
		result.FeeForSize = fee_for_size(result.NextBlockFeePerByte, p.Size)
		if result.EnterFeeForSize = txpolicy.FeeToEnter(p.Size); result.EnterFeeForSize > result.FeeForSize {
			result.FeeForSize = result.EnterFeeForSize
		}
	}
	result.Status = "OK"
	return result, nil
}
