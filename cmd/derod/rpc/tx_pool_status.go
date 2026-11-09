// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (txpool): GetTxStatus answers, for a tx in this node's mempool, when it stops being minable, from when a
// wallet may safely rebuild it, and where it stands in this node's block-template order. Read-only, node-local.
//
// Expiry, from the consensus rules (nothing here changes them):
//   - blockchain.go:786: a block at height b may carry the tx only if b - tx.Height < TX_VALIDITY_HEIGHT, so the last
//     height that may include it is L = tx.Height + TX_VALIDITY_HEIGHT - 1 (last_block_height).
//   - blockchain.go:480-483: a node at chain height H refuses every block of height below H - STABLE_LIMIT.
//     So once H - STABLE_LIMIT > L, i.e. H >= L + STABLE_LIMIT + 1 (rebuild_safe_height), no block this node can
//     still accept can include the tx: a wallet that rebuilds the payment from then on cannot pay twice.
//   - HouseKeeping (blockchain.go:284 -> mempool.go:111, every 60 s) drops it from this pool once the stable height
//     H - STABLE_LIMIT reaches tx.Height (pool_purge_height = tx.Height + STABLE_LIMIT, up to 60 s later).
// Order: Mempool_List_TX_SortedInfo, the list the template walks (miner_block.go:229-247), with the template's byte
// budget (BLOCK_TX_CAPACITY): next_block says whether the tx is inside that budget in this order. An estimate, as in
// GetFeeEstimate: the template also skips txs for nonce, history and reference reasons, and txs of equal milli-unit
// fee per byte are listed in no defined order (B19; the pool sorts by MilliFeesPerByte since r29).

import (
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// TxPoolStatus is filled for state "pool" only.
type TxPoolStatus struct {
	RefHeight         int64  `json:"ref_height"`          // tx.Height: the block height it was built against
	LastBlockHeight   int64  `json:"last_block_height"`   // highest block height that may include it
	RebuildSafeHeight int64  `json:"rebuild_safe_height"` // chain height from which no acceptable block can include it
	PoolPurgeHeight   int64  `json:"pool_purge_height"`   // chain height at which this node's pool drops it
	Expired           bool   `json:"expired"`             // chain height >= rebuild_safe_height
	Size              uint64 `json:"size"`
	Fee               uint64 `json:"fee"`
	FeePerKB          uint64 `json:"fee_per_kb"`    // exact fee*1024/size
	FeesPerByte       uint64 `json:"fees_per_byte"` // the integer rank the template sorts by (fee/size)
	PoolRank          int    `json:"pool_rank"`     // 1-based position in the template order; 0: not listed as ready
	BytesAhead        uint64 `json:"bytes_ahead"`   // bytes of txs listed before it
	NextBlock         bool   `json:"next_block"`    // inside the template's byte budget in that order (estimate)
}

// tx_pool_status is pure: tx (nil: no detail), the template order and the chain height.
func tx_pool_status(txid crypto.Hash, tx *transaction.Transaction, order []mempool.TX_Sorting_struct, chain_height int64) *TxPoolStatus {
	if tx == nil {
		return nil
	}
	ps := &TxPoolStatus{RefHeight: int64(tx.Height)}
	ps.LastBlockHeight = ps.RefHeight + blockchain.TX_VALIDITY_HEIGHT - 1
	ps.RebuildSafeHeight = ps.LastBlockHeight + config.STABLE_LIMIT + 1
	ps.PoolPurgeHeight = ps.RefHeight + config.STABLE_LIMIT
	ps.Expired = chain_height >= ps.RebuildSafeHeight
	ps.Fee = tx.Fees()
	ahead := uint64(0)
	for i, o := range order {
		if o.Hash == txid {
			ps.PoolRank, ps.BytesAhead, ps.Size, ps.FeesPerByte = i+1, ahead, o.Size, o.FeesPerByte
			ps.NextBlock = ahead+o.Size <= BLOCK_TX_CAPACITY && !ps.Expired
			break
		}
		ahead += o.Size
	}
	if ps.Size == 0 {
		ps.Size = uint64(len(tx.Serialize()))
		ps.FeesPerByte = ps.Fee / ps.Size
	}
	ps.FeePerKB = ps.Fee * 1024 / ps.Size
	return ps
}

// apply_pool_status fills Pool for every "pool" answer; the pool is listed once per call, and only if one is needed.
func apply_pool_status(txs []TxStatus, pool *mempool.Mempool, chain_height int64, mined func() map[crypto.Hash]bool) {
	var order []mempool.TX_Sorting_struct
	listed := false
	for i := range txs {
		if txs[i].State != "pool" {
			continue
		}
		h := crypto.HashHexToHash(txs[i].TxID)
		tx := pool.Mempool_Get_TX(h)
		if tx == nil {
			continue // left the pool since it was classified
		}
		if !listed {
			// r24: txs the recent blocks already carry stay pooled but are never selected again (recent_mined.go)
			order, _ = drop_mined(pool.Mempool_List_TX_SortedInfo(), mined())
			listed = true
		}
		txs[i].Pool = tx_pool_status(h, tx, order, chain_height)
	}
}
