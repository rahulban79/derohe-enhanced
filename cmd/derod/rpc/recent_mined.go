// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (txpool): mined transactions stay in the mempool. Nothing removes a tx from it when a block carrying the tx is
// added: the only deletions are HouseKeeping (blockchain.go:284 -> mempool.go:111, every 60 s, once the stable height
// reaches tx.Height) and the console commands (main.go mempool_flush / mempool_delete_tx). Measured on the simulator:
// two blocks selected 23 of 23 pooled txs and the pool still held 23 afterwards (r24 evidence r24_dbg_next_block.txt).
// The block template skips them by reading the Tx_hashes of the blocks at the last 20 heights (miner_block.go:186-247,
// history_tx), but every reader that sums the pool did not: GetFeeEstimate counted already-mined bytes as competing
// for the next block, GetTxStatus's next_block/bytes_ahead counted them as ahead, and the r24 pool cap would count
// them as occupying it. RecentlyMined is the same history the template reads, cached per topoheight.
//
// Window: a mined tx is still pooled only while tx.Height > stable height (HouseKeeping), and a block carrying it has
// height in (tx.Height, tx.Height + TX_VALIDITY_HEIGHT - 1], so every such block is above chain height - STABLE_LIMIT;
// MINED_WINDOW = 20 heights, the template's own history depth, covers that with room.

import (
	"sync"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/cryptography/crypto"
)

const MINED_WINDOW = 20

// MINED_TOPO_SCAN bounds the topo positions read (side blocks share heights; 3 per height is far above the live
// alt-block rate, GetInfo alt_blocks_count 0).
const MINED_TOPO_SCAN = 3 * MINED_WINDOW

var recent_mined struct {
	sync.Mutex
	topo int64
	set  map[crypto.Hash]bool
}

// recent_mined_scan collects the tx hashes of the blocks at topo positions top, top-1, ... while their height is at
// least top_height - MINED_WINDOW (at most MINED_TOPO_SCAN positions). Pure over its two readers.
func recent_mined_scan(top int64, blid_at func(int64) (crypto.Hash, bool), block func(crypto.Hash) (height int64, txs []crypto.Hash, ok bool)) map[crypto.Hash]bool {
	set := map[crypto.Hash]bool{}
	floor := int64(-1)
	for t := top; t >= 0 && t > top-MINED_TOPO_SCAN; t-- {
		blid, ok := blid_at(t)
		if !ok {
			break
		}
		h, txs, ok := block(blid)
		if !ok {
			break
		}
		if floor < 0 {
			floor = h - MINED_WINDOW
		}
		if h < floor {
			break
		}
		for _, x := range txs {
			set[x] = true
		}
	}
	return set
}

// RecentlyMined returns the txids carried by the blocks of the last MINED_WINDOW heights (read-only; do not modify).
func RecentlyMined() map[crypto.Hash]bool {
	if chain == nil {
		return nil
	}
	top := chain.Load_TOPO_HEIGHT()
	recent_mined.Lock()
	defer recent_mined.Unlock()
	if recent_mined.set != nil && recent_mined.topo == top {
		return recent_mined.set
	}
	recent_mined.set = recent_mined_scan(top, func(t int64) (crypto.Hash, bool) {
		h, err := chain.Load_Block_Topological_order_at_index(t)
		return h, err == nil
	}, func(blid crypto.Hash) (int64, []crypto.Hash, bool) {
		bl, err := chain.Load_BL_FROM_ID(blid)
		if err != nil {
			return 0, nil, false
		}
		return int64(bl.Height), bl.Tx_hashes, true
	})
	recent_mined.topo = top
	return recent_mined.set
}

// drop_mined removes the already-mined entries from a template-ordered pool listing; the order of the rest is kept.
func drop_mined(sorted []mempool.TX_Sorting_struct, mined map[crypto.Hash]bool) (out []mempool.TX_Sorting_struct, dropped int) {
	if len(mined) == 0 {
		return sorted, 0
	}
	out = make([]mempool.TX_Sorting_struct, 0, len(sorted))
	for _, s := range sorted {
		if mined[s.Hash] {
			dropped++
			continue
		}
		out = append(out, s)
	}
	return out, dropped
}
