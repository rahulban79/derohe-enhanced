// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// HF3 grandfather table: one place that prepares a pre-HF3 block before the chain executes it (Round 23b).
//
// blockchain/transaction_execute.go:244 executes a tx of blockchain.HF3_Affected_Txs with the entry's Parity, not the
// tx's own Proof.Parity(), whatever that field holds. The 75 literals set only Tx_Parity; Parity is computed by p2p as
// (block height > entry.Height) == entry.Tx_Parity, and until r23 only the sync path (process_object_response) did so.
// Every other way a block reaches Add_Complete_Block left the field at its last value (false after a start):
//   - processChunkedBlock (a block relayed as erasure-coded chunks; accepted within +-3 of our height),
//   - add_compact_block (a block assembled from the first chunk and the pools),
//   - the rewind path's ramstore (dead today: pop_count is never assigned),
//   - derod's console block_import.
// A table tx executed with the wrong parity advances the nonce slots of the wrong ring members, so this node's balance
// tree differs from every other node's from that block on; every later tx's Statement.Roothash then fails here
// (transaction_verify.go) and the node stalls: a liveness fault on a node that replays the pre-HF3 range, reachable by
// any peer that relays a historical block as chunks while that node syncs it. Entries whose Tx_Parity is false need
// Parity = true in their own block (58 of 75); entries mined again in a later block need Tx_Parity.
//
// The field is also process-global, written and read on different goroutines: two connections preparing two blocks
// that carry the same txid at different heights (the "duplicates" of the table) could each execute with the other's
// value. hf3_exec_mu makes "set, then execute" one step for blocks that carry a table tx; other blocks never take it.
//
// Consensus: unchanged. The value is the one the sync path has always computed (byte for byte the same expression);
// this only applies it on every path. Blocks at or above MAJOR_HF3_HEIGHT and blocks without a table tx are passed
// straight to Add_Complete_Block.

import (
	"sync"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

var hf3_exec_mu sync.Mutex

// hf3_carries reports whether a block at height carries a tx of the HF3 table (only below MAJOR_HF3_HEIGHT).
func hf3_carries(height uint64, txs []*transaction.Transaction) bool {
	if height >= uint64(globals.Config.MAJOR_HF3_HEIGHT) {
		return false
	}
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if _, ok := blockchain.HF3_Affected_Txs[tx.GetHash().String()]; ok {
			return true
		}
	}
	return false
}

// apply_hf3_parity is the sync path's HF3 step for one block: verify (which stores the table's proof and nonce
// bypasses), then Parity = (height > entry.Height) == entry.Tx_Parity. Caller holds hf3_exec_mu.
func apply_hf3_parity(height uint64, txs []*transaction.Transaction, verify func(*transaction.Transaction)) (n int) {
	if height >= uint64(globals.Config.MAJOR_HF3_HEIGHT) {
		return 0
	}
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		if t, ok := blockchain.HF3_Affected_Txs[tx.GetHash().String()]; ok {
			if verify != nil {
				verify(tx)
			}
			t.Parity = (height > t.Height) == t.Tx_Parity
			n++
		}
	}
	return n
}

// hf3_add runs add for cbl, preparing the HF3 table first (and atomically with add) when cbl carries a table tx.
func hf3_add(cbl *block.Complete_Block, verify func(*transaction.Transaction), add func(*block.Complete_Block) (error, bool)) (error, bool) {
	if cbl == nil || cbl.Bl == nil || !hf3_carries(cbl.Bl.Height, cbl.Txs) {
		return add(cbl)
	}
	hf3_exec_mu.Lock()
	defer hf3_exec_mu.Unlock()
	metrics.Set.GetOrCreateCounter("p2p_hf3_table_blocks_total").Inc()
	apply_hf3_parity(cbl.Bl.Height, cbl.Txs, verify)
	return add(cbl)
}

// Add_Complete_Block_HF3 is c.Add_Complete_Block with the HF3 table prepared exactly as the sync path prepares it.
// Every caller outside the blockchain package that offers a block to the chain uses it (TestR23bAddCompleteBlockCensus).
func Add_Complete_Block_HF3(c *blockchain.Blockchain, cbl *block.Complete_Block) (error, bool) {
	return hf3_add(cbl, func(tx *transaction.Transaction) { c.Verify_Transaction_NonCoinbase(tx) }, c.Add_Complete_Block)
}
