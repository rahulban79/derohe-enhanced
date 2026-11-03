// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Receiver-side compact block reconstruction (Round 20; no wire change, no handshake capability, nothing a peer sees).
//
// Every erasure-coded chunk already carries the whole block (header, the 10 miniblocks and the tx hashes, field BL);
// only the transactions travel in the Reed-Solomon shards. A block without transactions is therefore complete on its
// first chunk (feed_chunk), which is the "compact block" of other chains, already. A block WITH transactions waited
// for CHUNK_NEED (16) chunks from the network even when every one of its transactions was already in our mempool or
// regpool, which is the normal case because the block builder took them from its own mempool.
//
// Now, when the first verified chunk of such a block arrives and every tx hash resolves in our pools, the block is
// assembled from the pool copies and offered to the unchanged Add_Complete_Block, then re-chunked and announced by
// the unchanged Broadcast_Block, so this node serves all 48 chunks instead of the few it had. If any tx is missing,
// or the chain refuses the assembled block, nothing is marked processed and the chunk path continues exactly as
// before. It is tried once per block.
//
// Safety: Add_Complete_Block checks that the txs are a permutation of the block's tx hashes but then stores Txs[i]
// under Tx_hashes[i] (blockchain.go WriteTX), so the order matters. compact_block_txs builds the list strictly in
// Tx_hashes order and re-checks each decoded copy's hash. The copies are freshly decoded from the pool bytes, so the
// chain never shares a *Transaction with the mempool.
//
// Live share (GetBlockHeadersRange over topoheights 7,817,690-7,822,689): 10 of 5,000 blocks (0.2%) carried any
// transaction, so the propagation gain is limited to those blocks.

import (
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// COMPACT_BLOCKS (env DERO_COMPACT_BLOCKS=0 disables) gates the receiver-side reconstruction.
var COMPACT_BLOCKS = env_int("DERO_COMPACT_BLOCKS", 1, 0, 1) == 1

// compact_block_txs returns fresh copies of the block's transactions from the local pools, in Tx_hashes order, or
// ok=false if any is missing or does not hash to its slot.
func compact_block_txs(hashes []crypto.Hash, pool_tx func(crypto.Hash) *transaction.Transaction) (txs []*transaction.Transaction, ok bool) {
	txs, _, ok = compact_block_txs_raw(hashes, pool_tx)
	return
}

// compact_block_txs_raw is compact_block_txs that also returns the pool bytes each copy was decoded from
// (raws[i] belongs to txs[i]), so an accepted compact block can be observed like every other block path (r24, B18).
func compact_block_txs_raw(hashes []crypto.Hash, pool_tx func(crypto.Hash) *transaction.Transaction) (txs []*transaction.Transaction, raws [][]byte, ok bool) {
	if len(hashes) == 0 {
		return nil, nil, false
	}
	for _, h := range hashes {
		ptx := pool_tx(h)
		if ptx == nil {
			return nil, nil, false
		}
		var cp transaction.Transaction
		raw := ptx.Serialize()
		if err := deserialize_tx(&cp, raw); err != nil || cp.GetHash() != h {
			return nil, nil, false
		}
		txs = append(txs, &cp)
		raws = append(raws, raw)
	}
	return txs, raws, true
}

func pool_tx(txid crypto.Hash) *transaction.Transaction {
	if tx := chain.Mempool.Mempool_Get_TX(txid); tx != nil {
		return tx
	}
	return chain.Regpool.Regpool_Get_TX(txid)
}

// try_compact runs the reconstruction at most once per block (state.compact_tried), only while fewer than need chunks
// are held, and marks the block processed only when add reports success. Called with chunk_lock held.
// r24: txs also returns the pool bytes of each tx (compact_block_txs_raw) and add receives them for the observation.
func try_compact(state *Chunks_Per_Block_Data, have, need int, txs func() ([]*transaction.Transaction, [][]byte, bool), add func([]*transaction.Transaction, [][]byte) bool) bool {
	if !COMPACT_BLOCKS || state.Processed || state.compact_tried || have >= need || state.bl == nil || len(state.bl.Tx_hashes) == 0 {
		return false
	}
	state.compact_tried = true
	list, raws, ok := txs()
	if !ok {
		metrics.Set.GetOrCreateCounter("p2p_compact_block_misses_total").Inc() // a tx is not in our pools: wait for chunks
		return false
	}
	if !add(list, raws) {
		metrics.Set.GetOrCreateCounter("p2p_compact_block_rejects_total").Inc()
		return false
	}
	state.Processed = true
	metrics.Set.GetOrCreateCounter("p2p_compact_block_hits_total").Inc()
	return true
}

// add_compact_block offers the assembled block to the chain and relays it on success, as processChunkedBlock does.
// r24 (B18): raws are the pool bytes txs were decoded from; the txs of an ACCEPTED compact block are observed
// (txcanon.Observe, a counter only) exactly as the sync and chunk paths observe theirs. Before r24 this path, which
// carried every live tx block (p2p_compact_block_hits_total 3, block_tx_roundtrip_observed_total 0 on r23c), was the
// one block path the round-trip census never saw. A block already in the chain is not observed again.
func (connection *Connection) add_compact_block(bl *block.Block, txs []*transaction.Transaction, raws [][]byte) bool {
	cp := *bl // the chain gets its own copy of the header too
	cbl := block.Complete_Block{Bl: &cp, Txs: txs}
	blid := cp.GetHash()
	if chain.Is_Block_Topological_order(blid) || chain.Is_Block_Tip(blid) {
		return true
	}
	if _, ok := Add_Complete_Block_HF3(chain, &cbl); !ok {
		return false
	}
	connection.logger.V(2).Info("block assembled from first chunk and local pools", "blid", blid, "txcount", len(txs))
	Broadcast_Block(&cbl, connection.Peer_ID)
	observe_block_txs(raws, txs) // r24 (B18): only txs of an accepted block are observed
	return true
}
