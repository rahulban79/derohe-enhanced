// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// Settled-tx cache for GetTxStatus / WatchTx (Round 23b, rpcws).
//
// Measured on the live mainnet node (2026-10-30, 100 sequential loopback calls): GetTxStatus of ONE mined txid costs
// 16.8 ms p50 and 8 txids 89 ms, because chain.IS_TX_Valid reads and decodes the tx and then every block of the
// 2*TX_VALIDITY_HEIGHT heights after tx.Height (blockchain.go:1398-1434). For a tx that is long settled the answer
// can no longer change, so it is kept here:
//
//   - IS_TX_Valid answers the LAST topo-ordered block in heights [tx.Height+1, tx.Height+1+2*TX_VALIDITY_HEIGHT]
//     holding the txid. The mined block's height is >= tx.Height+1, so that window ends at or below
//     block_height + 2*TX_VALIDITY_HEIGHT. An answer is stored only when that bound is at or below the final height
//     (rpc_dero_gettxstatus.go final_height_scan): every block in the window is then settled, whatever tip wins.
//   - every hit is re-checked against the topo index (one Topo_store record read): if the block is no longer at the
//     stored topoheight the entry is dropped and the full lookup runs. A finality violation seen by the reorg monitor
//     (reorg_events.go) also empties the cache.
//
// Bounded (FINAL_TX_CACHE_MAX entries; when full the older half is dropped). DERO_TXSTATUS_CACHE=0 turns it off.
// Read-only, node-local; nothing here changes what the node accepts.

import (
	"os"
	"sync"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	dmetrics "github.com/deroproject/derohe/metrics"
)

const FINAL_TX_CACHE_MAX = 16384

type final_tx_entry struct {
	blid   crypto.Hash
	topo   int64
	height int64
}

type final_tx_cache struct {
	sync.Mutex
	on    bool
	by_tx map[crypto.Hash]final_tx_entry
	old   map[crypto.Hash]final_tx_entry // the previous half, still served (promoted on hit)
	by_bl map[crypto.Hash]final_tx_entry // block id -> its topo/height (for topo_of/height_of on a hit)
}

func new_final_tx_cache(on bool) *final_tx_cache {
	return &final_tx_cache{on: on, by_tx: map[crypto.Hash]final_tx_entry{}, old: map[crypto.Hash]final_tx_entry{}, by_bl: map[crypto.Hash]final_tx_entry{}}
}

var final_txs = new_final_tx_cache(os.Getenv("DERO_TXSTATUS_CACHE") != "0")

var (
	final_tx_hits    = dmetrics.Set.GetOrCreateCounter(`rpc_txstatus_final_cache_total{result="hit"}`)
	final_tx_misses  = dmetrics.Set.GetOrCreateCounter(`rpc_txstatus_final_cache_total{result="miss"}`)
	final_tx_stale   = dmetrics.Set.GetOrCreateCounter(`rpc_txstatus_final_cache_total{result="stale"}`)
	final_tx_stored  = dmetrics.Set.GetOrCreateCounter(`rpc_txstatus_final_cache_total{result="stored"}`)
	final_tx_flushes = dmetrics.Set.GetOrCreateCounter("rpc_txstatus_final_cache_flushes_total")
)

// settled reports whether a tx mined in a block at height may be cached at final height final.
func final_tx_settled(height, final int64) bool {
	return height > 0 && final >= 0 && height+2*blockchain.TX_VALIDITY_HEIGHT <= final
}

// lookup returns the cached block of txid if blid_at(topo) still names it; a mismatch drops the entry.
func (c *final_tx_cache) lookup(txid crypto.Hash, blid_at func(int64) (crypto.Hash, error)) (e final_tx_entry, ok bool) {
	c.Lock()
	if !c.on {
		c.Unlock()
		return e, false
	}
	e, ok = c.by_tx[txid]
	if !ok {
		if e, ok = c.old[txid]; ok {
			c.by_tx[txid] = e // promote
			delete(c.old, txid)
		}
	}
	c.Unlock()
	if !ok {
		final_tx_misses.Inc()
		return e, false
	}
	if b, err := blid_at(e.topo); err != nil || b != e.blid { // verify on hit
		c.Lock()
		delete(c.by_tx, txid)
		delete(c.old, txid)
		delete(c.by_bl, e.blid)
		c.Unlock()
		final_tx_stale.Inc()
		return final_tx_entry{}, false
	}
	final_tx_hits.Inc()
	return e, true
}

func (c *final_tx_cache) block(blid crypto.Hash) (e final_tx_entry, ok bool) {
	c.Lock()
	defer c.Unlock()
	e, ok = c.by_bl[blid]
	return
}

func (c *final_tx_cache) store(txid crypto.Hash, e final_tx_entry) {
	c.Lock()
	defer c.Unlock()
	if !c.on {
		return
	}
	if _, ok := c.by_tx[txid]; ok {
		return
	}
	if len(c.by_tx) >= FINAL_TX_CACHE_MAX/2 { // rotate: the older half goes
		c.old = c.by_tx
		c.by_tx = make(map[crypto.Hash]final_tx_entry, FINAL_TX_CACHE_MAX/2)
		c.by_bl = make(map[crypto.Hash]final_tx_entry, len(c.old))
		for _, o := range c.old {
			c.by_bl[o.blid] = o
		}
	}
	c.by_tx[txid] = e
	c.by_bl[e.blid] = e
	final_tx_stored.Inc()
}

func (c *final_tx_cache) flush() {
	c.Lock()
	defer c.Unlock()
	c.by_tx = map[crypto.Hash]final_tx_entry{}
	c.old = map[crypto.Hash]final_tx_entry{}
	c.by_bl = map[crypto.Hash]final_tx_entry{}
	final_tx_flushes.Inc()
}

func (c *final_tx_cache) size() int {
	c.Lock()
	defer c.Unlock()
	return len(c.by_tx) + len(c.old)
}

// final_cache_sink is implemented by sources whose settled answers may be cached (chain_tx_status).
type final_cache_sink interface {
	remember_final(txid crypto.Hash, blid crypto.Hash, topo, height, final int64)
}

func (s chain_tx_status) remember_final(txid crypto.Hash, blid crypto.Hash, topo, height, final int64) {
	if !final_tx_settled(height, final) || topo < 0 {
		return
	}
	final_txs.store(txid, final_tx_entry{blid: blid, topo: topo, height: height})
}

func (s chain_tx_status) topo_blid(t int64) (h crypto.Hash, err error) {
	r, err := s.ch().Store.Topo_store.Read(t)
	if err != nil {
		return h, err
	}
	return r.BLOCK_ID, nil
}
