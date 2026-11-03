// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (verify-txpool): the txids of the block templates this node handed to miners, so the r24 pool cap
// (glue/txpolicy) never evicts one of them. Accept_new_block finds a job's template in chain.mining_blocks_cache
// (an LRU of 256 templates, blockchain/blockchain.go:151) and completes a final miniblock by looking each template
// txid up in the mempool, regpool or block store (blockchain/miner_block.go:529-547); a txid found nowhere fails the
// submission ("Tx not found in pool or DB, rejecting submitted block"), so an eviction there loses a found block.
// TEMPLATE_KEEP matches that LRU: a job whose template has left it cannot be accepted anyway.

import (
	"sync"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
)

const TEMPLATE_KEEP = 256

type template_rec struct {
	ts  uint64
	txs []crypto.Hash
}

var template_txs struct {
	sync.Mutex
	q    []template_rec
	ref  map[crypto.Hash]int
	snap map[crypto.Hash]bool // rebuilt on change; read-only for callers
}

// NoteTemplate records the txids of a template handed out (a cached template served again is recorded once).
func NoteTemplate(bl *block.Block) {
	if bl == nil {
		return
	}
	t := &template_txs
	t.Lock()
	defer t.Unlock()
	for i := len(t.q) - 1; i >= 0 && i >= len(t.q)-4; i-- { // the 100 ms cache serves the same template again
		if t.q[i].ts == bl.Timestamp {
			return
		}
	}
	if t.ref == nil {
		t.ref = map[crypto.Hash]int{}
	}
	rec := template_rec{ts: bl.Timestamp, txs: append([]crypto.Hash(nil), bl.Tx_hashes...)}
	t.q = append(t.q, rec)
	for _, h := range rec.txs {
		t.ref[h]++
	}
	for len(t.q) > TEMPLATE_KEEP {
		for _, h := range t.q[0].txs {
			if t.ref[h]--; t.ref[h] <= 0 {
				delete(t.ref, h)
			}
		}
		t.q = t.q[1:]
	}
	t.snap = nil
}

// TemplateTxs returns the txids carried by the last TEMPLATE_KEEP templates handed out (read-only; do not modify).
func TemplateTxs() map[crypto.Hash]bool {
	t := &template_txs
	t.Lock()
	defer t.Unlock()
	if t.snap == nil {
		t.snap = make(map[crypto.Hash]bool, len(t.ref))
		for h := range t.ref {
			t.snap[h] = true
		}
	}
	return t.snap
}
