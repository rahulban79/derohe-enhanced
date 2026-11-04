// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Per-connection budget for announced transaction ids (Round 22, security; local relay policy, validity unchanged).
//
// Every txid a peer announces in Peer.NotifyINV costs us a mempool and regpool lookup, a tx_inflight wait check, two
// failed file opens in the tx store (storefs.go ReadTX tries the legacy and the current path), a tx_asked claim and a
// tx_known record, and then an entry in the GetObject request we send back. An INV may carry MAX_INV_TXS (4096)
// txids and nothing limited how often a peer sent one: random txids cost the sender 32 bytes each and us all of the
// above, repeated as fast as the link allows. Honest peers announce one tx per INV (broadcast_Tx), at the network's
// transaction rate.
//
// Each connection now has a token bucket of INV_TX_RATE txids per second (burst INV_TX_BURST). Txids beyond it are
// ignored, not penalised: the peer simply is not asked for them (an honest burst above the bucket loses nothing, the
// other peers announce the same txs). Cost on the honest path: one mutex and a few float operations per INV.
//
// r22 merge (SEC22-2 review): INV_TX_RATE is also a hard per-connection ceiling on how fast this node LEARNS txs from
// one peer: 64 tx/s sustained. Today's network carries < 1 tx per 300 blocks, but the consensus block size
// (STARGATE_HE_MAX_BLOCK_SIZE ~10.25 MB per ~18 s block, ~2 KB/tx) allows ~280 tx/s (estimate). A future high-TPS
// round must raise INV_TX_RATE (and re-check the mempool rebroadcast, which must not send > INV_TX_BURST txids to one
// peer in a burst). p2p_inv_txids_over_budget_total counts what the bucket ignored: it must stay 0 on honest traffic.

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/metrics"
)

const INV_TX_RATE = 64    // announced txids per second per connection ...
const INV_TX_BURST = 1024 // ... with this burst

var inv_txids_over_budget = metrics.Set.NewCounter("p2p_inv_txids_over_budget_total")
var tx_fetch_short_replies = metrics.Set.NewCounter("p2p_tx_fetch_short_replies_total")

type inv_budget struct {
	sync.Mutex
	tokens float64
	last   time.Time
	init   bool
}

// take spends up to n tokens at now and returns how many of the n txids may be processed.
func (b *inv_budget) take(n int, now time.Time) int {
	b.Lock()
	defer b.Unlock()
	if !b.init {
		b.init, b.tokens, b.last = true, INV_TX_BURST, now
	} else if dt := now.Sub(b.last); dt > 0 {
		b.tokens += dt.Seconds() * INV_TX_RATE
		if b.tokens > INV_TX_BURST {
			b.tokens = INV_TX_BURST
		}
		b.last = now
	}
	allowed := n
	if float64(allowed) > b.tokens {
		allowed = int(b.tokens)
	}
	if allowed < 0 {
		allowed = 0
	}
	b.tokens -= float64(allowed)
	return allowed
}

// clip_inv_txs applies c's announced-txid budget to an INV's tx list.
func (c *Connection) clip_inv_txs(list [][32]byte, now time.Time) [][32]byte {
	if len(list) == 0 {
		return list
	}
	n := c.inv_budget.take(len(list), now)
	if n < len(list) {
		inv_txids_over_budget.Add(len(list) - n)
		c.obs.inv_clipped.Add(uint64(len(list) - n)) // r25 (CO24-N5): attributable to this connection
		return list[:n]
	}
	return list
}
