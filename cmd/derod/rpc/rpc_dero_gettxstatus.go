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

// DERO.GetTxStatus (r20): where are these transactions now? For up to MAX_TX_STATUS txids per call it answers
// mined (with topoheight, block hash and confirmations), pool, regpool, orphaned (stored, but in no valid block) or
// unknown. A wallet or exchange watching its own sends used to call GetTransaction for that, which also expands
// every ring member to an address (a balance-tree snapshot per tx); this reads the tx store, the validity index and
// the pools only. Combined with the existing Block/Height push on /ws, a client can follow confirmations with ONE
// call per new block, without a per-connection server-side subscription.
//
// Cost bounds: at most MAX_TX_STATUS txids per call (more is an error, never a silent clip); a call with more than
// TX_STATUS_FREE txids takes one of the node-wide range slots (rpc_dero_explorer.go) like the other multi-item reads;
// ctx is checked per txid, so a disconnected client stops costing reads. Read-only: no consensus state is touched.
//
// Semantics (r20 merge, RW-07 review): "mined" = the txid appears in a topo-ordered block within the tx's height
// window, the same rule as GetTransaction's ValidBlock (chain.IS_TX_Valid); it does not prove that the tx executed.
// A valid block that has no topological position (topo_of < 0) is reported "unconfirmed", never "mined" with
// topoheight -1. "orphaned" = stored, but no valid block was found, which also covers a tx whose height window is
// outside the indexed range (a pruned node). The cost gain over GetTransaction is an estimate, not benchmarked.

import "context"
import "fmt"
import "strings"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/blockchain"

const MAX_TX_STATUS = 64
const TX_STATUS_FREE = 8 // small polls (a wallet's few pending sends) never queue behind explorer range calls

type GetTxStatus_Params struct {
	TxIDs []string `json:"txids"`
}

type TxStatus struct {
	TxID          string `json:"txid"`
	State         string `json:"state"` // mined | unconfirmed | pool | regpool | orphaned | unknown | invalid_txid
	TopoHeight    int64  `json:"topoheight"`
	BlockHash     string `json:"block_hash,omitempty"`
	Confirmations int64  `json:"confirmations"` // tip topoheight - topoheight + 1 for mined, else 0
	// r23 finality (see final_height): Height is the mined block's height (0 otherwise); Final means no block the
	// network can still accept can change where this tx is (reorg-safe); BlocksToFinal is how many more heights the
	// chain must grow before Final can be true (0 once final or when not mined; an estimate when no sync block exists
	// yet above the tx).
	Height        int64 `json:"height,omitempty"`
	Final         bool  `json:"final"`
	BlocksToFinal int64 `json:"blocks_to_final,omitempty"`
	// r24 (txpool): expiry, rebuild safety and template position of a tx in this node's mempool (tx_pool_status.go)
	Pool *TxPoolStatus `json:"pool,omitempty"`
}

type GetTxStatus_Result struct {
	TopoHeight int64      `json:"topoheight"`
	Txs        []TxStatus `json:"txs"`
	Status     string     `json:"status"`
	// r23: StableHeight is GetInfo's stableheight (height - STABLE_LIMIT); FinalHeight is the highest height at or
	// below which every mined tx is final (-1: none found in the scanned window).
	StableHeight int64 `json:"stable_height"`
	FinalHeight  int64 `json:"final_height"`
}

// tx_finality_source is what finality needs on top of tx_status_source; sources without it (tests) report no
// finality fields.
type tx_finality_source interface {
	height_of(blid crypto.Hash) int64
	final_height() (final, stable int64)
	chain_height() int64
}

// FINAL_SCAN bounds the heights final_height inspects (one topo-index lookup each).
const FINAL_SCAN = 64

// final_height_scan: finality from the consensus rules, not from a confirmation count.
//
//   - blockchain.go:481-484 refuses every block whose height is below chain height - STABLE_LIMIT, so heights below
//     H-STABLE_LIMIT never get another block, and a new block's parent is at H-STABLE_LIMIT-1 or above.
//   - A sync height s (exactly one topo-ordered block there, the IsBlockSyncBlockHeightSpecific rule) with
//     s <= H-STABLE_LIMIT-1 can never gain a second block, so every later block descends from that one block and the
//     order of everything at or below s is settled whatever tip wins.
//
// So the answer is the highest such s, scanning down from H-STABLE_LIMIT-1 at most FINAL_SCAN heights; -1 if none.
// blocks_at(h) returns the number of topo-ordered blocks at height h.
func final_height_scan(chain_height int64, stable_limit int64, blocks_at func(h int64) int) int64 {
	top := chain_height - stable_limit - 1
	for s := top; s >= 0 && s > top-FINAL_SCAN; s-- {
		if blocks_at(s) == 1 {
			return s
		}
	}
	return -1
}

// finality reads the final and stable heights once and returns apply, which fills Height, Final and BlocksToFinal of
// one mined entry (other entries are left as they are). ok=false when src has no finality support (tests); apply is
// then a no-op and both heights are -1.
func finality(src tx_status_source, chain_height int64) (apply func(s *TxStatus), final, stable int64, ok bool) {
	fs, ok := src.(tx_finality_source)
	if !ok {
		return func(*TxStatus) {}, -1, -1, false
	}
	final, stable = fs.final_height()
	apply = func(s *TxStatus) {
		if s.State != "mined" || s.BlockHash == "" {
			return
		}
		blid := crypto.HashHexToHash(s.BlockHash)
		s.Height = fs.height_of(blid)
		s.Final = final >= 0 && s.Height <= final
		if sink, ok := src.(final_cache_sink); ok && s.Final { // r23b: settled answers skip IS_TX_Valid next time
			sink.remember_final(crypto.HashHexToHash(s.TxID), blid, s.TopoHeight, s.Height, final)
		}
		s.BlocksToFinal = 0
		if !s.Final {
			// the chain height at which s.Height <= H - STABLE_LIMIT - 1, assuming that height is then a sync height
			if need := s.Height + config.STABLE_LIMIT + 1 - chain_height; need > 0 {
				s.BlocksToFinal = need
			} else {
				s.BlocksToFinal = 1
			}
		}
	}
	return apply, final, stable, true
}

// tx_status_source is what tx_status needs from the chain (an interface so the classification is testable).
type tx_status_source interface {
	valid_block(h crypto.Hash) (blid crypto.Hash, ok bool)
	topo_of(blid crypto.Hash) int64
	stored(h crypto.Hash) bool
	in_mempool(h crypto.Hash) bool
	in_regpool(h crypto.Hash) bool
}

// tx_status classifies one txid against the chain top.
func tx_status(txid string, top int64, src tx_status_source) (s TxStatus) {
	s.TxID = strings.TrimSpace(txid)
	s.TopoHeight = -1
	if len(s.TxID) != 64 {
		s.State = "invalid_txid"
		return
	}
	h := crypto.HashHexToHash(s.TxID)
	if h.IsZero() {
		s.State = "invalid_txid"
		return
	}
	if blid, ok := src.valid_block(h); ok {
		s.BlockHash = blid.String()
		if topo := src.topo_of(blid); topo < 0 {
			s.State = "unconfirmed" // in a block without a topological position: no confirmations to count
			return
		} else {
			s.TopoHeight = topo
		}
		s.State = "mined"
		if top >= s.TopoHeight {
			s.Confirmations = top - s.TopoHeight + 1
		}
		return
	}
	switch {
	case src.in_mempool(h):
		s.State = "pool"
	case src.in_regpool(h):
		s.State = "regpool"
	case src.stored(h):
		s.State = "orphaned"
	default:
		s.State = "unknown"
	}
	return
}

// chain_tx_status reads c, or the package's chain when c is nil (r21: tx_events_loop passes the chain it was
// started with, so a later RPCServer_Start in the same process does not race with it).
type chain_tx_status struct{ c *blockchain.Blockchain }

func (s chain_tx_status) ch() *blockchain.Blockchain {
	if s.c != nil {
		return s.c
	}
	return chain
}

func (s chain_tx_status) valid_block(h crypto.Hash) (crypto.Hash, bool) {
	if e, ok := final_txs.lookup(h, s.topo_blid); ok { // r23b: settled answer, re-checked against the topo index
		return e.blid, true
	}
	blid, _, ok := s.ch().IS_TX_Valid(h)
	return blid, ok
}
func (s chain_tx_status) topo_of(blid crypto.Hash) int64 {
	if e, ok := final_txs.block(blid); ok {
		return e.topo
	}
	return s.ch().Load_Block_Topological_order(blid)
}
func (s chain_tx_status) stored(h crypto.Hash) bool {
	_, err := s.ch().Store.Block_tx_store.ReadTX(h)
	return err == nil
}
func (s chain_tx_status) in_mempool(h crypto.Hash) bool {
	return s.ch().Mempool.Mempool_Get_TX(h) != nil
}
func (s chain_tx_status) in_regpool(h crypto.Hash) bool {
	return s.ch().Regpool.Regpool_Get_TX(h) != nil
}
func (s chain_tx_status) height_of(blid crypto.Hash) int64 {
	if e, ok := final_txs.block(blid); ok {
		return e.height
	}
	return s.ch().Load_Height_for_BL_ID(blid)
}
func (s chain_tx_status) chain_height() int64 { return s.ch().Get_Height() }
func (s chain_tx_status) final_height() (int64, int64) {
	c := s.ch()
	h := c.Get_Height()
	return final_height_scan(h, config.STABLE_LIMIT, func(x int64) int { return len(c.Get_Blocks_At_Height(x)) }), c.Get_Stable_Height()
}

func GetTxStatus(ctx context.Context, p GetTxStatus_Params) (result GetTxStatus_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	if len(p.TxIDs) == 0 || len(p.TxIDs) > MAX_TX_STATUS {
		return result, fmt.Errorf("txids must hold 1..%d transaction ids, got %d", MAX_TX_STATUS, len(p.TxIDs))
	}
	if len(p.TxIDs) > TX_STATUS_FREE {
		release, err := acquire_range_slot(ctx)
		if err != nil {
			return result, err
		}
		defer release()
	}
	src := chain_tx_status{}
	chain_height := src.chain_height() // read before the statuses: blocks_to_final never undercounts
	result.TopoHeight = chain.Load_TOPO_HEIGHT()
	if result.Txs, err = tx_statuses(ctx, p.TxIDs, result.TopoHeight, src); err != nil {
		return result, err
	}
	apply, final, stable, _ := finality(src, chain_height)
	for i := range result.Txs {
		apply(&result.Txs[i])
	}
	apply_pool_status(result.Txs, chain.Mempool, chain_height, RecentlyMined) // r24
	result.FinalHeight, result.StableHeight = final, stable
	result.Status = "OK"
	return result, nil
}

// tx_statuses classifies every id in order, looking each distinct id up once (r21, security): a stored txid costs
// IS_TX_Valid = one tx read and decode plus the blocks of 2*TX_VALIDITY_HEIGHT heights. Repeats of one id in a call
// (also with other blanks or hex case, which tx_status parses to the same hash) reuse the first answer. This is a
// convenience for clients, NOT a cost bound: 64 DISTINCT mined txids still cost 64 scans; the bound on a call is
// MAX_TX_STATUS plus the range slot it needs (r21 merge: SEC21-08 verifier).
func tx_statuses(ctx context.Context, ids []string, top int64, src tx_status_source) (out []TxStatus, err error) {
	seen := make(map[string]int, len(ids)) // trimmed, lower-cased id -> index of its first answer in out
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		key := strings.ToLower(strings.TrimSpace(id))
		if i, ok := seen[key]; ok {
			s := out[i]
			s.TxID = strings.TrimSpace(id) // answer in the caller's own spelling, like tx_status does
			out = append(out, s)
			continue
		}
		seen[key] = len(out)
		out = append(out, tx_status(id, top, src))
	}
	return out, nil
}
