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

// r22 (rpcws): a verify-on-hit cache for DERO.GetTransaction's mined-tx answers.
//
// A loopback load profile (cmd/simulator rpcload_test.go, 32 HTTP clients, 8 hot RPCs) put GetTransaction at 27% of
// all CPU, nearly all of it in syscalls: chain.IS_TX_Valid loads every topo-ordered block in heights
// [tx.Height+1, tx.Height+1+2*TX_VALIDITY_HEIGHT] (each Load_BL_FROM_ID opens and lists a directory and reads a
// file), then Load_Block_Topological_order binary-searches the topo file again, and the ring is expanded from the
// balance tree. Wallet sync asks for every tx of its history this way, and explorers ask for the same txs again.
//
// The answer is a function of: the tx bytes (content-addressed by its hash), the SET of topo-ordered block ids that
// Find_Blocks_Height_Range returns for that height range (blocks are content-addressed by id), and the topo record
// (block id, state version, height) of the block the tx is valid in, whose state version selects the snapshot the
// ring and the SC fields come from. So an entry stores exactly those inputs, and a hit is used only after proving
// them again against the CURRENT chain: the tx is still in the block store, Find_Blocks_Height_Range returns the
// same set, and the topo record at the cached position is byte-identical. Anything else (a reorg, a rewind, a block
// joining the range near the tip) recomputes and replaces the entry. A stale entry costs the proof, never a wrong
// answer. Only valid, fully computed answers are cached; mempool and not-found answers never are. The cache only
// feeds an RPC reply; consensus never reads it.
//
// r22 merge: OFF by default (derod --rpc-tx-cache turns it on). A hit costs ~0.28 ms of CPU and a miss ~2 ms, so on a
// node whose RPC is reachable by others the reply time tells a prober whether someone fetched that tx since the entry
// was filled (a wallet syncing that block, an explorer): a cross-client timing oracle a privacy coin should not add by
// default. Measured gain is an upper bound at a 100% hit rate (x5.4-7.2 less CPU per call, loopback simulator); the
// live node served 0 GetTransaction calls, so its benefit there is nil. Enable it on a loopback-only or single-tenant
// RPC (an explorer backend, a wallet server) where the operator already sees every query.
//
// tx_validity mirrors IS_TX_Valid; note that on a Load_BL error it may return a non-zero valid_blid together with
// valid=false (IS_TX_Valid's own return in that case); callers only use valid_blid when valid is true.

import (
	"sync"
	"sync/atomic"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// bounds: entries and approximate bytes (tx hex + ring addresses + code). A ring-16 transfer is ~10-15 KB of hex,
// so the byte bound is the one that binds; either bound clears the cache wholesale (as registration_cache does).
const tx_result_cache_max = 1 << 14
const tx_result_cache_max_bytes = 32 << 20

type tx_result_entry struct {
	blids   []crypto.Hash         // Find_Blocks_Height_Range's set when computed (compared as a set)
	topo    int64                 // topo position of the valid block
	record  blockchain.TopoRecord // topo record at topo when computed
	hex     string                // Txs_as_hex element
	related rpc.Tx_Related_Info   // Txs element
}

// size is the entry's approximate heap footprint, for the byte bound.
func (e *tx_result_entry) size() int {
	n := 256 + 32*len(e.blids) + len(e.hex) + len(e.related.ValidBlock) + len(e.related.Signer) + len(e.related.Code)
	for _, ring := range e.related.Ring {
		for _, a := range ring {
			n += 16 + len(a)
		}
	}
	return n
}

type tx_result_cache struct {
	sync.Mutex
	m              map[crypto.Hash]*tx_result_entry
	bytes          int    // sum of size() of the entries in m (approximate)
	hits, verified uint64 // hits = proofs that passed; verified = proofs attempted
}

var tx_cache = tx_result_cache{m: map[crypto.Hash]*tx_result_entry{}}

// tx_cache_on gates the cache (r22 merge): 0 = off (the default: no timing oracle), 1 = on (derod --rpc-tx-cache).
var tx_cache_on atomic.Int32

// SetTxResultCache turns GetTransaction's result cache on or off (derod --rpc-tx-cache); off also empties it.
func SetTxResultCache(on bool) {
	if on {
		tx_cache_on.Store(1)
		return
	}
	tx_cache_on.Store(0)
	tx_cache.Lock()
	tx_cache.m = map[crypto.Hash]*tx_result_entry{}
	tx_cache.bytes = 0
	tx_cache.Unlock()
}

// TxResultCacheOn reports whether the cache is enabled.
func TxResultCacheOn() bool { return tx_cache_on.Load() == 1 }

func (c *tx_result_cache) get(h crypto.Hash) *tx_result_entry {
	c.Lock()
	defer c.Unlock()
	return c.m[h]
}

func (c *tx_result_cache) put(h crypto.Hash, e *tx_result_entry) {
	if !TxResultCacheOn() {
		return
	}
	c.Lock()
	defer c.Unlock()
	sz := e.size()
	if sz > tx_result_cache_max_bytes/64 { // one answer may not take more than 1/64 of the budget
		return
	}
	if old, ok := c.m[h]; ok {
		c.bytes -= old.size()
		delete(c.m, h)
	}
	if len(c.m) >= tx_result_cache_max || c.bytes+sz > tx_result_cache_max_bytes {
		c.m = map[crypto.Hash]*tx_result_entry{}
		c.bytes = 0
	}
	c.m[h] = e
	c.bytes += sz
}

func (c *tx_result_cache) drop(h crypto.Hash) {
	c.Lock()
	defer c.Unlock()
	if old, ok := c.m[h]; ok {
		c.bytes -= old.size()
		delete(c.m, h)
	}
}

func (c *tx_result_cache) count(hit bool) {
	c.Lock()
	defer c.Unlock()
	c.verified++
	if hit {
		c.hits++
	}
}

// tx_range_blocks is the height range IS_TX_Valid searches for tx, as Find_Blocks_Height_Range arguments.
func tx_range_blocks(tx *transaction.Transaction) (start, stop int64) {
	start = int64(tx.Height + 1)
	return start, start + 2*blockchain.TX_VALIDITY_HEIGHT
}

// tx_validity is chain.IS_TX_Valid with the block list it searched returned too (the cache's proof input).
// It must stay equal to IS_TX_Valid; TestR22TxResultCacheOnSimulatorChain checks that on a simulator chain.
func tx_validity(c *blockchain.Blockchain, hash crypto.Hash, tx *transaction.Transaction) (valid_blid crypto.Hash, invalid_blid []crypto.Hash, valid bool, blids []crypto.Hash, ok bool) {
	blids = c.Find_Blocks_Height_Range(tx_range_blocks(tx))
	for _, blid := range blids {
		bl, err := c.Load_BL_FROM_ID(blid)
		if err != nil {
			return valid_blid, invalid_blid, false, blids, false // IS_TX_Valid returns (zero, nil, false) here too
		}
		for _, bltxhash := range bl.Tx_hashes {
			if bltxhash == hash {
				valid_blid, valid = blid, true // last one found wins, as in IS_TX_Valid
			}
		}
	}
	return valid_blid, invalid_blid, valid, blids, true
}

func same_hash_set(a, b []crypto.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[crypto.Hash]int, len(a))
	for _, h := range a {
		set[h]++
	}
	for _, h := range b {
		if set[h] == 0 {
			return false
		}
		set[h]--
	}
	return true
}

// lookup returns the cached answer for a mined tx only after proving its inputs unchanged on the current chain.
// tx must be the tx deserialized from the block store for hash (the caller has just read it).
func (c *tx_result_cache) lookup(ch *blockchain.Blockchain, hash crypto.Hash, tx *transaction.Transaction) *tx_result_entry {
	if !TxResultCacheOn() {
		return nil
	}
	e := c.get(hash)
	if e == nil {
		return nil
	}
	ok := same_hash_set(ch.Find_Blocks_Height_Range(tx_range_blocks(tx)), e.blids)
	if ok {
		r, err := ch.Store.Topo_store.Read(e.topo)
		ok = err == nil && r == e.record
	}
	c.count(ok)
	if !ok {
		c.drop(hash)
		return nil
	}
	return e
}
