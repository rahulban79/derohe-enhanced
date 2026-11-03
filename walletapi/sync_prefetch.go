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

package walletapi

// Parallel history-sync discovery and block prefetch (r20, GP-07; non-consensus, the daemon is untouched).
//
// SyncHistory binary-searches the wallet's encrypted balance over topoheights and then processes every block where
// it changed (synchistory_internal_binary_search / synchistory_block). Every daemon call on that path was strictly
// serial: one GetEncryptedBalance per bisection step, then per changed block two more balances, one GetBlock and one
// GetTransaction PER TRANSACTION. Against a remote daemon each call costs a full round trip, so a miner's wallet
// (one changed block per mined block) paid ~2 RTT per block even after the r19 caches.
//
// This file runs the SAME bisection ahead of the serial pass with up to sync_parallel calls in flight. It only
// fetches: balances go into the per-run balance cache (sync_cache.go) and are decoded into the per-wallet decode
// memo, and the blocks the serial pass will process are fetched (GetBlock plus ONE batched GetTransaction per block,
// at most SYNC_TX_BATCH hashes per call) up to SYNC_PREFETCH_AHEAD blocks ahead of it. The serial pass is unchanged
// and still decides everything: it consumes prefetched answers where present and calls the daemon itself otherwise,
// so a failed, missing or extra prefetch can only cost time, never change entries or their order.
//
// Bounds: at most sync_parallel daemon calls in flight; at most SYNC_DISCOVER_GOROUTINES extra goroutines during
// discovery (beyond that a branch is walked inline); at most SYNC_PREFETCH_AHEAD prefetched blocks held at once.
// DERO_WALLET_SYNC_PARALLEL=1 restores the strictly serial behaviour.

import (
	"bytes"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// SYNC_PARALLEL is the default number of daemon calls a history sync keeps in flight.
const SYNC_PARALLEL = 6

// SYNC_DISCOVER_GOROUTINES bounds the goroutines the parallel bisection may run at once.
const SYNC_DISCOVER_GOROUTINES = 32

// SYNC_PREFETCH_AHEAD is how many changed blocks are fetched ahead of the serial pass.
const SYNC_PREFETCH_AHEAD = 32

// SYNC_TX_BATCH is the most transaction hashes asked for in one DERO.GetTransaction call.
const SYNC_TX_BATCH = 32

var sync_parallel = sync_parallel_from_env(os.Getenv("DERO_WALLET_SYNC_PARALLEL"))

func sync_parallel_from_env(v string) int {
	if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 64 {
		return n
	}
	return SYNC_PARALLEL
}

// discover_leaves walks the bisection of synchistory_internal_binary_search without processing any block and returns,
// sorted and de-duplicated, every topo the serial walk passes to synchistory_block when fetch returns the same
// balances. fetch must be safe for concurrent use; a failed fetch (ok=false) prunes that branch (the serial pass will
// meet the same error itself). At most par fetches run at once and at most SYNC_DISCOVER_GOROUTINES extra goroutines.
func discover_leaves(start int64, start_e []byte, end int64, end_e []byte, registration int64, par int, fetch func(topo int64) ([]byte, bool)) []int64 {
	if par < 1 {
		par = 1
	}
	sem := make(chan struct{}, par)
	spawn := make(chan struct{}, SYNC_DISCOVER_GOROUTINES)
	var mu sync.Mutex
	set := map[int64]struct{}{}
	leaf := func(t int64) {
		mu.Lock()
		set[t] = struct{}{}
		mu.Unlock()
	}
	var wg sync.WaitGroup
	var walk func(s int64, se []byte, e int64, ee []byte)
	walk = func(s int64, se []byte, e int64, ee []byte) {
		if e < 0 {
			return
		}
		median := (s + e) / 2
		if s == median {
			leaf(s)
		}
		if e-s <= 1 {
			leaf(e)
			return
		}
		sem <- struct{}{}
		me, ok := fetch(median)
		<-sem
		if !ok {
			return
		}
		lower := s == registration || !bytes.Equal(se, me)
		upper := !bytes.Equal(me, ee)
		if lower && upper {
			select {
			case spawn <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-spawn }()
					walk(s, se, median, me)
				}()
			default:
				walk(s, se, median, me)
			}
			walk(median, me, e, ee)
			return
		}
		if lower {
			walk(s, se, median, me)
		}
		if upper {
			walk(median, me, e, ee)
		}
	}
	walk(start, start_e, end, end_e)
	wg.Wait()
	out := make([]int64, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// blockSlot is one prefetched block: closed done means bres/txs are final.
type blockSlot struct {
	done chan struct{}
	ok   bool // bres is a successful GetBlock answer
	bres rpc.GetBlock_Result
	txs  map[string]rpc.GetTransaction_Result // per tx hash, shaped like a single-hash GetTransaction answer
}

// syncPrefetch fetches the blocks of leaves (ascending) at most ahead blocks in front of the serial consumer.
type syncPrefetch struct {
	mu     sync.Mutex
	scid   crypto.Hash
	leaves []int64
	index  map[int64]int
	next   int // next leaf index to start
	taken  int // leaves before this index were consumed or passed by the consumer
	ahead  int
	slots  map[int64]*blockSlot
	sem    chan struct{}
	fill   func(topo int64, s *blockSlot)
}

func newSyncPrefetch(scid crypto.Hash, leaves []int64, ahead, par int, fill func(topo int64, s *blockSlot)) *syncPrefetch {
	if par < 1 {
		par = 1
	}
	p := &syncPrefetch{scid: scid, leaves: leaves, index: make(map[int64]int, len(leaves)), ahead: ahead,
		slots: map[int64]*blockSlot{}, sem: make(chan struct{}, par), fill: fill}
	for i, t := range leaves {
		p.index[t] = i
	}
	return p
}

// ensure starts the fetches of leaves[from : from+ahead] that were not started yet.
func (p *syncPrefetch) ensure(from int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next < from {
		p.next = from // leaves the consumer already passed are never fetched
	}
	for ; p.next < len(p.leaves) && p.next < from+p.ahead; p.next++ {
		t := p.leaves[p.next]
		s := &blockSlot{done: make(chan struct{})}
		p.slots[t] = s
		go func() {
			p.sem <- struct{}{}
			defer func() { <-p.sem }()
			defer close(s.done)
			p.fill(t, s)
		}()
	}
}

// take hands the consumer the prefetched block for topo (waiting for it if it is in flight) and keeps the window
// full. It returns nil when topo was not prefetched; the caller then asks the daemon itself.
func (p *syncPrefetch) take(topo int64) *blockSlot {
	if p == nil {
		return nil
	}
	i, known := p.index[topo]
	if !known {
		return nil
	}
	p.ensure(i + 1)
	p.mu.Lock()
	for ; p.taken < i; p.taken++ { // leaves the consumer passed without taking are dropped, not held
		delete(p.slots, p.leaves[p.taken])
	}
	if p.taken == i {
		p.taken++
	}
	s := p.slots[topo]
	delete(p.slots, topo)
	p.mu.Unlock()
	if s == nil {
		return nil
	}
	<-s.done
	if !s.ok {
		return nil
	}
	return s
}

// held reports how many prefetched blocks are held (tests).
func (p *syncPrefetch) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.slots)
}

// fetch_own_balance is GetEncryptedBalanceAtTopoHeight(scid, topo, own address) for topo >= 0 without any of its
// side effects (w.Error, w.account.Registered); a successful answer is put in the per-run cache, where the serial
// pass finds it (and then applies the same side effects a fetch would). It returns the serialized ciphertext.
func (w *Wallet_Memory) fetch_own_balance(gen uint64, scid crypto.Hash, topo int64) ([]byte, bool) {
	if topo < 0 {
		return nil, false
	}
	if _, e, ok := w.syncstate.getBalance(syncKey{scid, topo}); ok {
		return e.Serialize(), true
	}
	var result rpc.GetEncryptedBalance_Result
	if err := rpc_client.Call("DERO.GetEncryptedBalance", rpc.GetEncryptedBalance_Params{SCID: scid, Address: w.GetAddress().String(), TopoHeight: topo}, &result); err != nil {
		return nil, false
	}
	if result.Status != "OK" {
		return nil, false // unregistered at that topo, or an SC answer the serial path handles itself
	}
	raw, err := hex.DecodeString(result.Data)
	if err != nil {
		return nil, false
	}
	var nb crypto.NonceBalance
	if err := safe_unmarshal_nonce_balance(&nb, raw); err != nil || nb.Balance == nil || nb.Balance.Left == nil || nb.Balance.Right == nil {
		return nil, false
	}
	w.syncstate.putBalanceGen(gen, syncKey{scid, topo}, result.Bits, nb.NonceHeight, result.BlockHash, nb.Balance)
	w.DecodeEncryptedBalance_Memory(nb.Balance, 0) // fills the decode memo on this worker
	return nb.Balance.Serialize(), true
}

func safe_unmarshal_nonce_balance(nb *crypto.NonceBalance, raw []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errBadNonceBalance
		}
	}()
	nb.Unmarshal(raw)
	return nil
}

type prefetchError string

func (e prefetchError) Error() string { return string(e) }

const errBadNonceBalance = prefetchError("undecodable balance from daemon")

// fill_block is the production prefetch of one changed block: its two balances, the block and its transactions.
func (w *Wallet_Memory) fill_block(gen uint64, scid crypto.Hash, registration int64) func(topo int64, s *blockSlot) {
	return func(topo int64, s *blockSlot) {
		if topo > 0 && topo != registration {
			w.fetch_own_balance(gen, scid, topo-1)
		}
		w.fetch_own_balance(gen, scid, topo)
		if err := rpc_client.Call("DERO.GetBlock", rpc.GetBlock_Params{Height: uint64(topo)}, &s.bres); err != nil {
			return
		}
		s.ok = true
		if s.bres.Block_Header.SideBlock {
			return
		}
		raw, err := hex.DecodeString(s.bres.Blob)
		if err != nil {
			return
		}
		var bl block.Block
		if bl.Deserialize(raw) != nil || len(bl.Tx_hashes) == 0 {
			return
		}
		s.txs = map[string]rpc.GetTransaction_Result{}
		for i := 0; i < len(bl.Tx_hashes); i += SYNC_TX_BATCH {
			j := i + SYNC_TX_BATCH
			if j > len(bl.Tx_hashes) {
				j = len(bl.Tx_hashes)
			}
			var p rpc.GetTransaction_Params
			for _, h := range bl.Tx_hashes[i:j] {
				p.Tx_Hashes = append(p.Tx_Hashes, h.String())
			}
			var r rpc.GetTransaction_Result
			if err := rpc_client.Call("DERO.GetTransaction", p, &r); err != nil {
				continue // the serial pass asks for these one by one and reports the error itself
			}
			split_tx_batch(p.Tx_Hashes, r, s.txs)
		}
	}
}

// split_tx_batch turns one batched GetTransaction answer into single-hash answers. A malformed answer (lengths that
// do not match the request) adds nothing, so the serial pass falls back to single calls.
// An entry with empty hex or In_pool is never served (r20 merge, RW-01 review): derod's GetTransaction adds "" for a
// hash it cannot find and a LATER found hash resets the error, so a batch can succeed where the single call fails;
// served, the empty entry failed to decode and the serial pass marked the block done, silently losing the entry.
// Left out, that hash goes through the single call, which keeps the serial pass's error-and-retry semantics.
func split_tx_batch(hashes []string, r rpc.GetTransaction_Result, out map[string]rpc.GetTransaction_Result) {
	if len(r.Txs_as_hex) != len(hashes) || len(r.Txs) != len(hashes) {
		return
	}
	for i, h := range hashes {
		if r.Txs_as_hex[i] == "" || r.Txs[i].In_pool {
			continue
		}
		out[h] = rpc.GetTransaction_Result{Txs_as_hex: []string{r.Txs_as_hex[i]}, Txs: []rpc.Tx_Related_Info{r.Txs[i]}, Status: r.Status}
	}
}

// start_sync_prefetch runs the parallel discovery for [start_topo, end_topo] and arms the block prefetcher of the
// active run. It is a no-op when sync_parallel is 1.
func (w *Wallet_Memory) start_sync_prefetch(scid crypto.Hash, start_topo int64, start_e *crypto.ElGamal, end_topo int64, end_e *crypto.ElGamal) {
	if sync_parallel <= 1 || end_topo < 0 || start_e == nil || end_e == nil {
		return
	}
	gen := w.syncstate.generation()
	if gen == 0 {
		return
	}
	registration := w.getEncryptedBalanceresult(scid).Registration
	leaves := discover_leaves(start_topo, start_e.Serialize(), end_topo, end_e.Serialize(), registration, sync_parallel, func(t int64) ([]byte, bool) {
		return w.fetch_own_balance(gen, scid, t)
	})
	p := newSyncPrefetch(scid, leaves, SYNC_PREFETCH_AHEAD, sync_parallel, w.fill_block(gen, scid, registration))
	if w.syncstate.setPrefetch(p) {
		p.ensure(0)
	}
}

// tx returns the prefetched single-hash GetTransaction answer for hash (nil-safe).
func (s *blockSlot) tx(hash string) (rpc.GetTransaction_Result, bool) {
	if s == nil || s.txs == nil {
		return rpc.GetTransaction_Result{}, false
	}
	r, ok := s.txs[hash]
	if ok && (len(r.Txs_as_hex) != 1 || len(r.Txs) != 1) {
		return rpc.GetTransaction_Result{}, false
	}
	return r, ok
}
