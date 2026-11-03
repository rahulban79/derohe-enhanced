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

// Wallet-side history-sync caches (non-consensus; the daemon is untouched).
//
// A history sync (SyncHistory) binary-searches the wallet's encrypted balance
// over topoheights and then processes every block where it changed. Before
// this file the same (scid, topo) encrypted balance was fetched from the
// daemon up to 3 times (as a search midpoint, as block "topo" and as block
// "topo+1"'s previous balance), leaf blocks were processed twice, every
// fetched balance was brute-force decoded from scratch (hint 0) and the whole
// wallet was re-encrypted and rewritten to disk after every block that
// produced an entry (O(entries^2) for a miner's wallet).
//
// syncRun lives only for one SyncHistory call (which is serialised by
// sync_multilock). decodeCache is per wallet: the decoded value is a pure
// function of (ciphertext, wallet secret key), so caching it cannot change
// any result.

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// ConstructElGamal deep-copies both points
func cloneElGamal(e *crypto.ElGamal) *crypto.ElGamal {
	return crypto.ConstructElGamal(e.Left, e.Right)
}

type syncKey struct {
	scid crypto.Hash
	topo int64
}

type syncBalance struct {
	bits     int
	lastused uint64
	blid     crypto.Hash
	e        *crypto.ElGamal // private copy; callers always get a fresh clone
}

type syncRun struct {
	balances map[syncKey]syncBalance
	done     map[syncKey]bool // blocks already processed in this run
	dirty    bool             // entries changed, wallet must be saved
	saved    time.Time        // last intermediate save during this run
	gen      uint64           // run generation; late prefetch answers of an older run are dropped
	pf       *syncPrefetch    // r20: parallel block prefetch of this run (sync_prefetch.go), or nil
}

// how often a long history sync persists its progress (crash safety)
const syncRunSaveEvery = 30 * time.Second

// bound for the per-wallet decode cache (entries are ~80 bytes)
const decodeCacheMax = 1 << 14

type walletSyncState struct {
	mu     sync.Mutex
	run    *syncRun
	gen    uint64
	decode map[string]uint64
}

func (s *walletSyncState) begin() {
	s.mu.Lock()
	s.gen++
	s.run = &syncRun{balances: map[syncKey]syncBalance{}, done: map[syncKey]bool{}, saved: time.Now(), gen: s.gen}
	s.mu.Unlock()
}

// generation returns the generation of the active run (0 when none is active)
func (s *walletSyncState) generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil {
		return 0
	}
	return s.run.gen
}

// setPrefetch attaches p to the active run; false when no run is active
func (s *walletSyncState) setPrefetch(p *syncPrefetch) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil {
		return false
	}
	s.run.pf = p
	return true
}

// prefetch returns the active run's prefetcher for scid, or nil
func (s *walletSyncState) prefetch(scid crypto.Hash) *syncPrefetch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil || s.run.pf == nil || s.run.pf.scid != scid {
		return nil
	}
	return s.run.pf
}

// end finishes the run and reports whether entries changed during it
func (s *walletSyncState) end() (dirty bool) {
	s.mu.Lock()
	if s.run != nil {
		dirty = s.run.dirty
	}
	s.run = nil
	s.mu.Unlock()
	return
}

func (s *walletSyncState) getBalance(k syncKey) (b syncBalance, e *crypto.ElGamal, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil {
		return
	}
	if b, ok = s.run.balances[k]; !ok {
		return
	}
	return b, cloneElGamal(b.e), true
}

func (s *walletSyncState) putBalance(k syncKey, bits int, lastused uint64, blid crypto.Hash, e *crypto.ElGamal) {
	s.putBalanceGen(0, k, bits, lastused, blid, e)
}

// putBalanceGen stores only into run generation gen (0 = whichever run is active): a prefetch answer that arrives
// after its run ended must not seed the next run's cache.
func (s *walletSyncState) putBalanceGen(gen uint64, k syncKey, bits int, lastused uint64, blid crypto.Hash, e *crypto.ElGamal) {
	if e == nil || e.Left == nil || e.Right == nil {
		return
	}
	c := cloneElGamal(e)
	s.mu.Lock()
	if s.run != nil && (gen == 0 || s.run.gen == gen) {
		s.run.balances[k] = syncBalance{bits: bits, lastused: lastused, blid: blid, e: c}
	}
	s.mu.Unlock()
}

// isDone reports whether block k was already processed in the active run
func (s *walletSyncState) isDone(k syncKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.run != nil && s.run.done[k]
}

// markDone records a processed block; changed=true marks the run dirty. It
// returns active=false when no run is active (caller must save itself) and
// saveNow=true when a long run should persist intermediate progress.
func (s *walletSyncState) markDone(k syncKey, changed bool) (active, saveNow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run == nil {
		return false, false
	}
	s.run.done[k] = true
	if changed {
		s.run.dirty = true
	}
	if s.run.dirty && time.Since(s.run.saved) >= syncRunSaveEvery {
		s.run.saved = time.Now()
		s.run.dirty = false
		return true, true
	}
	return true, false
}

func (s *walletSyncState) getDecoded(key string) (v uint64, ok bool) {
	s.mu.Lock()
	v, ok = s.decode[key]
	s.mu.Unlock()
	return
}

func (s *walletSyncState) putDecoded(key string, v uint64) {
	s.mu.Lock()
	if s.decode == nil || len(s.decode) >= decodeCacheMax {
		s.decode = map[string]uint64{}
	}
	s.decode[key] = v
	s.mu.Unlock()
}
