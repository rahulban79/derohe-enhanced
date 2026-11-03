// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Transaction flow (Round 19, local relay policy only: which transactions are valid, and how they are verified, is
// unchanged; Add_TX_To_Pool is still called, unmodified, for every transaction the node accepts).
//
//  1. In-flight collapse. NotifyINV checks Mempool_TX_Exist, fetches, then verifies (~40 ms CPU at ring 2, ~80 ms
//     at ring 16, ~1 s at ring 128). Until the first verification finishes the tx is not in the mempool, so every
//     peer that relays it inside that window makes us fetch and fully verify it again: measured 6 concurrent copies
//     of one tx = 6.2x the CPU of one (cmd/simulator/txflow_load_test.go, dup_concurrent). Concurrent admissions of
//     byte-identical transactions now share one Add_TX_To_Pool call. The key is Keccak256 of the exact bytes
//     received, NOT the txid: the txid does not cover the proofs (blockchain caches HF3+ verdicts by the same
//     Keccak256 for that reason), so a forged copy with a valid txid and a broken proof never shares a verdict with
//     the honest copy. An INV for a txid that is being admitted waits (bounded) for that admission and skips the
//     fetch if the tx landed in the pool; otherwise it fetches as before. One NotifyINV call waits at most
//     TX_INFLIGHT_WAIT in total, however many txids it lists (r19 merge, verifier TXF-02).
//  2. Rebroadcast. Upstream relays a tx submitted over RPC exactly once (Broadcast_Tx) and never again; the mempool
//     has no relay loop (its Exit_Mutex "stop relaying" channel has no reader). A tx submitted while the node has no
//     handshaken peers, or whose INVs all failed, sat in our mempool until purged while the wallet reported success.
//     Privacy (r19 merge, verifier TXF-03): re-announcing only our own txs would mark this node as their origin to
//     any peer that sees the repeats. So every tx this node announced - submitted here (Broadcast_Tx) or relayed
//     after our own successful admission (admit_relayed_tx) - is tracked the same way and re-announced while it
//     stays unmined in our mempool, after REBROADCAST_AFTER plus a random delay of up to REBROADCAST_AFTER, at most
//     REBROADCAST_MAX times. An interval in which no handshaken peer was eligible does not use up an attempt. Peers
//     that already have the tx answer the INV from their mempool index (no fetch), so the cost is one ~100-byte INV
//     per peer per interval. Limit: a tx relayed to us and mined at once is re-announced by nobody, as before; the
//     repeats of an unmined tx come from every node that relayed it, not only its origin.

import (
	"errors"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/txcanon"
	"github.com/deroproject/derohe/glue/txprecheck"
	"github.com/deroproject/derohe/transaction"
)

// TX_INFLIGHT_WAIT bounds how long an INV handler waits for another connection's admission of the same txid.
// It is below the 10 s Peer.NotifyINV call timeout (call.go) so the announcing peer never times out on us.
const TX_INFLIGHT_WAIT = 3 * time.Second

var errTxFlightAborted = errors.New("tx admission aborted")

type tx_flight struct {
	done chan struct{}
	err  error
}

type tx_inflight_set struct {
	sync.Mutex
	bykey  map[crypto.Hash]*tx_flight // Keccak256(raw bytes) -> flight
	bytxid map[crypto.Hash]*tx_flight // txid -> latest flight for that txid
}

func new_tx_inflight_set() *tx_inflight_set {
	return &tx_inflight_set{bykey: map[crypto.Hash]*tx_flight{}, bytxid: map[crypto.Hash]*tx_flight{}}
}

var tx_inflight = new_tx_inflight_set()

// do runs admit once for all concurrent callers presenting the same key. shared is true for callers that received
// another caller's result. A panicking admit is reported to waiters as errTxFlightAborted, never as success.
func (s *tx_inflight_set) do(key, txid crypto.Hash, admit func() error) (err error, shared bool) {
	s.Lock()
	if f, ok := s.bykey[key]; ok {
		s.Unlock()
		<-f.done
		return f.err, true
	}
	f := &tx_flight{done: make(chan struct{}), err: errTxFlightAborted}
	s.bykey[key] = f
	s.bytxid[txid] = f
	s.Unlock()

	defer func() {
		s.Lock()
		delete(s.bykey, key)
		if s.bytxid[txid] == f {
			delete(s.bytxid, txid)
		}
		s.Unlock()
		close(f.done)
	}()
	err = admit()
	f.err = err
	return err, false
}

// settled waits up to timeout for an admission of txid in progress on another connection and reports whether the
// tx is now present according to have. With no admission in progress it returns false at once (fetch as before).
func (s *tx_inflight_set) settled(txid crypto.Hash, timeout time.Duration, have func(crypto.Hash) bool) bool {
	s.Lock()
	f := s.bytxid[txid]
	s.Unlock()
	if f == nil {
		return false
	}
	if timeout <= 0 { // the caller's wait budget is spent: only an admission that already finished counts
		select {
		case <-f.done:
			return have(txid)
		default:
			return false
		}
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-f.done:
	case <-t.C:
		return false
	}
	return have(txid)
}

// relay_admit is the mempool admission used for a transaction relayed to us as raw (Round 22): the round-trip relay
// policy of glue/txcanon first, then add. A tx whose re-serialization no node can decode never reaches the mempool,
// so it is never relayed by us or put into a block template we mine. Not scored against the peer (a stock node
// never sends such bytes; the refusal costs one Serialize, ~22 us at ring 2).
// r23: glue/txprecheck runs first: a transfer whose structure consensus refuses (duplicate ring member, ring of one,
// no DERO payload, mixed roothash, zero burn) is refused before Add_TX_To_Pool reads any state for it.
func relay_admit(raw []byte, add func(*transaction.Transaction) error) func(*transaction.Transaction) error {
	return func(tx *transaction.Transaction) error {
		return txprecheck.Admit(tx, func(tx *transaction.Transaction) error { return txcanon.Admit(raw, tx, add) })
	}
}

// relay_tip returns our chain's height (tests replace it); the one read upstream's too-old check already made.
var relay_tip = func() int64 { return chain.Get_Height() }

// relay_window is the r23b admission window of a relayed transaction against our tip (glue/txprecheck/window.go):
// too old or too new for any block extending our tip, or a grandfathered HF3 TXID. Never applied to block txs.
func relay_window(tx *transaction.Transaction, txid crypto.Hash) error {
	if err := txprecheck.Window(tx.Height, relay_tip()); err != nil {
		return err
	}
	return txprecheck.HF3(txid)
}

// admit_relayed_tx admits one relayed transaction through the in-flight set. It returns Add_TX_To_Pool's verdict
// and whether THIS caller should relay the tx onward: only the caller whose own admission succeeded relays, so a
// collapsed duplicate neither re-verifies nor re-broadcasts.
func admit_relayed_tx(raw []byte, tx *transaction.Transaction, add func(*transaction.Transaction) error) (err error, relay bool) {
	err, shared := tx_inflight.do(crypto.Keccak256(raw), tx.GetHash(), func() error { return add(tx) })
	relay = err == nil && !shared
	if relay {
		track_announced_tx(tx, globals.Time()) // re-announced exactly like a tx submitted here (privacy, TXF-03)
	}
	return err, relay
}

const REBROADCAST_AFTER = 36 * time.Second // two block times; a relayed tx is normally mined in one or two
const REBROADCAST_MAX = 4                  // mempool purges an unmined tx after ~8 blocks (stable height)
const REBROADCAST_TRACK_MAX = 1024

// rebroadcast_jitter is the random extra delay of each re-announcement, uniform in [0, REBROADCAST_AFTER) (tests
// replace it).
var rebroadcast_jitter = func() time.Duration { return time.Duration(mrand.Int63n(int64(REBROADCAST_AFTER))) }

type announced_tx struct {
	tx    *transaction.Transaction
	next  time.Time
	count int
}

var announced_txs = struct {
	sync.Mutex
	m map[crypto.Hash]*announced_tx
}{m: map[crypto.Hash]*announced_tx{}}

// track_announced_tx records a tx this node announced, whether it was submitted here or relayed: both are handled
// identically from here on.
func track_announced_tx(tx *transaction.Transaction, now time.Time) {
	announced_txs.Lock()
	defer announced_txs.Unlock()
	if len(announced_txs.m) >= REBROADCAST_TRACK_MAX {
		return
	}
	h := tx.GetHash()
	if _, ok := announced_txs.m[h]; ok {
		return
	}
	announced_txs.m[h] = &announced_tx{tx: tx, next: now.Add(REBROADCAST_AFTER + rebroadcast_jitter())}
}

// due_announced_txs returns the tracked txs to re-announce now and forgets those that left the pool (mined, purged,
// evicted) or used up their rebroadcasts. With no eligible peer (peers == 0) nothing is due and no attempt is used.
func due_announced_txs(now time.Time, in_pool func(crypto.Hash) bool, peers int) (due []*transaction.Transaction) {
	announced_txs.Lock()
	defer announced_txs.Unlock()
	for h, e := range announced_txs.m {
		if !in_pool(h) || e.count >= REBROADCAST_MAX {
			delete(announced_txs.m, h)
		}
	}
	if peers == 0 {
		return nil
	}
	for _, e := range announced_txs.m {
		if !now.Before(e.next) {
			e.next = now.Add(REBROADCAST_AFTER + rebroadcast_jitter())
			e.count++
			due = append(due, e.tx)
		}
	}
	return
}

// eligible_tx_peers counts the connections broadcast_Tx would announce to (handshaken, not ourselves, within its
// height window).
func eligible_tx_peers() (n int) {
	our_height := chain.Get_Height()
	for _, v := range UniqueConnections() {
		if v.State.Load() == HANDSHAKE_PENDING || v.Peer_ID == GetPeerID() {
			continue
		}
		if ph := v.Height.Load(); (our_height-ph) > 25 || (our_height+5) < ph {
			continue
		}
		n++
	}
	return
}

func rebroadcast_announced_txs() {
	defer globals.Recover(3)
	if chain == nil {
		return
	}
	now := globals.Time()
	for _, tx := range due_announced_txs(now, chain.Mempool.Mempool_TX_Exist, eligible_tx_peers()) {
		broadcast_Tx(tx, 0, now.UTC().UnixMicro())
	}
}

func have_pool_tx(txid crypto.Hash) bool {
	return chain.Mempool.Mempool_TX_Exist(txid) || chain.Regpool.Regpool_TX_Exist(txid)
}
