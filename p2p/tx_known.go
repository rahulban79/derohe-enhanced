// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Per-connection known-transaction inventory (Round 21, local relay policy only; what is valid is unchanged).
//
// broadcast_Tx announced every newly admitted tx to every eligible peer, including the peer that served it to us
// (chain_sync.go relays with PeerID 0) and every peer that had already announced the same txid to us. Those peers
// hold the tx; each such NotifyINV is a wasted round trip on their side and ours, and the work grows with
// peers x txs, i.e. exactly with TPS. Bitcoin keeps the same per-peer "inventory known" filter.
//
// A connection now remembers the txids its peer announced to us (NotifyINV -> txs_to_fetch) for TX_KNOWN_TTL, and
// broadcast_Tx skips that peer for those txids. Only announcements FROM the peer are recorded, never our sends to
// it, so the r19 rebroadcast still reaches a peer that never announced the tx. The set is bounded (TX_KNOWN_MAX);
// when it is full of live entries a new txid is not recorded (fail open: the peer is announced to as before).

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

// TX_KNOWN_TTL: an announcing peer had the tx in its pool; mempool keeps an unmined tx for ~8 blocks (~2.5 min).
const TX_KNOWN_TTL = 10 * time.Minute

// TX_KNOWN_MAX bounds the record per connection (~40 bytes per entry).
const TX_KNOWN_MAX = 2048

var _ = metrics.Set.GetOrCreateCounter("p2p_tx_inv_known_skipped_total")

type tx_known_set struct {
	sync.Mutex
	seen       map[crypto.Hash]time.Time // txid -> when the peer last announced it to us
	next_sweep time.Time                 // r22: a full set holds no expired entry before this (see note)
	sweeps     int                       // full-set sweeps run (tests)
}

// note records that the peer announced txid at now.
func (s *tx_known_set) note(txid crypto.Hash, now time.Time) {
	s.Lock()
	defer s.Unlock()
	if s.seen == nil {
		s.seen = map[crypto.Hash]time.Time{}
	}
	if _, ok := s.seen[txid]; !ok && len(s.seen) >= TX_KNOWN_MAX {
		// r22 (security): one INV may carry MAX_INV_TXS (4096) txids, twice TX_KNOWN_MAX. Once the set was full of
		// live entries every further new txid swept all 2048 of them and found nothing to drop, so one INV cost
		// ~2048 x 2048 map iterations under the lock. A sweep that frees nothing now records when its oldest entry
		// expires; no entry can expire earlier (an entry's time only moves forward), so notes until then return at once.
		if now.Before(s.next_sweep) {
			return // fail open
		}
		s.sweeps++
		oldest := now
		for k, at := range s.seen {
			if now.Sub(at) >= TX_KNOWN_TTL {
				delete(s.seen, k)
			} else if at.Before(oldest) {
				oldest = at
			}
		}
		if len(s.seen) >= TX_KNOWN_MAX {
			s.next_sweep = oldest.Add(TX_KNOWN_TTL)
			return // fail open
		}
	}
	s.seen[txid] = now
}

// has reports whether the peer announced txid within TX_KNOWN_TTL before now.
func (s *tx_known_set) has(txid crypto.Hash, now time.Time) bool {
	s.Lock()
	defer s.Unlock()
	at, ok := s.seen[txid]
	return ok && now.Sub(at) < TX_KNOWN_TTL
}

func (s *tx_known_set) size() int {
	s.Lock()
	defer s.Unlock()
	return len(s.seen)
}

// tx_announce_targets is broadcast_Tx's peer filter: handshaken, not the excluded/own id, within the height window,
// and not a peer that announced txid to us (it already holds the tx).
func tx_announce_targets(conns []*Connection, txid crypto.Hash, exclude_id uint64, our_height int64, now time.Time) (targets []*Connection, known_skipped int) {
	for _, v := range conns {
		if v.State.Load() == HANDSHAKE_PENDING || exclude_id == v.Peer_ID || v.Peer_ID == GetPeerID() {
			continue
		}
		peer_height := v.Height.Load()
		if (our_height-peer_height) > 25 || (our_height+5) < peer_height {
			continue
		}
		if v.tx_known.has(txid, now) {
			known_skipped++
			continue
		}
		targets = append(targets, v)
	}
	if known_skipped > 0 {
		metrics.Set.GetOrCreateCounter("p2p_tx_inv_known_skipped_total").Add(known_skipped)
	}
	return
}
