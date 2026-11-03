// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Per-connection memory of transaction requests (Round 20, local relay policy only; what is valid is unchanged).
//
// Live r19 evidence (derod.log from 2026-10-27 05:48 to 2026-10-28 08:33): all 23 p2p_tx_fetch_failures_total came
// from one peer, which announced txs it could no longer serve ("open /root/daemon2/.../bltx_store/...tx: no such
// file"). They covered only 10 distinct txids: the peer re-announced the same txid up to 6 times within 100 ms
// (03:15:49.655 to 03:15:49.750), and NotifyINV sent one Peer.GetObject per announcement. Every repeat failed again
// and was counted against MAX_TX_FETCH_FAILURES, so one lost mempool entry used up 6 of the 8 failures and the
// connection was dropped twice (p2p_tx_fetch_budget_drops_total 2, three closed-pipe errors at 03:18:06.409).
//
// A connection now asks a peer for a given txid at most once per TX_ASK_HOLD. A repeat announcement while the first
// request is in flight, or after it failed, is skipped; the same tx can still be fetched at once from any other peer
// (the record is per connection), and from this peer again after the hold. The set is bounded (TX_ASK_MAX); when it
// is full of live entries, a new txid is requested as before and not recorded (fail open: never lose a tx).

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
)

// TX_ASK_HOLD is below REBROADCAST_AFTER (36 s), so a peer's honest re-announcement of a still-unmined tx is
// fetched again if the first request failed.
const TX_ASK_HOLD = 30 * time.Second

// TX_ASK_MAX bounds the per-connection record: 512 entries x ~40 bytes; an honest peer announces a few txs per block.
const TX_ASK_MAX = 512

type tx_ask_set struct {
	sync.Mutex
	asked map[crypto.Hash]time.Time // txid -> when this connection last asked the peer for it
}

// claim reports whether txid may be requested from this peer now, and records the request when it may.
func (s *tx_ask_set) claim(txid crypto.Hash, now time.Time) bool {
	s.Lock()
	defer s.Unlock()
	if s.asked == nil {
		s.asked = map[crypto.Hash]time.Time{}
	}
	if at, ok := s.asked[txid]; ok && now.Sub(at) < TX_ASK_HOLD {
		metrics.Set.GetOrCreateCounter("p2p_tx_ask_repeats_skipped_total").Inc()
		return false
	}
	if len(s.asked) >= TX_ASK_MAX {
		for k, at := range s.asked {
			if now.Sub(at) >= TX_ASK_HOLD {
				delete(s.asked, k)
			}
		}
		if len(s.asked) >= TX_ASK_MAX {
			return true // full of live entries: request as before, without a record
		}
	}
	s.asked[txid] = now
	return true
}

func (s *tx_ask_set) size() int {
	s.Lock()
	defer s.Unlock()
	return len(s.asked)
}
