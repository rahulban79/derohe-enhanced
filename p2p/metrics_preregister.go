// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Counters that exist only after their first event (Round 21 self-detect). metrics.Set.GetOrCreateCounter creates a
// series on first use, so live r20 (/metrics 2026-10-28 13:21) had no p2p_compact_block_*, p2p_tx_ask_repeats_skipped
// or p2p_outbound_netgroup_refused series at all: "never happened" and "not wired / not running this build" looked
// the same. Registering them at start makes a zero visible (r21 merge: the unlabelled p2p_* names live in
// counter_registry.go; this file keeps the fixed-label and non-p2p_ series and the lagging-peer gauge).

import "github.com/deroproject/derohe/metrics"

var preregistered_p2p_counters = []string{ // the unlabelled p2p_* counters are in counter_registry.go (p2p_counters)
	"miniblock_ours_broadcast_failed_total",
	`p2p_handshake_failures_by_kind_total{kind="grey"}`,
	`p2p_handshake_failures_by_kind_total{kind="white"}`,
	`p2p_handshake_failures_by_kind_total{kind="unlisted"}`,
}

func init() {
	for _, name := range preregistered_p2p_counters {
		metrics.Set.GetOrCreateCounter(name)
	}
}

// LAGGING_PEER_BLOCKS is the relay window of Broadcast_Block / broadcast_MiniBlock / broadcast_Tx: a peer more than
// this many blocks behind us receives none of them.
const LAGGING_PEER_BLOCKS = 25

// lagging_peer_count counts handshaken connections outside the relay window. Live r20 (GetPeerInfo 13:23): 2 of the 14
// [r25 B70: RFC 5737 stand-ins for the observed addresses]
// outgoing peers (203.0.113.166 at 7,472,150 on top_version 2, 203.0.113.167 at 7,537,830) were ~286k-351k blocks
// behind, so p2p_peer_count 14 overstated the useful relay fan-out (12; miniblock_ours_broadcast_peers 36 for 3 shares).
func lagging_peer_count(conns []*Connection, our_height int64) (n int) {
	for _, c := range conns {
		if c.State.Load() == HANDSHAKE_PENDING {
			continue
		}
		if our_height-c.Height.Load() > LAGGING_PEER_BLOCKS {
			n++
		}
	}
	return
}

var _ = metrics.Set.GetOrCreateGauge("p2p_peer_lagging_count", func() float64 {
	if chain == nil {
		return 0
	}
	var conns []*Connection
	for _, c := range UniqueConnections() {
		conns = append(conns, c)
	}
	return float64(lagging_peer_count(conns, chain.Get_Height()))
})
