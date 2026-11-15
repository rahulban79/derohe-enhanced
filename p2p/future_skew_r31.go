// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// r31 (dero-rft §7 B269 (b); seed R31-1): per-peer attribution of blocks the chain refused because their timestamp is
// more than 50 ms ahead of this node's clock (blockchain/blockchain.go, the upstream rule, unchanged). On 2026-11-11
// three such refusals in the whole log chain came from ONE peer; our clock was fine (sntp +0.0017 s), so the skew is
// the sender's. Observability only: the verdict, the 50 ms limit and the peer's standing are untouched. No penalty
// is scored for a future block (one event is a clock, not an attack); a bound for repeated skew needs a measured
// distribution first, which is what this histogram collects.
//
//   p2p_future_blocks_total               refusals for a future timestamp (eager, 0 from start)
//   p2p_future_block_skew_seconds         block timestamp - our clock at the refusal (le-histogram, 0 from start)
//   PeerInfo future_blocks / future_skew_max_ms   per connection

import "github.com/deroproject/derohe/metrics"

// FUTURE_SKEW_BUCKETS (seconds): the rule's 50 ms limit up to five minutes ahead.
var FUTURE_SKEW_BUCKETS = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 300}

var future_blocks_total = metrics.Set.GetOrCreateCounter("p2p_future_blocks_total")
var future_skew_seconds = metrics.Set.GetOrCreatePrometheusHistogramExt("p2p_future_block_skew_seconds", FUTURE_SKEW_BUCKETS)

// note_future_skew records one future-timestamp refusal of a block stamped ts (unix ms) when our clock read now_ms,
// attributed to c (nil = this node). It returns the skew in ms (ts - now_ms; 0 or below when the block's time had
// passed by the time the verdict was noted).
func note_future_skew(c *Connection, ts uint64, now_ms int64) int64 {
	skew := int64(ts) - now_ms
	future_blocks_total.Inc()
	s := float64(skew) / 1000
	if s < 0 {
		s = 0
	}
	future_skew_seconds.Update(s)
	if c != nil {
		c.obs.future_blocks.Add(1)
		for {
			old := c.obs.future_skew_max.Load()
			if skew <= old || c.obs.future_skew_max.CompareAndSwap(old, skew) {
				break
			}
		}
	}
	return skew
}

// log_incoming_block_failure (r31, B269 (c)): a synced block the chain did not add. It was
// connection.logger.V(2).Error: logr prints an Error at every verbosity, so it reached the console as an ERROR from
// a logger NAMED after the peer's ip:port ("P2P.incoming.<ip>:<port>"). The verdict itself is already on the console
// once, attributed and rate-limited (note_block_result "Block rejected"); this echo goes to the file log at V(2) from
// the package logger, naming the sender only by its self-chosen peer_id (a pseudonym).
func log_incoming_block_failure(c *Connection, err error, missing_past bool) {
	msg := "Incoming Block could not be added due to some error"
	if missing_past {
		msg = "Incoming Block could not be added due to missing past, so skipping future block"
	}
	logger.V(2).Info(msg, "peer_id", peer_label(conn_peer(c)), "err", refusal_error_text(err))
}
