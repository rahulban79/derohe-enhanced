// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Eager registration of the p2p counters (r21 forensics, observability only).
//
// Every p2p counter is created lazily by its first GetOrCreateCounter(...).Inc(), so a path that has not fired yet is
// ABSENT from /metrics rather than 0. On the live r20 node (2026-10-28, 18 min up, no transaction in any block) the
// new r20 counters p2p_compact_block_{hits,misses,rejects}_total and p2p_tx_ask_repeats_skipped_total were missing,
// which reads the same as a binary without the feature; so were the bootstrap, penalty and netgroup counters.
// Registering them at start makes "never happened" (0) distinguishable from "not built in" (absent).
// TestP2PCountersRegisteredEagerly keeps this list complete against the GetOrCreateCounter literals in p2p/*.go.
// Labelled counters (call_timeouts, first_relay, penalty_events, miniblock_deliveries) stay lazy: their label values
// are open-ended (r29 B152: busy_rejections has a closed method set and is created in r29_lazy_preregister.go). The
// few fixed-label and non-p2p_ series that must also show a zero (handshake failures by kind,
// miniblock_ours_broadcast_failed_total) are registered in metrics_preregister.go (r21 merge: one list per series, the
// syncp2p and forensics registrations deduplicated).

import "github.com/deroproject/derohe/metrics"

var p2p_counters = []string{
	"p2p_bans_total",
	"p2p_block_offer_duplicate_total", // r25 (consensus_obs_r25.go)
	"p2p_bootstrap_fallbacks_total",
	"p2p_bootstrap_foreign_keys_total",
	"p2p_bootstrap_prefill_fallbacks_total",
	"p2p_bootstrap_sections_total",
	"p2p_chunks_unknown_tip_total",
	"p2p_compact_block_hits_total",
	"p2p_compact_block_misses_total",
	"p2p_compact_block_rejects_total",
	"p2p_gossip_quarantine_refusals_total",
	"p2p_grey_quarantined_total",
	"p2p_handshake_failures_total",
	"p2p_hf3_table_blocks_total",
	"p2p_outbound_netgroup_refused_total",
	"p2p_penalty_bans_total",
	"p2p_penalty_aggregate_bans_total",     // r23c
	"p2p_inbound_aggregate_refusals_total", // r23c
	"p2p_sync_blocks_fetched_total",
	"p2p_sync_continued_rounds_total",
	"p2p_sync_getobject_calls_total",
	"p2p_sync_large_block_fallbacks_total",
	"p2p_sync_locator_read_errors_total", // r24
	"p2p_stuck_peer_evictions_total",
	"p2p_stuck_peer_fast_evictions_total",
	"p2p_sync_pow_prewarmed_total",
	"p2p_tx_ask_repeats_skipped_total",
	"p2p_tx_fetch_budget_drops_total",
	"p2p_tx_fetch_failures_total",
	"p2p_tx_inv_known_skipped_total",
	"p2p_chain_requests_served_total",  // r25 (peers, CO24-N3)
	"p2p_chain_request_blocks_total",   // r25
	"p2p_chain_requests_refused_total", // r25
	"p2p_objects_unserved_total",       // r25 (CO24-N6)
	"p2p_sync_short_answers_total",     // r25 (CO24-N6)
	"p2p_sync_peer_holds_total",        // r25 (B47)
	"p2p_sync_held_fallbacks_total",    // r26 (B99)
	"p2p_sync_relay_forgiven_total",    // r26 (B99)
	"p2p_sync_strike_decays_total",     // r27 (B99 observability)
	"p2p_sync_served_forgiven_total",   // r27 (B99 observability)
	"p2p_bans_loaded_total",            // r27 (bans reloaded at start)
}

func init() {
	for _, name := range p2p_counters {
		metrics.Set.GetOrCreateCounter(name)
	}
}
