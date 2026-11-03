// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Back-to-back sync rounds (Round 19, p2p scheduling only: the same requests, the same verification).
//
// One sync_chain covers what one chain response lists (at most ~512 blocks: live r18 restart 2026-10-24, the first
// round went 7805170 -> 7805682). The next round waited for the 4 s syncroniser cron plus trigger_sync's 1 s
// "still lagging?" sleep. derod.log (2026-10-21..24) shows 5 idle gaps of 1.44-4.75 s (mean 2.92 s) between rounds
// while the node was still 32-794 blocks behind; at r18's ~46 blocks/s a 512-block round takes ~11 s, so about a fifth
// of a long catch-up was idle (estimate).
// After a round that made progress, sync again at once with the same peer while it is still well ahead of us.

// Bounds (verifier F4): a round must add at least SYNC_CONTINUE_MIN_PROGRESS blocks, so a peer that trickles one
// block per round is not kept in a tight loop, and at most SYNC_CONTINUE_MAX_ROUNDS rounds (about 8k blocks) run back
// to back before trigger_sync returns, so the syncroniser cron reshuffles peers.
const SYNC_CONTINUE_MIN_LAG = 16      // blocks; closer than this, normal block propagation (and the cron) catches up
const SYNC_CONTINUE_MIN_PROGRESS = 64 // blocks per round
const SYNC_CONTINUE_MAX_ROUNDS = 16   // ~8k blocks at 512/round with one peer, then back to the cron

// sync_should_continue decides whether trigger_sync runs another sync round with the same peer right away.
func sync_should_continue(round int, before, after, peer_height int64, peer_exited bool) bool {
	if peer_exited || round >= SYNC_CONTINUE_MAX_ROUNDS {
		return false
	}
	if after-before < SYNC_CONTINUE_MIN_PROGRESS { // little or no progress: a failing, slow or useless peer must not be retried in a tight loop
		return false
	}
	return peer_height-after > SYNC_CONTINUE_MIN_LAG
}
