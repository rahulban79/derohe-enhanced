// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r29 (live-observability, dero-rft §7 B152): the node-side families the R28 registry build found absent from the live
// page are created at start: miniblock_ours_orphaned_total by resolve_fate's closed reason set
// (TestR29OrphanedReasonsAreResolveFates), and the two chain counters whose sources sit in the consensus-guarded
// blockchain packages (mempool.go, blockchain.go) are registered here by the same names, which GetOrCreateCounter
// returns to those sources unchanged. transaction_total's types are the TransactionType names a mined block's txs
// carry (transaction.go String: NORMAL, REGISTRATION, BURN, SC).

import "github.com/deroproject/derohe/metrics"

var orphaned_reasons = []string{"block_race", "slots_full", "not_included"}

func init() {
	for _, r := range orphaned_reasons {
		metrics.Set.GetOrCreateCounter(`miniblock_ours_orphaned_total{reason="` + r + `"}`)
	}
	metrics.Set.GetOrCreateCounter("mempool_discarded_total")
	for _, ty := range []string{"NORMAL", "REGISTRATION", "BURN", "SC"} {
		metrics.Set.GetOrCreateCounter(`transaction_total{type="` + ty + `"}`)
	}
}
