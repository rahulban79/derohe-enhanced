// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// r29 (live-observability, dero-rft §7 B152): the p2p families the R28 registry build found absent from the live page
// (in_scrape=false) are created at start, so "never happened" reads 0 instead of absent. Their label sets are closed:
// busy_methods are the heavy() call sites of controller.go and broadcast_fail_reasons the values failure_reason
// returns (TestR29BusyMethodsAreTheHeavyCallSites, TestR29BroadcastFailReasonsClosedSet keep them so).

import "github.com/deroproject/derohe/metrics"

var busy_methods = []string{"Peer.Chain", "Peer.ChangeSet", "Peer.GetObject", "Peer.TreeSection"}

var broadcast_fail_reasons = []string{"duplicate", "timeout", "peer_behind", "peer_unregistered", "connection", "other"}

func init() {
	metrics.Set.GetOrCreateCounter("miniblock_ours_broadcast_peers_total")
	metrics.Set.GetOrCreateFloatCounter("p2p_bootstrap_wait_seconds_total")
	metrics.Set.GetOrCreateFloatCounter("p2p_bootstrap_process_seconds_total")
	for _, m := range busy_methods {
		metrics.Set.GetOrCreateCounter(`p2p_busy_rejections_total{method="` + m + `"}`)
	}
	for _, r := range broadcast_fail_reasons {
		metrics.Set.GetOrCreateCounter(`miniblock_ours_broadcast_failed_by_reason_total{reason="` + r + `"}`)
	}
}
