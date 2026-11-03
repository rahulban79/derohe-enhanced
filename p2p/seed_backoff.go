// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Dial back-off for endpoints that are not in the peer list (Round 19, local dialing policy only).
//
// Round 18 revived the peer list's exponential back-off for failed handshakes (note_handshake_failure ->
// Peer_SetFail), but Peer_SetFail is a no-op for an address the peer list does not hold. The seed loop
// (maintain_seed_node_connection) dials a random config.Mainnet_seed_nodes entry every 2 s, and an unreachable seed
// is never added to the list, so it was redialled for ever: on the live r18 node (2026-10-24 18:49-19:25, 15 peers,
// all reachable whitelisted peers connected) KCP_ActiveOpens reached 568 and p2p_handshake_failures_total 548 in
// 2,161 s, while 5 of the 8 seeds have never completed a handshake (none of them is in peers.json). The same
// 1, 2, 4 ... 512 s schedule as fail_backoff_seconds now applies to them.

import "sync"
import "time"

const MAX_UNLISTED_BACKOFF_ENTRIES = 256

type unlisted_backoff struct {
	fails uint64
	next  time.Time
}

var unlisted_mu sync.Mutex
var unlisted_fail = map[string]*unlisted_backoff{} // ip -> back-off state

// note_unlisted_failure records a failed handshake to an ip that is not in the peer list.
func note_unlisted_failure(ip string, now time.Time) {
	if ip == "" {
		return
	}
	unlisted_mu.Lock()
	defer unlisted_mu.Unlock()
	r := unlisted_fail[ip]
	if r == nil {
		if len(unlisted_fail) >= MAX_UNLISTED_BACKOFF_ENTRIES { // bounded: forget entries whose back-off has expired
			for k, v := range unlisted_fail {
				if !now.Before(v.next) {
					delete(unlisted_fail, k)
				}
			}
			if len(unlisted_fail) >= MAX_UNLISTED_BACKOFF_ENTRIES {
				return
			}
		}
		r = &unlisted_backoff{}
		unlisted_fail[ip] = r
	}
	r.fails++
	r.next = now.Add(time.Duration(fail_backoff_seconds(r.fails)) * time.Second)
}

// unlisted_dial_allowed reports whether an endpoint outside the peer list may be dialled now.
func unlisted_dial_allowed(ip string, now time.Time) bool {
	unlisted_mu.Lock()
	defer unlisted_mu.Unlock()
	r := unlisted_fail[ip]
	return r == nil || !now.Before(r.next)
}

// note_unlisted_success clears the back-off once a handshake to ip succeeded.
func note_unlisted_success(ip string) {
	unlisted_mu.Lock()
	delete(unlisted_fail, ip)
	unlisted_mu.Unlock()
}

// seed_should_dial: the seed loop's dial decision for one randomly chosen seed endpoint.
func seed_should_dial(endpoint string, now time.Time) bool {
	return endpoint != "" && unlisted_dial_allowed(ParseIPNoError(endpoint), now)
}
