// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package p2p

// Grey-peer quarantine (Round 21, local dialing policy only; nothing about validity changes).
//
// Live r20 (derod pid 39803, 2026-10-28 13:26:35 -> 13:27:35): p2p_handshake_failures_total rose 196 -> 206, ten
// failed outgoing handshakes per minute, while the peer list held only 7 unconnected entries. Cause: clean_up purges
// a gossiped (grey) entry once FailCount reaches 8, and the very next handshake or 10th ping of any connected peer
// gossips it again (peer_add_gossip -> Peer_Add with FailCount 0), so the back-off restarts at 1 s and a dead
// address costs 8 dials every ~2-3 minutes forever. peers.json at 13:19 showed the four grey entries at FailCount
// 3, 4, 4 and 7 only 5 minutes after the restart. Over the 7-day log 89.38.99.117 and 89.38.97.110 produced 1,542
// and 1,364 "backing off" lines and never once connected.
//
// A grey entry purged for failures is now remembered for GREY_QUARANTINE (doubling per repeat, at most
// GREY_QUARANTINE_MAX) and gossip cannot re-admit it before then. Whitelisted peers (connected to before) are never
// quarantined; they keep their capped exponential back-off. The table is bounded (GREY_QUARANTINE_ENTRIES); when it
// is full of live entries a new address is simply not recorded (fail open: the address is dialed as before).

import (
	"sync"
	"time"

	"github.com/deroproject/derohe/metrics"
)

const GREY_QUARANTINE = 6 * time.Hour
const GREY_QUARANTINE_MAX = 48 * time.Hour
const GREY_QUARANTINE_ENTRIES = 1024

type grey_quarantine_entry struct {
	strikes uint
	until   time.Time
}

var grey_quarantine = struct {
	sync.Mutex
	m map[string]*grey_quarantine_entry
}{m: map[string]*grey_quarantine_entry{}}

var _ = metrics.Set.GetOrCreateCounter("p2p_grey_quarantined_total")
var _ = metrics.Set.GetOrCreateCounter("p2p_gossip_quarantine_refusals_total")

func grey_quarantine_duration(strikes uint) time.Duration {
	d := GREY_QUARANTINE
	for i := uint(1); i < strikes && d < GREY_QUARANTINE_MAX; i++ {
		d *= 2
	}
	if d > GREY_QUARANTINE_MAX {
		d = GREY_QUARANTINE_MAX
	}
	return d
}

// quarantine_grey records that the grey entry ip was purged for repeated failures.
func quarantine_grey(ip string, now time.Time) {
	if ip == "" {
		return
	}
	grey_quarantine.Lock()
	defer grey_quarantine.Unlock()
	e := grey_quarantine.m[ip]
	if e == nil {
		if len(grey_quarantine.m) >= GREY_QUARANTINE_ENTRIES {
			for k, v := range grey_quarantine.m {
				if !now.Before(v.until) {
					delete(grey_quarantine.m, k)
				}
			}
			if len(grey_quarantine.m) >= GREY_QUARANTINE_ENTRIES {
				return // fail open
			}
		}
		e = &grey_quarantine_entry{}
		grey_quarantine.m[ip] = e
	}
	e.strikes++
	e.until = now.Add(grey_quarantine_duration(e.strikes))
	metrics.Set.GetOrCreateCounter("p2p_grey_quarantined_total").Inc()
}

// grey_quarantined reports whether gossip about ip must be ignored at now.
func grey_quarantined(ip string, now time.Time) bool {
	grey_quarantine.Lock()
	defer grey_quarantine.Unlock()
	e := grey_quarantine.m[ip]
	return e != nil && now.Before(e.until)
}

// grey_quarantine_clear forgets ip (it answered a handshake after all).
func grey_quarantine_clear(ip string) {
	grey_quarantine.Lock()
	delete(grey_quarantine.m, ip)
	grey_quarantine.Unlock()
}

func grey_quarantine_size() int {
	grey_quarantine.Lock()
	defer grey_quarantine.Unlock()
	return len(grey_quarantine.m)
}
