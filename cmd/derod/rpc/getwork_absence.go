// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r23b payouts: a node whose miner left earns nothing, and nothing said so. Over the 72 h before 2026-10-30 19:10
// the getwork miner was connected 22.4 h (31%; derod.log presence lines), every gap ended by a console "exit" in the
// miner log, the longest 10.5 h (07:30 -> 18:03). The node now exports how long it has been without a miner
// (getwork_miner_absent_seconds; 0 while one is connected, -1 before the first one since start, so a node that never
// mines is not reported as "absent") and logs a WARNING once the absence passes DERO_MINER_ABSENT_WARN_MIN minutes
// (default 10, 0 = off), then again every MINER_ABSENT_REPEAT while it lasts. Monitoring only: no consensus input.

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/metrics"
)

// getwork_absent_since_unix: unix seconds when the last miner left; 0 while a miner is connected or before the first.
var getwork_absent_since_unix int64

// getwork_miner_seen: 1 once any miner registered since start.
var getwork_miner_seen int32

const MINER_ABSENT_WARN_DEFAULT = 10 * time.Minute
const MINER_ABSENT_REPEAT = time.Hour

var _ = metrics.Set.NewGauge("getwork_miner_absent_seconds", func() float64 {
	return miner_absent_seconds(atomic.LoadInt32(&getwork_miner_seen) == 1, atomic.LoadInt64(&getwork_absent_since_unix), time.Now().Unix())
})

// miner_absent_seconds: -1 when no miner was ever seen, 0 while one is connected, else the seconds since the last left.
func miner_absent_seconds(seen bool, since, now int64) float64 {
	if !seen {
		return -1
	}
	if since == 0 || now < since {
		return 0
	}
	return float64(now - since)
}

// note_presence keeps the absence clock: called under client_list_mutex with the miner count after the change.
func note_presence(after int, now time.Time) {
	if after > 0 {
		atomic.StoreInt32(&getwork_miner_seen, 1)
		atomic.StoreInt64(&getwork_absent_since_unix, 0)
		return
	}
	if atomic.LoadInt32(&getwork_miner_seen) == 1 && atomic.LoadInt64(&getwork_absent_since_unix) == 0 {
		atomic.StoreInt64(&getwork_absent_since_unix, now.Unix())
	}
}

// miner_absent_warn_after parses DERO_MINER_ABSENT_WARN_MIN (minutes; 0 = off; unset/invalid = the default).
func miner_absent_warn_after(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return MINER_ABSENT_WARN_DEFAULT
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return MINER_ABSENT_WARN_DEFAULT
	}
	return time.Duration(n) * time.Minute
}

// absence_warn_due: warn once the absence reaches after, then every repeat. last is the previous warning (zero =
// none in this absence). Pure, so the rule is unit-tested.
func absence_warn_due(absent, after, repeat time.Duration, last, now time.Time) bool {
	if after <= 0 || absent < after {
		return false
	}
	return last.IsZero() || now.Sub(last) >= repeat
}

// run_absence_watch checks every tick; it never touches the chain or the miners.
func run_absence_watch(after time.Duration, tick <-chan time.Time, warn func(absent time.Duration, since time.Time)) {
	var last time.Time
	var last_since int64
	for now := range tick {
		since := atomic.LoadInt64(&getwork_absent_since_unix)
		if since == 0 || since != last_since { // a miner came back, or a new absence began: start over
			last = time.Time{}
			last_since = since
		}
		if since == 0 {
			continue
		}
		absent := now.Sub(time.Unix(since, 0))
		if absence_warn_due(absent, after, MINER_ABSENT_REPEAT, last, now) {
			last = now
			warn(absent, time.Unix(since, 0))
		}
	}
}
