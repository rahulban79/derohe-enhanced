// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r23c verify (p2psec): once an aggregate ban ends, a lookup from ANY address must restore the one-atomic-load fast
// path (before the fix only a lookup from the expired aggregate itself did, so admit_inbound paid ~1.9x forever).

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestR23cVerifyAggStaleClearedByAnyLookup(t *testing.T) {
	reset_agg(t)
	saved := nonbanlist
	defer func() { nonbanlist = saved }()
	nonbanlist = nil
	now := time.Now()
	for i := 0; i < PENALTY_AGG_MEMBERS; i++ {
		note_score_ban(fmt.Sprintf("203.0.113.%d", 10+i), now)
	}
	if atomic.LoadInt32(&agg_active) != 1 || !inbound_aggregate_banned("203.0.113.99", now) {
		t.Fatal("setup: the aggregate is not banned")
	}
	later := now.Add(PENALTY_AGG_BAN_BASE + time.Second)
	if inbound_aggregate_banned("198.51.100.7", later) { // an UNRELATED address arrives after the ban ended
		t.Fatal("unrelated address refused")
	}
	if n := atomic.LoadInt32(&agg_active); n != 0 {
		t.Fatalf("agg_active=%d after the only aggregate ban ended: every inbound session keeps paying the slow path", n)
	}
	// a ban that is still running keeps the slow path, and stays enforced
	for i := 0; i < PENALTY_AGG_MEMBERS; i++ {
		note_score_ban(fmt.Sprintf("192.0.2.%d", 10+i), later)
	}
	if inbound_aggregate_banned("198.51.100.7", later.Add(time.Second)) || !inbound_aggregate_banned("192.0.2.200", later.Add(time.Second)) {
		t.Fatal("running ban not enforced after recount")
	}
}
