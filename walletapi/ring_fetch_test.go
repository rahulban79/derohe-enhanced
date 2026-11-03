// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
package walletapi

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Round trips overlap (bounded), every index is fetched once, and the reported error is the lowest failing index,
// i.e. the one the old sequential loop would have returned.
func TestFetchOrderedOverlapsBoundedAndKeepsFirstError(t *testing.T) {
	const n, workers = 32, 8
	var inflight, peak, calls int32
	slow := func(i int) error {
		atomic.AddInt32(&calls, 1)
		c := atomic.AddInt32(&inflight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if c <= p || atomic.CompareAndSwapInt32(&peak, p, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) // one simulated round trip
		atomic.AddInt32(&inflight, -1)
		return nil
	}
	t0 := time.Now()
	if err := fetch_ordered(n, workers, slow); err != nil {
		t.Fatal(err)
	}
	el := time.Since(t0)
	if calls != n {
		t.Fatalf("calls=%d want %d", calls, n)
	}
	if peak > workers || peak < 2 {
		t.Fatalf("peak in flight=%d, want 2..%d", peak, workers)
	}
	if el > time.Duration(n)*20*time.Millisecond/2 {
		t.Fatalf("no overlap: %v for %d round trips", el, n)
	}

	e3, e7 := errors.New("member 3"), errors.New("member 7")
	err := fetch_ordered(10, 4, func(i int) error {
		switch i {
		case 3:
			time.Sleep(30 * time.Millisecond) // finishes after 7 fails
			return e3
		case 7:
			return e7
		}
		return nil
	})
	if err != e3 {
		t.Fatalf("err=%v, want the lowest failing index (member 3)", err)
	}
}

// TestRingProgressGivesUp: the decoy loop ends with an error after RING_MAX_STALL_ROUNDS rounds without a new
// member, and progress resets the count (TXF-05: it used to spin forever).
func TestRingProgressGivesUp(t *testing.T) {
	r := ring_progress{need: 16}
	have := 2
	rounds := 0
	var err error
	for ; rounds < 10000; rounds++ {
		if err = r.check(have); err != nil {
			break
		}
		if rounds < 5 {
			have += 2 // some progress first
		}
	}
	if err == nil {
		t.Fatalf("a loop that never reaches the ring size must give up")
	}
	if rounds != 5+RING_MAX_STALL_ROUNDS {
		t.Fatalf("gave up after %d rounds, want %d", rounds, 5+RING_MAX_STALL_ROUNDS)
	}
	if !strings.Contains(err.Error(), "ringsize 16") || !strings.Contains(err.Error(), "have 12") {
		t.Fatalf("error must name the ring size and progress: %s", err)
	}
	r = ring_progress{need: 1 << 20}
	h := 2
	for i := 1; i <= 3*RING_MAX_STALL_ROUNDS; i++ {
		if i%(RING_MAX_STALL_ROUNDS-1) == 0 {
			h++ // a slow trickle of new members keeps it going
		}
		if err := r.check(h); err != nil {
			t.Fatalf("round %d: progress within the window must not fail: %s", i, err)
		}
	}
}

func TestRingStallDelay(t *testing.T) {
	if ring_stall_delay(0) != 0 {
		t.Fatalf("a round after progress must not wait")
	}
	if ring_stall_delay(3) != 150*time.Millisecond || ring_stall_delay(500) != time.Second {
		t.Fatalf("bad back-off %v %v", ring_stall_delay(3), ring_stall_delay(500))
	}
	var total time.Duration
	for i := 1; i < RING_MAX_STALL_ROUNDS; i++ {
		total += ring_stall_delay(i)
	}
	if total < 30*time.Second || total > 90*time.Second {
		t.Fatalf("total stall budget %v outside 30-90 s", total)
	}
}

// TestRingStallWired pins the call site: the decoy loop of TransferPayload0 checks ring_progress every round.
func TestRingStallWired(t *testing.T) {
	src, err := os.ReadFile("wallet_transfer.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	loop := strings.Index(s, "for ringsize != 2 {")
	check := strings.Index(s, "if err = ring_stall.check(len(ring_balances)); err != nil {")
	if loop < 0 || check < loop || check-loop > 600 {
		t.Fatalf("the decoy loop must start with ring_stall.check (TXF-05)")
	}
}
