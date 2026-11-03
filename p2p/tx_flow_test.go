// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
package p2p

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

func flow_tx(height uint64) (*transaction.Transaction, []byte) {
	tx := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: height}}
	return tx, tx.Serialize()
}

// N connections deliver the same bytes while the first admission is still verifying: one Add_TX_To_Pool call,
// everyone gets its verdict, exactly one caller relays.
func TestTxInflightCollapsesConcurrentAdmissions(t *testing.T) {
	tx, raw := flow_tx(7)
	var calls, relays int32
	release := make(chan struct{})
	add := func(*transaction.Transaction) error {
		atomic.AddInt32(&calls, 1)
		<-release
		return nil
	}
	const n = 8
	var wg sync.WaitGroup
	started := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			if err, relay := admit_relayed_tx(raw, tx, add); err != nil {
				t.Errorf("unexpected err %v", err)
			} else if relay {
				atomic.AddInt32(&relays, 1)
			}
		}()
	}
	for i := 0; i < n; i++ {
		<-started
	}
	time.Sleep(50 * time.Millisecond) // let every caller reach the in-flight set
	close(release)
	wg.Wait()
	if calls != 1 || relays != 1 {
		t.Fatalf("calls=%d relays=%d, want 1 and 1", calls, relays)
	}
	// once settled the entry is gone: a later delivery is admitted again (the pool's own dedupe answers it)
	if err, relay := admit_relayed_tx(raw, tx, func(*transaction.Transaction) error { return errors.New("already in pool") }); err == nil || relay {
		t.Fatalf("stale flight reused: err=%v relay=%v", err, relay)
	}
}

// Different bytes with the same txid (txid does not cover proofs) must never share a verdict.
func TestTxInflightKeyIsBytesNotTxid(t *testing.T) {
	tx, raw := flow_tx(9)
	forged := append(append([]byte(nil), raw...), 0xff)
	var calls int32
	release := make(chan struct{})
	add := func(*transaction.Transaction) error { atomic.AddInt32(&calls, 1); <-release; return nil }
	var wg sync.WaitGroup
	for _, b := range [][]byte{raw, forged} {
		wg.Add(1)
		go func(b []byte) { defer wg.Done(); admit_relayed_tx(b, tx, add) }(b)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls != 2 {
		t.Fatalf("calls=%d, want 2 (distinct bytes verified separately)", calls)
	}
}

// A panicking admission is never reported to waiters as success (they would relay an unverified tx).
func TestTxInflightPanicIsNotSuccess(t *testing.T) {
	s := new_tx_inflight_set()
	var key, txid crypto.Hash
	key[0], txid[0] = 1, 2
	entered := make(chan struct{})
	release := make(chan struct{})
	go func() {
		defer func() { recover() }()
		s.do(key, txid, func() error { close(entered); <-release; panic("boom") })
	}()
	<-entered
	got := make(chan error, 1)
	go func() { err, _ := s.do(key, txid, func() error { return nil }); got <- err }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	select {
	case err := <-got:
		if err == nil {
			t.Fatalf("waiter saw success from a panicked admission")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("waiter hung")
	}
}

// An INV for a txid being admitted elsewhere waits and then skips the fetch if the tx landed in the pool.
func TestTxInflightSettledWaitsForAdmission(t *testing.T) {
	s := new_tx_inflight_set()
	var key, txid crypto.Hash
	key[0], txid[0] = 3, 4
	var inpool int32
	have := func(crypto.Hash) bool { return atomic.LoadInt32(&inpool) == 1 }
	if s.settled(txid, time.Second, have) {
		t.Fatalf("no flight: must not report settled")
	}
	entered := make(chan struct{})
	go s.do(key, txid, func() error {
		close(entered)
		time.Sleep(80 * time.Millisecond)
		atomic.StoreInt32(&inpool, 1)
		return nil
	})
	<-entered
	if !s.settled(txid, time.Second, have) {
		t.Fatalf("waited flight landed in pool but settled=false")
	}
	// bounded: a stuck admission does not hold the INV handler past the timeout
	block := make(chan struct{})
	entered2 := make(chan struct{})
	var txid2 crypto.Hash
	txid2[0] = 5
	go s.do(txid2, txid2, func() error { close(entered2); <-block; return nil })
	<-entered2
	t0 := time.Now()
	if s.settled(txid2, 60*time.Millisecond, func(crypto.Hash) bool { return true }) || time.Since(t0) > time.Second {
		t.Fatalf("settled must time out and report false")
	}
	close(block)
}

func reset_announced(jitter time.Duration) func() {
	announced_txs.Lock()
	announced_txs.m = map[crypto.Hash]*announced_tx{}
	announced_txs.Unlock()
	saved := rebroadcast_jitter
	rebroadcast_jitter = func() time.Duration { return jitter }
	return func() {
		rebroadcast_jitter = saved
		announced_txs.Lock()
		announced_txs.m = map[crypto.Hash]*announced_tx{}
		announced_txs.Unlock()
	}
}

func TestLocalTxRebroadcastPolicy(t *testing.T) {
	defer reset_announced(0)()
	tx, _ := flow_tx(11)
	gone, _ := flow_tx(12)
	t0 := time.Unix(1700000000, 0)
	track_announced_tx(tx, t0)
	track_announced_tx(gone, t0)
	pool := map[crypto.Hash]bool{tx.GetHash(): true}
	in := func(h crypto.Hash) bool { return pool[h] }

	if d := due_announced_txs(t0.Add(REBROADCAST_AFTER/2), in, 3); len(d) != 0 {
		t.Fatalf("rebroadcast before interval: %d", len(d))
	}
	announced_txs.Lock()
	_, kept := announced_txs.m[gone.GetHash()]
	announced_txs.Unlock()
	if kept {
		t.Fatalf("tx no longer in pool must be forgotten")
	}
	n := 0
	for i := 1; i <= REBROADCAST_MAX+3; i++ {
		n += len(due_announced_txs(t0.Add(time.Duration(i)*REBROADCAST_AFTER), in, 3))
	}
	if n != REBROADCAST_MAX {
		t.Fatalf("rebroadcasts=%d want %d", n, REBROADCAST_MAX)
	}
	announced_txs.Lock()
	left := len(announced_txs.m)
	announced_txs.Unlock()
	if left != 0 {
		t.Fatalf("exhausted entry not pruned")
	}
}

// privacy (TXF-03): a tx we relayed after our own successful admission is tracked exactly like one submitted here,
// so the repeats do not single out the origin
func TestRebroadcastTreatsRelayedLikeLocal(t *testing.T) {
	defer reset_announced(0)()
	defer func(s *tx_inflight_set) { tx_inflight = s }(tx_inflight)
	tx_inflight = new_tx_inflight_set()
	relayed, raw := flow_tx(21)
	local, _ := flow_tx(22)
	if _, relay := admit_relayed_tx(raw, relayed, func(*transaction.Transaction) error { return nil }); !relay {
		t.Fatal("own successful admission must relay")
	}
	track_announced_tx(local, globals.Time())
	announced_txs.Lock()
	r, l := announced_txs.m[relayed.GetHash()], announced_txs.m[local.GetHash()]
	announced_txs.Unlock()
	if r == nil || l == nil {
		t.Fatalf("relayed tracked %v, local tracked %v: both must be re-announced alike", r != nil, l != nil)
	}
	failed, raw2 := flow_tx(23)
	admit_relayed_tx(raw2, failed, func(*transaction.Transaction) error { return errors.New("bad proof") })
	announced_txs.Lock()
	_, bad := announced_txs.m[failed.GetHash()]
	announced_txs.Unlock()
	if bad {
		t.Fatal("a rejected tx was queued for rebroadcast")
	}
}

// TXF-03 (2): an interval with no eligible peer does not use up an attempt
func TestRebroadcastNeedsEligiblePeer(t *testing.T) {
	defer reset_announced(0)()
	tx, _ := flow_tx(31)
	t0 := time.Unix(1700000000, 0)
	track_announced_tx(tx, t0)
	in := func(crypto.Hash) bool { return true }
	for i := 1; i <= 2*REBROADCAST_MAX; i++ {
		if d := due_announced_txs(t0.Add(time.Duration(i)*REBROADCAST_AFTER), in, 0); len(d) != 0 {
			t.Fatal("re-announced with no eligible peer")
		}
	}
	if d := due_announced_txs(t0.Add(time.Duration(2*REBROADCAST_MAX+1)*REBROADCAST_AFTER), in, 1); len(d) != 1 {
		t.Fatalf("attempts were used up while no peer was eligible (due %d)", len(d))
	}
}

// re-announcements are delayed by a random jitter on top of REBROADCAST_AFTER
func TestRebroadcastJitter(t *testing.T) {
	defer reset_announced(10 * time.Second)()
	tx, _ := flow_tx(41)
	t0 := time.Unix(1700000000, 0)
	track_announced_tx(tx, t0)
	in := func(crypto.Hash) bool { return true }
	if d := due_announced_txs(t0.Add(REBROADCAST_AFTER+9*time.Second), in, 1); len(d) != 0 {
		t.Fatal("re-announced before its jitter elapsed")
	}
	if d := due_announced_txs(t0.Add(REBROADCAST_AFTER+10*time.Second), in, 1); len(d) != 1 {
		t.Fatal("not re-announced after interval + jitter")
	}
}

// TXF-02: a spent wait budget never blocks
func TestTxInflightSettledZeroBudget(t *testing.T) {
	s := new_tx_inflight_set()
	tx, raw := flow_tx(51)
	release := make(chan struct{})
	go s.do(crypto.Keccak256(raw), tx.GetHash(), func() error { <-release; return nil })
	for i := 0; i < 100; i++ {
		s.Lock()
		_, ok := s.bytxid[tx.GetHash()]
		s.Unlock()
		if ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	t0 := time.Now()
	if s.settled(tx.GetHash(), 0, func(crypto.Hash) bool { return true }) || time.Since(t0) > 100*time.Millisecond {
		t.Fatalf("zero budget waited %s", time.Since(t0))
	}
	close(release)
}
