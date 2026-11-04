// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r25 (secpool, B44): the pool cap holds under concurrent admissions, and the fee-rate summary follows the mined set.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// The r24 verifier's case: 3,000 B of room under a 30,000 B cap, six 3,000 B txs paying the same rate as the pool,
// all verifying at once. Base 17da0dc: 6 admitted, 45,000 B pooled. Now one is admitted and the pool stays at the cap.
func TestR25CapHoldsUnderConcurrentAdmissions(t *testing.T) {
	f := new_fake_pool()
	fill(f, 9, 3000, func(i int) uint64 { return 80 })
	attach_test(t, f, 30_000)
	release := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted, full := 0, 0
	entered := make(chan struct{}, 6)
	for i := 0; i < 6; i++ {
		tx, raw := forged(80, uint64(10+i), 3000)
		wg.Add(1)
		go func(tx *transaction.Transaction, raw []byte) {
			defer wg.Done()
			err := Admit(raw, tx, func(tx *transaction.Transaction) error {
				entered <- struct{}{}
				<-release // still verifying while the others reach the gate
				f.put(forged_txid(tx), tx, 3000)
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				admitted++
			case errors.Is(err, ErrPoolFull):
				full++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}(tx, raw)
	}
	time.Sleep(100 * time.Millisecond) // every admission is either verifying or refused by now
	close(release)
	wg.Wait()
	f.Lock()
	pooled := uint64(len(f.txs)) * 3000
	f.Unlock()
	t.Logf("SECPOOL cap-concurrency cap=30000 admitted=%d refused_full=%d pooled_bytes=%d", admitted, full, pooled)
	if admitted != 1 || full != 5 || pooled > 30_000 {
		t.Fatalf("admitted %d, refused %d, pooled %d B over a 30,000 B cap", admitted, full, pooled)
	}
	p.Lock()
	left := p.inflight
	p.Unlock()
	if left != 0 {
		t.Fatalf("%d reserved bytes left after every admission finished", left)
	}
}

// A failed or panicking admission gives its reservation back.
func TestR25ReservationReleasedOnFailure(t *testing.T) {
	f := new_fake_pool()
	fill(f, 9, 3000, func(i int) uint64 { return 80 })
	attach_test(t, f, 30_000)
	tx, raw := forged(80, 1, 3000)
	Admit(raw, tx, func(*transaction.Transaction) error { return errors.New("nonce already used") })
	func() {
		defer func() { recover() }()
		tx, raw := forged(80, 2, 3000)
		Admit(raw, tx, func(*transaction.Transaction) error { panic("boom") })
	}()
	tx, raw = forged(80, 3, 3000)
	called := false
	if err := Admit(raw, tx, func(*transaction.Transaction) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("room left by failed admissions was not given back: %v", err)
	}
}

// FeeToEnter counts the bytes still verifying, like the gate it predicts.
func TestR25FeeToEnterCountsReserved(t *testing.T) {
	f := new_fake_pool()
	fill(f, 9, 3000, func(i int) uint64 { return 80 })
	attach_test(t, f, 30_000)
	if FeeToEnter(3000) != 0 {
		t.Fatal("room for one: no entry fee expected")
	}
	release := make(chan struct{})
	started := make(chan struct{})
	tx, raw := forged(80, 1, 3000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Admit(raw, tx, func(*transaction.Transaction) error {
			close(started)
			<-release
			return errors.New("not admitted")
		})
	}()
	<-started
	need := FeeToEnter(3000)
	close(release)
	<-done // before the cleanup restores txid_of
	if need == 0 {
		t.Fatal("FeeToEnter ignored a reservation the gate counts")
	}
}

// After a block carries the pooled txs, the next admission sees them as mined at once (base: refused for up to
// SUMMARY_TTL by the cached summary).
func TestR25SummaryFollowsMinedSet(t *testing.T) {
	f := new_fake_pool()
	hs := fill(f, 10, 3000, func(i int) uint64 { return 1000 })
	attach_test(t, f, 30_000)
	var mu sync.Mutex
	cur := map[crypto.Hash]bool{}
	SetMinedSource(func() map[crypto.Hash]bool { mu.Lock(); defer mu.Unlock(); return cur })
	tx, raw := forged(10, 1, 3000)
	if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("full pool of better payers: %v, want ErrPoolFull", err)
	}
	next := map[crypto.Hash]bool{} // a block carried all of them: RecentlyMined returns a new map
	for _, h := range hs {
		next[h] = true
	}
	mu.Lock()
	cur = next
	mu.Unlock()
	tx, raw = forged(10, 2, 3000) // well inside SUMMARY_TTL of the refusal above
	if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); err != nil {
		t.Fatalf("refused against txs a block already carried: %v", err)
	}
}

// The mined-set check costs no pool listing while the set is unchanged (the summary cache still works).
func TestR25SummaryCachedWhileMinedSetUnchanged(t *testing.T) {
	f := new_fake_pool()
	fill(f, 5, 3000, func(i int) uint64 { return 100 })
	attach_test(t, f, 1<<30)
	same := map[crypto.Hash]bool{crypto.Keccak256([]byte("x")): true}
	SetMinedSource(func() map[crypto.Hash]bool { return same })
	for i := 0; i < 20; i++ {
		tx, raw := forged(100, uint64(i), 3000)
		Admit(raw, tx, func(*transaction.Transaction) error { return nil })
	}
	if f.lists > 2 {
		t.Fatalf("pool listed %d times for 20 admissions with an unchanged mined set", f.lists)
	}
}
