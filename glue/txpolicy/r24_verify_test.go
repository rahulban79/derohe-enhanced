// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r24 (verify-txpool): adversarial regression tests of the flight and the negative cache.

import (
	"errors"
	"testing"
	"time"

	"github.com/deroproject/derohe/transaction"
)

// V2: a panicking leader must release its followers with an error (never success, never a hang).
func TestR24LeaderPanicReleasesFollowers(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		defer func() { recover() }()
		Admit(raw, tx, func(*transaction.Transaction) error { close(started); <-release; panic("boom") })
	}()
	<-started
	res := make(chan error, 1)
	go func() {
		res <- Admit(append([]byte(nil), raw...), tx, func(*transaction.Transaction) error { return nil })
	}()
	time.Sleep(30 * time.Millisecond)
	close(release)
	select {
	case err := <-res:
		if err == nil || errors.Is(err, ErrDuplicate) {
			t.Fatalf("follower of a panicked leader got %v", err)
		}
		t.Logf("VERIFY follower of panicked leader: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatalf("follower hung after the leader panicked")
	}
}

// V3: the negative verdict is keyed by the exact bytes, not the txid: an attacker who presents a corrupted-proof
// variant of a valid tx (same txid in DERO, the proof is not hashed into it) must not block the valid bytes.
func TestR24NegCacheCannotPoisonValidBytes(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, good := forged(100, 1, 3000)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 1
	perr := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	Admit(bad, tx, func(*transaction.Transaction) error { return perr })
	if KnownInvalid(bad) == nil {
		t.Fatalf("bad bytes not remembered")
	}
	called := false
	if err := Admit(good, tx, func(*transaction.Transaction) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("valid bytes of the same tx were refused by the negative cache: %v called=%v", err, called)
	}
	if KnownInvalid(good) != nil {
		t.Fatalf("valid bytes reported known-invalid")
	}
}

// V4: a pool-full refusal is never remembered as invalid (the same bytes must be re-gated once room exists).
func TestR24PoolFullNotRemembered(t *testing.T) {
	f := new_fake_pool()
	hs := fill(f, 10, 3000, func(i int) uint64 { return 80 })
	attach_test(t, f, 30_000)
	tx, raw := forged(80, 1, 3000)
	if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("want ErrPoolFull: %v", err)
	}
	f.Mempool_Delete_TX(hs[0])
	p.Lock()
	p.sum_at = time.Time{}
	p.Unlock()
	called := false
	if err := Admit(raw, tx, func(*transaction.Transaction) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("after room appeared: %v called=%v", err, called)
	}
}
