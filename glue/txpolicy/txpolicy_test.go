// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r24 tests: forged pools and transactions (no chain); each rule is reverted by a gm-r24-txpool-* mutation.

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

type fake_pool struct {
	sync.Mutex
	txs     map[crypto.Hash]*transaction.Transaction
	sizes   map[crypto.Hash]uint64
	deleted []crypto.Hash
	lists   int
}

func new_fake_pool() *fake_pool {
	return &fake_pool{txs: map[crypto.Hash]*transaction.Transaction{}, sizes: map[crypto.Hash]uint64{}}
}

func (f *fake_pool) Mempool_List_TX_SortedInfo() (out []mempool.TX_Sorting_struct) {
	f.Lock()
	defer f.Unlock()
	f.lists++
	for h, tx := range f.txs {
		out = append(out, mempool.TX_Sorting_struct{Hash: h, Size: f.sizes[h], FeesPerByte: tx.Fees() / f.sizes[h]})
	}
	return
}
func (f *fake_pool) Mempool_Get_TX(h crypto.Hash) *transaction.Transaction {
	f.Lock()
	defer f.Unlock()
	return f.txs[h]
}
func (f *fake_pool) Mempool_Delete_TX(h crypto.Hash) *transaction.Transaction {
	f.Lock()
	defer f.Unlock()
	tx := f.txs[h]
	if tx != nil {
		delete(f.txs, h)
		f.deleted = append(f.deleted, h)
	}
	return tx
}
func (f *fake_pool) put(h crypto.Hash, tx *transaction.Transaction, size uint64) {
	f.Lock()
	defer f.Unlock()
	f.txs[h], f.sizes[h] = tx, size
}

// forged tx with a fee and a distinct height (so its txid differs); raw is a byte string of the given size
func forged(fee uint64, height uint64, size int) (*transaction.Transaction, []byte) {
	tx := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: height}}
	tx.Payloads = []transaction.AssetPayload{{}}
	tx.Payloads[0].Statement.Fees = fee
	raw := []byte(strings.Repeat(fmt.Sprintf("%020d|%020d|", fee, height), size/42+1))[:size]
	return tx, raw
}

// forged transactions carry no proofs, so they cannot be serialized: their txid is a hash of their fee and height
func forged_txid(tx *transaction.Transaction) crypto.Hash {
	return crypto.Keccak256([]byte(fmt.Sprintf("txid-%d-%d", tx.Fees(), tx.Height)))
}

func attach_test(t *testing.T, pool Pool, cap uint64) {
	Attach(pool, cap)
	old := txid_of
	txid_of = forged_txid
	t.Cleanup(func() { Detach(); SetMinedSource(nil); txid_of = old })
}

func TestR24LessRateExactAndNoOverflow(t *testing.T) {
	// both rank 0 under the mempool's integer fee/size, yet 1.2x vs 1.0x the floor must order
	if !less_rate(40, 1703, 120, 5033) || less_rate(120, 5033, 40, 1703) {
		t.Fatalf("exact fee rate order wrong")
	}
	if less_rate(100, 1000, 100, 1000) {
		t.Fatalf("equal rates are not less")
	}
	// 64-bit products overflow here: 2^63 * 4 = 2^65 wraps to 0, below 1 * 1
	if less_rate(1<<63, 1, 1, 4) || !less_rate(1, 4, 1<<63, 1) {
		t.Fatalf("fee rate compare overflows 64 bits")
	}
	if less_rate(math.MaxUint64, 2, math.MaxUint64-1, 2) || !less_rate(math.MaxUint64-1, 2, math.MaxUint64, 2) {
		t.Fatalf("128-bit compare wrong at the top of the range")
	}
}

func TestR24DetachedIsPassThrough(t *testing.T) {
	Attach(new_fake_pool(), 0)
	Detach() // after an Attach: Detach must really turn every rule off
	calls := 0
	bad := errors.New("Incoming TX x could not be verified, err transaction statement 0 verification failed")
	tx, raw := forged(100, 1, 3000)
	for i := 0; i < 3; i++ {
		if err := Admit(raw, tx, func(*transaction.Transaction) error { calls++; return bad }); err != bad {
			t.Fatalf("err %v", err)
		}
	}
	if calls != 3 {
		t.Fatalf("detached policy must call add every time, got %d", calls)
	}
}

func TestR24ConcurrentIdenticalBytesVerifiedOnce(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	var calls int32
	release := make(chan struct{})
	add := func(*transaction.Transaction) error {
		atomic.AddInt32(&calls, 1)
		<-release
		return nil
	}
	const N = 6
	errs := make([]error, N)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); errs[0] = Admit(raw, tx, add) }()
	for atomic.LoadInt32(&calls) == 0 {
		time.Sleep(time.Millisecond)
	}
	for i := 1; i < N; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = Admit(append([]byte(nil), raw...), tx, add) }(i)
	}
	time.Sleep(50 * time.Millisecond) // followers are parked on the flight
	close(release)
	wg.Wait()
	if calls != 1 {
		t.Fatalf("%d concurrent copies verified %d times, want 1", N, calls)
	}
	if errs[0] != nil {
		t.Fatalf("leader: %v", errs[0])
	}
	for i := 1; i < N; i++ {
		if !errors.Is(errs[i], ErrDuplicate) {
			t.Fatalf("follower %d: %v, want ErrDuplicate (never a second success: that would relay twice)", i, errs[i])
		}
	}
}

func TestR24KnownInvalidBytesNotReverified(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	calls := 0
	bad := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	for i := 0; i < 5; i++ {
		err := Admit(raw, tx, func(*transaction.Transaction) error { calls++; return bad })
		if err == nil || err.Error() != bad.Error() || !strings.Contains(err.Error(), "could not be verified") {
			t.Fatalf("replay %d: %v (the text must stay what p2p scores)", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("an invalid proof was verified %d times, want 1", calls)
	}
	// other bytes are verified as usual
	tx2, raw2 := forged(100, 2, 3000)
	if err := Admit(raw2, tx2, func(*transaction.Transaction) error { calls++; return nil }); err != nil || calls != 2 {
		t.Fatalf("different bytes: err %v calls %d", err, calls)
	}
}

func TestR24OnlyProofFailuresRemembered(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	for _, msg := range []string{
		"TX x rejected height(5) reference not found",
		"Incoming TX x nonce verification failed, err nonce already used",
		"Incoming TX x could not be verified, err balance not obtained err leaf not found",
		"TX x rejected by pool by mempool",
	} {
		calls := 0
		for i := 0; i < 3; i++ {
			Admit(raw, tx, func(*transaction.Transaction) error { calls++; return errors.New(msg) })
		}
		if calls != 3 {
			t.Fatalf("%q: verified %d times, want 3 (state-dependent refusals are never remembered)", msg, calls)
		}
	}
}

func TestR24KnownInvalidBoundAndTTL(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	now := time.Unix(1_000_000, 0)
	p.now = func() time.Time { return now }
	t.Cleanup(func() { p.now = time.Now })
	bad := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	for i := 0; i < NEG_MAX+10; i++ {
		tx, raw := forged(100, uint64(i), 200)
		Admit(raw, tx, func(*transaction.Transaction) error { return bad })
	}
	p.Lock()
	n := len(p.neg)
	p.Unlock()
	if n > NEG_MAX {
		t.Fatalf("negative cache holds %d entries, bound %d", n, NEG_MAX)
	}
	tx, raw := forged(100, uint64(NEG_MAX+9), 200) // the newest entry
	calls := 0
	Admit(raw, tx, func(*transaction.Transaction) error { calls++; return bad })
	if calls != 0 {
		t.Fatalf("newest entry was dropped")
	}
	now = now.Add(NEG_TTL + time.Second)
	Admit(raw, tx, func(*transaction.Transaction) error { calls++; return bad })
	if calls != 1 {
		t.Fatalf("an expired verdict must be verified again")
	}
}

// pool of n txs of size sz paying fee_i each; returns their hashes
func fill(f *fake_pool, n int, sz uint64, fee func(i int) uint64) (hs []crypto.Hash) {
	for i := 0; i < n; i++ {
		tx, _ := forged(fee(i), uint64(1000+i), 100)
		h := crypto.Keccak256([]byte(fmt.Sprintf("pool-%d", i)))
		f.put(h, tx, sz)
		hs = append(hs, h)
	}
	return
}

func TestR24PoolFullRefusesLowFeeBeforeVerification(t *testing.T) {
	f := new_fake_pool()
	fill(f, 10, 3000, func(i int) uint64 { return 80 + uint64(i) }) // 30,000 bytes, rates 80..89 per 3000 B
	attach_test(t, f, 30_000)
	calls := 0
	add := func(*transaction.Transaction) error { calls++; return nil }
	// pays exactly the lowest rate in the pool (tie): refused, never verified
	tx, raw := forged(80, 1, 3000)
	if err := Admit(raw, tx, add); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("tie with the lowest: %v, want ErrPoolFull", err)
	}
	// pays less: refused
	tx, raw = forged(79, 2, 3000)
	if err := Admit(raw, tx, add); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("lower: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a refused tx was verified %d times", calls)
	}
	if strings.Contains(fmt.Sprint(ErrPoolFull), "could not be verified") {
		t.Fatalf("ErrPoolFull must not read as a verification failure (p2p would score an honest relay)")
	}
}

func TestR24PoolFullEvictsLowestPayingForBetterTx(t *testing.T) {
	f := new_fake_pool()
	hs := fill(f, 10, 3000, func(i int) uint64 { return 80 + uint64(i) })
	attach_test(t, f, 30_000)
	tx, raw := forged(200, 1, 6000) // needs 6000 bytes: the two lowest-paying (80, 81) go
	add := func(tx *transaction.Transaction) error { f.put(forged_txid(tx), tx, 6000); return nil }
	if err := Admit(raw, tx, add); err != nil {
		t.Fatalf("better tx refused: %v", err)
	}
	if len(f.deleted) != 2 || f.deleted[0] != hs[0] && f.deleted[0] != hs[1] || f.deleted[1] != hs[0] && f.deleted[1] != hs[1] {
		t.Fatalf("evicted %v, want exactly the two lowest-paying %v %v", f.deleted, hs[0], hs[1])
	}
	if f.Mempool_Get_TX(forged_txid(tx)) == nil {
		t.Fatalf("admitted tx was evicted")
	}
	s := Snapshot()
	if s.PoolBytes > 30_000 || !s.Attached {
		t.Fatalf("pool over cap after eviction: %+v", s)
	}
}

func TestR24PoolBelowCapAdmitsAnyFee(t *testing.T) {
	f := new_fake_pool()
	fill(f, 3, 3000, func(i int) uint64 { return 1000 })
	attach_test(t, f, 30_000)
	tx, raw := forged(1, 1, 3000) // far below everyone, but the pool has room
	called := false
	if err := Admit(raw, tx, func(*transaction.Transaction) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("room in the pool: err %v called %v", err, called)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("evicted with room left: %v", f.deleted)
	}
}

func TestR24RegistrationBypassesPolicy(t *testing.T) {
	f := new_fake_pool()
	fill(f, 10, 3000, func(i int) uint64 { return 1000 })
	attach_test(t, f, 30_000) // full
	reg := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.REGISTRATION}}
	called := false
	if err := Admit(make([]byte, 101), reg, func(*transaction.Transaction) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("registration (regpool, no fee) must pass through: %v", err)
	}
}

func TestR24SummaryCachedBetweenAdmissions(t *testing.T) {
	f := new_fake_pool()
	fill(f, 5, 3000, func(i int) uint64 { return 100 })
	attach_test(t, f, 1<<30)
	for i := 0; i < 20; i++ {
		tx, raw := forged(100, uint64(i), 3000)
		Admit(raw, tx, func(*transaction.Transaction) error { return nil })
	}
	if f.lists > 2 {
		t.Fatalf("pool listed %d times for 20 admissions inside one SUMMARY_TTL", f.lists)
	}
}

func TestR24PanickingAdmissionLeavesPolicyUsable(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	func() {
		defer func() { recover() }() // the RPC / p2p callers recover like this
		Admit(raw, tx, func(*transaction.Transaction) error { panic("boom") })
	}()
	done := make(chan error, 1)
	go func() { done <- Admit(raw, tx, func(*transaction.Transaction) error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after a recovered panic: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("policy deadlocked after a panic inside an admission")
	}
}

// GetFeeEstimate's enter_fee_for_size must be exactly the gate's threshold: that fee passes, one unit less does not.
func TestR24FeeToEnterMatchesGate(t *testing.T) {
	for _, size := range []uint64{1703, 3000, 4158, 13353} {
		f := new_fake_pool()
		fill(f, 10, 3000, func(i int) uint64 { return 80 + uint64(i) })
		attach_test(t, f, 30_000)
		need := FeeToEnter(size)
		if need == 0 {
			t.Fatalf("size %d: full pool reported no entry fee", size)
		}
		tx, raw := forged(need-1, 1, int(size))
		if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); !errors.Is(err, ErrPoolFull) {
			t.Fatalf("size %d fee %d (one below FeeToEnter): %v, want ErrPoolFull", size, need-1, err)
		}
		tx, raw = forged(need, 2, int(size))
		if err := Admit(raw, tx, func(tx *transaction.Transaction) error { f.put(forged_txid(tx), tx, size); return nil }); err != nil {
			t.Fatalf("size %d fee %d (= FeeToEnter): %v", size, need, err)
		}
		Detach()
	}
	f := new_fake_pool()
	fill(f, 3, 3000, func(i int) uint64 { return 80 })
	attach_test(t, f, 30_000)
	if FeeToEnter(3000) != 0 {
		t.Fatalf("room in the pool: no entry fee")
	}
	if FeeToEnter(40_000) != math.MaxUint64 {
		t.Fatalf("larger than everything evictable: no fee is enough")
	}
}

// derod turns the policy on; without Attach every rule above is a pass-through.
func TestR24DerodAttachesPolicy(t *testing.T) {
	src, err := os.ReadFile("../../cmd/derod/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\ttxpolicy.Attach(chain.Mempool, 0)\n") {
		t.Fatalf("cmd/derod/main.go no longer attaches the r24 mempool admission policy")
	}
}

func TestR24KnownInvalidPreDecode(t *testing.T) {
	attach_test(t, new_fake_pool(), 1<<30)
	tx, raw := forged(100, 1, 3000)
	if KnownInvalid(raw) != nil {
		t.Fatalf("unknown bytes reported invalid")
	}
	bad := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	Admit(raw, tx, func(*transaction.Transaction) error { return bad })
	if err := KnownInvalid(raw); err == nil || err.Error() != bad.Error() {
		t.Fatalf("KnownInvalid after a proof failure: %v", err)
	}
	Detach()
	if KnownInvalid(raw) != nil {
		t.Fatalf("detached policy must not refuse")
	}
}

// mined txs stay pooled until HouseKeeping: they must neither fill the cap nor be evicted
func TestR24MinedTxsDoNotOccupyCap(t *testing.T) {
	f := new_fake_pool()
	hs := fill(f, 10, 3000, func(i int) uint64 { return 1000 }) // full, and all pay far more than the newcomer
	attach_test(t, f, 30_000)
	mined := map[crypto.Hash]bool{}
	for _, h := range hs {
		mined[h] = true
	}
	SetMinedSource(func() map[crypto.Hash]bool { return mined })
	tx, raw := forged(10, 1, 3000)
	if err := Admit(raw, tx, func(tx *transaction.Transaction) error { f.put(forged_txid(tx), tx, 3000); return nil }); err != nil {
		t.Fatalf("pool of mined txs refused a pending one: %v", err)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("mined txs evicted: %v", f.deleted)
	}
	if s := Snapshot(); s.PoolBytes != 3000 || s.PoolTxs != 1 {
		t.Fatalf("pending accounting %+v, want only the new tx", s)
	}
}

func TestR24DerodSetsMinedSource(t *testing.T) {
	src, err := os.ReadFile("../../cmd/derod/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\ttxpolicy.SetMinedSource(derodrpc.RecentlyMined)") {
		t.Fatalf("cmd/derod/main.go no longer tells the policy which pooled txs are mined")
	}
}
