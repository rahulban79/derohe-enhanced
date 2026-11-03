package rpc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/graviton"
)

// r19 merge: one implementation of the GetSupplyAudit cost control (forensics F5 + security SEC-7 + features F1);
// these tests come from all three patches, adapted to it.

func reset_supply_audit(compute func(context.Context, int64) (GetSupplyAudit_Result, error), tip func() (supply_audit_key, error)) func() {
	oc, ot := supply_audit_compute, supply_audit_tip
	supply_audit_compute, supply_audit_tip = compute, tip
	supply_audit_cache.valid = false
	return func() { supply_audit_compute, supply_audit_tip = oc, ot; supply_audit_cache.valid = false }
}

func fixed_tip(topo int64, b byte) func() (supply_audit_key, error) {
	return func() (supply_audit_key, error) { return supply_audit_key{topo: topo, blid: crypto.Hash{b}}, nil }
}

// live 2026-10-24: one audit = 50,425 SC trees, 23 s cold. Concurrent callers must share one walk (forensics F5,
// features F1).
func TestSupplyAuditSingleFlightAndCache(t *testing.T) {
	var calls, running, overlap, cached int32
	defer reset_supply_audit(func(ctx context.Context, topo int64) (GetSupplyAudit_Result, error) {
		if atomic.AddInt32(&running, 1) > 1 {
			atomic.StoreInt32(&overlap, 1)
		}
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		return GetSupplyAudit_Result{Height: 7806180, TopoHeight: topo, Status: "OK", Top: []SupplyAudit_SC{{SCID: "aa", Balance: 1}}}, nil
	}, fixed_tip(7806180, 1))()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := GetSupplyAudit(context.Background())
			if err != nil || r.Height != 7806180 {
				t.Errorf("r=%+v err=%v", r, err)
				return
			}
			if r.Cached {
				atomic.AddInt32(&cached, 1)
			}
			r.Top[0].Balance = 99 // callers must not be able to corrupt the cached copy
		}()
	}
	wg.Wait()
	if overlap != 0 {
		t.Fatal("two audits walked the SC trees at the same time")
	}
	if calls != 1 || cached != 31 {
		t.Fatalf("32 callers at one tip ran %d audits (%d cached answers), want 1 and 31", calls, cached)
	}
	if r, _ := GetSupplyAudit(context.Background()); r.Top[0].Balance != 1 {
		t.Fatal("cached top list was mutated through a returned slice")
	}
}

// keyed by (topoheight, block id): a new topoheight, or a different block at the same topoheight after a rewind,
// walks again (verifier SEC-7)
func TestSupplyAuditCachedPerTopo(t *testing.T) {
	var walks int32
	compute := func(ctx context.Context, topo int64) (GetSupplyAudit_Result, error) {
		atomic.AddInt32(&walks, 1)
		return GetSupplyAudit_Result{TopoHeight: topo, Top: []SupplyAudit_SC{{SCID: "a", Balance: 1}}}, nil
	}
	defer reset_supply_audit(compute, fixed_tip(100, 1))()
	k := func(topo int64, b byte) supply_audit_key { return supply_audit_key{topo: topo, blid: crypto.Hash{b}} }
	ctx := context.Background()
	supply_audit_for(ctx, k(100, 1), compute)
	if r, _ := supply_audit_for(ctx, k(100, 1), compute); !r.Cached || walks != 1 {
		t.Fatalf("same tip recomputed: walks=%d", walks)
	}
	if r, _ := supply_audit_for(ctx, k(101, 1), compute); r.TopoHeight != 101 || r.Cached || walks != 2 {
		t.Fatalf("a new topoheight must recompute: walks=%d topo=%d", walks, r.TopoHeight)
	}
	if r, _ := supply_audit_for(ctx, k(101, 2), compute); r.Cached || walks != 3 {
		t.Fatalf("a different block at the same topoheight (rewind/reorg) served the old audit: walks=%d", walks)
	}
	if r, _ := supply_audit_for(ctx, k(100, 1), compute); r.Cached || walks != 4 {
		t.Fatalf("a rewind to an earlier tip served a newer audit: walks=%d", walks)
	}
}

func TestSupplyAuditFailureNotCached(t *testing.T) {
	var calls int32
	defer reset_supply_audit(func(ctx context.Context, topo int64) (GetSupplyAudit_Result, error) {
		atomic.AddInt32(&calls, 1)
		return GetSupplyAudit_Result{}, errors.New("walk failed")
	}, fixed_tip(5, 1))()
	GetSupplyAudit(context.Background())
	GetSupplyAudit(nil)
	if calls != 2 {
		t.Fatalf("a failed audit was cached (calls=%d)", calls)
	}
}

// a waiter whose context ends gives up instead of queueing behind a long walk (forensics F5 note, features F1)
func TestSupplyAuditWaiterHonoursContext(t *testing.T) {
	release := make(chan struct{})
	defer reset_supply_audit(func(ctx context.Context, topo int64) (GetSupplyAudit_Result, error) {
		<-release
		return GetSupplyAudit_Result{TopoHeight: topo}, nil
	}, fixed_tip(9, 1))()
	done := make(chan struct{})
	go func() { GetSupplyAudit(context.Background()); close(done) }()
	time.Sleep(10 * time.Millisecond) // the first caller holds the walk
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if _, err := GetSupplyAudit(ctx); err == nil || time.Since(t0) > time.Second {
		t.Fatalf("waiter with an expired context: err %v after %s", err, time.Since(t0))
	}
	close(release)
	<-done
}

func TestAuditSCBalancesStopsOnCancel(t *testing.T) {
	store, _ := graviton.NewMemStore()
	ss, _ := store.LoadSnapshot(0)
	meta, _ := ss.GetTree(config.SC_META)
	var scid [32]byte
	scid[0] = 1
	meta.Put(scid[:], []byte{1})
	if _, err := graviton.Commit(meta); err != nil {
		t.Fatal(err)
	}
	ss, _ = store.LoadSnapshot(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := audit_sc_balances_ctx(ctx, ss, 10); err == nil {
		t.Fatal("cancelled audit kept walking")
	}
}
