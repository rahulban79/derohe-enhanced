package rpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/cryptography/crypto"
)

type fake_tx_src struct {
	valid             map[crypto.Hash]crypto.Hash
	topo              map[crypto.Hash]int64
	stores, mem, regs map[crypto.Hash]bool
}

func (f fake_tx_src) valid_block(h crypto.Hash) (crypto.Hash, bool) {
	b, ok := f.valid[h]
	return b, ok
}
func (f fake_tx_src) topo_of(b crypto.Hash) int64   { return f.topo[b] }
func (f fake_tx_src) stored(h crypto.Hash) bool     { return f.stores[h] }
func (f fake_tx_src) in_mempool(h crypto.Hash) bool { return f.mem[h] }
func (f fake_tx_src) in_regpool(h crypto.Hash) bool { return f.regs[h] }

func hh(b byte) crypto.Hash { var h crypto.Hash; h[0] = b; h[31] = b; return h }

// TestTxStatusClassification: mined (with confirmations), pool, regpool, orphaned, unknown and malformed ids.
func TestTxStatusClassification(t *testing.T) {
	blk := hh(0xb1)
	f := fake_tx_src{
		valid:  map[crypto.Hash]crypto.Hash{hh(1): blk},
		topo:   map[crypto.Hash]int64{blk: 95},
		stores: map[crypto.Hash]bool{hh(1): true, hh(4): true},
		mem:    map[crypto.Hash]bool{hh(2): true, hh(4): true},
		regs:   map[crypto.Hash]bool{hh(3): true},
	}
	cases := map[string]string{hh(1).String(): "mined", hh(2).String(): "pool", hh(3).String(): "regpool",
		hh(5).String(): "unknown", "zz": "invalid_txid", strings.Repeat("0", 64): "invalid_txid", hh(4).String(): "pool"}
	for id, want := range cases {
		if got := tx_status(id, 100, f); got.State != want {
			t.Fatalf("%s: state %q want %q", id, got.State, want)
		}
	}
	f.mem = nil
	if got := tx_status(hh(4).String(), 100, f); got.State != "orphaned" || got.Confirmations != 0 || got.TopoHeight != -1 {
		t.Fatalf("stored tx in no valid block and no pool: %+v", got)
	}
	// r20 merge (RW-07 review): a valid block without a topological position is not "mined" at topoheight -1
	f.valid[hh(6)], f.topo[hh(0xb6)] = hh(0xb6), -1
	if u := tx_status(hh(6).String(), 100, f); u.State != "unconfirmed" || u.TopoHeight != -1 || u.Confirmations != 0 || u.BlockHash != hh(0xb6).String() {
		t.Fatalf("block without topo order: %+v", u)
	}
	m := tx_status(" "+hh(1).String()+" ", 100, f)
	if m.State != "mined" || m.TopoHeight != 95 || m.Confirmations != 6 || m.BlockHash != blk.String() {
		t.Fatalf("mined: %+v", m)
	}
}

// TestTxStatusLimits: 0 or more than MAX_TX_STATUS ids is an error; a large call needs a range slot, a small one
// does not queue behind range calls.
func TestTxStatusLimits(t *testing.T) {
	ctx := context.Background()
	if _, err := GetTxStatus(ctx, GetTxStatus_Params{}); err == nil {
		t.Fatal("empty txids accepted")
	}
	big := make([]string, MAX_TX_STATUS+1)
	if _, err := GetTxStatus(ctx, GetTxStatus_Params{TxIDs: big}); err == nil || !strings.Contains(err.Error(), "1..64") {
		t.Fatalf("over-limit call not refused: %v", err)
	}
	for i := 0; i < RANGE_CONCURRENCY; i++ {
		range_slots <- struct{}{}
	}
	defer func() {
		for i := 0; i < RANGE_CONCURRENCY; i++ {
			<-range_slots
		}
	}()
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := GetTxStatus(short, GetTxStatus_Params{TxIDs: make([]string, TX_STATUS_FREE+1)}); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("a large call must wait for a range slot: %v", err)
	}
	if _, err := GetTxStatus(short, GetTxStatus_Params{TxIDs: make([]string, TX_STATUS_FREE)}); err != nil && strings.Contains(err.Error(), "busy") {
		t.Fatalf("a small call must not queue for a range slot: %v", err)
	}
}

type counting_tx_src struct {
	fake_tx_src
	lookups *int
}

func (c counting_tx_src) valid_block(h crypto.Hash) (crypto.Hash, bool) {
	*c.lookups++
	return c.fake_tx_src.valid_block(h)
}

// r21: repeated txids in one call are looked up once (a mined txid costs a tx decode plus ~22 heights of block loads).
func TestTxStatusesDedupesRepeats(t *testing.T) {
	blk := hh(0xb1)
	n := 0
	src := counting_tx_src{fake_tx_src{valid: map[crypto.Hash]crypto.Hash{hh(0xab): blk}, topo: map[crypto.Hash]int64{blk: 95}}, &n}
	ids := make([]string, MAX_TX_STATUS)
	for i := range ids {
		ids[i] = hh(0xab).String() // hex letters, so the upper-case variants differ
		if i%2 == 1 {
			ids[i] = " " + ids[i] // the same id with blanks is the same id
		}
		if i%3 == 2 {
			ids[i] = strings.ToUpper(ids[i]) // and in upper-case hex (r21 merge)
		}
	}
	ids[7] = hh(2).String()
	out, err := tx_statuses(context.Background(), ids, 100, src)
	if err != nil || len(out) != len(ids) {
		t.Fatalf("got %d answers, err %v", len(out), err)
	}
	if n != 2 {
		t.Fatalf("%d chain lookups for 2 distinct txids", n)
	}
	for i, s := range out {
		want := "mined"
		if i == 7 {
			want = "unknown"
		}
		if s.State != want {
			t.Fatalf("answer %d: %+v, want %s (order must follow the request)", i, s, want)
		}
		if s.TxID != strings.TrimSpace(ids[i]) {
			t.Fatalf("answer %d carries txid %q, asked %q", i, s.TxID, ids[i])
		}
	}
}

// r21 (R-6): cross-site callers together hold at most FOREIGN_RANGE_CONCURRENCY range slots, so a web page can no
// longer occupy every node-wide slot; local callers still get the rest, and a refused foreign wait frees its claim.
func TestForeignRangeSlotsLeaveRoomForLocal(t *testing.T) {
	ctx := context.Background()
	short := func() context.Context {
		c, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		t.Cleanup(cancel)
		return c
	}
	r1, err := acquire_range_slot_as(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquire_range_slot_as(short(), true); err == nil || !strings.Contains(err.Error(), "cross-site") {
		t.Fatalf("a second foreign range call got a slot: %v", err)
	}
	r2, err := acquire_range_slot_as(short(), false)
	if err != nil {
		t.Fatalf("a local caller was starved by one foreign page: %v", err)
	}
	r2()
	r1()
	if len(range_slots) != 0 || len(foreign_range_slots) != 0 {
		t.Fatalf("slots leaked: node %d foreign %d", len(range_slots), len(foreign_range_slots))
	}
	for i := 0; i < RANGE_CONCURRENCY; i++ { // node-wide full: a foreign waiter that gives up must release its claim
		range_slots <- struct{}{}
	}
	if _, err := acquire_range_slot_as(short(), true); err == nil {
		t.Fatal("got a slot while all were held")
	}
	for i := 0; i < RANGE_CONCURRENCY; i++ {
		<-range_slots
	}
	if len(foreign_range_slots) != 0 {
		t.Fatal("a foreign caller that timed out kept its foreign slot")
	}
}

// FuzzTxStatuses: any id list (as decoded from JSON) is answered one-for-one, in order, without panicking; a repeated
// id gets the same answer as its first copy.
func FuzzTxStatuses(f *testing.F) {
	f.Add(hh(1).String(), " "+hh(1).String(), "zz")
	f.Add(strings.Repeat("0", 64), "", strings.Repeat("g", 64))
	blk := hh(0xb1)
	src := fake_tx_src{valid: map[crypto.Hash]crypto.Hash{hh(1): blk}, topo: map[crypto.Hash]int64{blk: 95},
		mem: map[crypto.Hash]bool{hh(2): true}}
	f.Fuzz(func(t *testing.T, a, b, c string) {
		ids := []string{a, b, c, a}
		out, err := tx_statuses(context.Background(), ids, 100, src)
		if err != nil || len(out) != len(ids) {
			t.Fatalf("%d answers for %d ids (err %v)", len(out), len(ids), err)
		}
		if out[3] != out[0] {
			t.Fatalf("repeat answered differently: %+v vs %+v", out[3], out[0])
		}
		for _, s := range out {
			if s.State == "" || (s.State != "mined" && s.Confirmations != 0) {
				t.Fatalf("bad answer %+v", s)
			}
		}
	})
}
