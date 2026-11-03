// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

// r24 (txpool) tests: GetTxStatus pool detail (expiry / rebuild safety / template order), forged inputs.

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/txpolicy"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

func r24_tx(fee, height uint64) *transaction.Transaction {
	tx := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: height}}
	tx.Payloads = []transaction.AssetPayload{{}}
	tx.Payloads[0].Statement.Fees = fee
	return tx
}

func TestR24PoolStatusExpiryHeights(t *testing.T) {
	h := crypto.Hash{1}
	tx := r24_tx(120, 1000)
	order := []mempool.TX_Sorting_struct{{Hash: h, Size: 5033, FeesPerByte: 0}}
	ps := tx_pool_status(h, tx, order, 1000)
	// blockchain.go:786 (b - tx.Height < 11) and blockchain.go:481 (b >= H - 8)
	if ps.LastBlockHeight != 1010 || ps.RebuildSafeHeight != 1019 || ps.PoolPurgeHeight != 1008 {
		t.Fatalf("heights %+v, want last 1010, rebuild_safe 1019, purge 1008", ps)
	}
	for H, want := range map[int64]bool{1018: false, 1019: true} {
		// at H a block of height b is accepted iff b >= H-8; the tx fits iff b <= 1010
		includable := H-8 <= 1010
		if got := tx_pool_status(h, tx, order, H).Expired; got != want || got == includable {
			t.Fatalf("H=%d expired=%v want %v (an acceptable block exists: %v)", H, got, want, includable)
		}
	}
	if ps.FeePerKB != 120*1024/5033 || ps.FeesPerByte != 0 || ps.Fee != 120 || ps.Size != 5033 {
		t.Fatalf("fee fields %+v", ps)
	}
}

func TestR24PoolStatusTemplateOrder(t *testing.T) {
	var order []mempool.TX_Sorting_struct
	for i := 0; i < 5; i++ {
		order = append(order, mempool.TX_Sorting_struct{Hash: crypto.Hash{byte(i + 1)}, Size: BLOCK_TX_CAPACITY / 4})
	}
	for i := 0; i < 5; i++ {
		ps := tx_pool_status(order[i].Hash, r24_tx(100, 50), order, 50)
		if ps.PoolRank != i+1 || ps.BytesAhead != uint64(i)*(BLOCK_TX_CAPACITY/4) {
			t.Fatalf("tx %d: rank %d ahead %d", i, ps.PoolRank, ps.BytesAhead)
		}
		if want := i < 4; ps.NextBlock != want {
			t.Fatalf("tx %d: next_block %v, want %v (4 quarter-blocks fit)", i, ps.NextBlock, want)
		}
	}
	if tx_pool_status(crypto.Hash{9}, nil, order, 50) != nil {
		t.Fatalf("no tx, no detail")
	}
	// an expired tx is never predicted into the next block
	if ps := tx_pool_status(order[0].Hash, r24_tx(100, 50), order, 50+19); ps.NextBlock || !ps.Expired {
		t.Fatalf("expired tx: %+v", ps)
	}
}

func TestR24GetTxStatusWiresPoolDetail(t *testing.T) {
	src, err := os.ReadFile("rpc_dero_gettxstatus.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\tapply_pool_status(result.Txs, chain.Mempool, chain_height, RecentlyMined) // r24") {
		t.Fatalf("GetTxStatus no longer fills the r24 pool detail")
	}
	ps, err := os.ReadFile("tx_pool_status.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ps), "order, _ = drop_mined(pool.Mempool_List_TX_SortedInfo(), mined())") {
		t.Fatalf("the pool detail counts already-mined txs as ahead")
	}
}

func TestR24FeeEstimateCoversPoolGate(t *testing.T) {
	src, err := os.ReadFile("rpc_dero_getfeeestimate.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "if result.EnterFeeForSize = txpolicy.FeeToEnter(p.Size); result.EnterFeeForSize > result.FeeForSize {\n\t\t\tresult.FeeForSize = result.EnterFeeForSize") {
		t.Fatalf("GetFeeEstimate fee_for_size no longer covers the r24 pool-full gate")
	}
}

type r24_rpc_pool struct{}

func (r24_rpc_pool) Mempool_List_TX_SortedInfo() []mempool.TX_Sorting_struct { return nil }
func (r24_rpc_pool) Mempool_Get_TX(crypto.Hash) *transaction.Transaction     { return nil }
func (r24_rpc_pool) Mempool_Delete_TX(crypto.Hash) *transaction.Transaction  { return nil }

// Bytes whose proof already failed are refused by SendRawTransaction before they are decoded (chain is nil here:
// a decode or a pool lookup would fail differently or be a recovered panic).
func TestR24SendRawTransactionRefusesKnownInvalidBeforeDecode(t *testing.T) {
	with_send_tip(t, 1000)
	txpolicy.Attach(r24_rpc_pool{}, 0)
	defer txpolicy.Detach()
	h := fixture_tx_hex(t, byte(transaction.NORMAL), 1000)
	raw, _ := hex.DecodeString(h)
	bad := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	if err := txpolicy.Admit(raw, r24_tx(80, 1000), func(*transaction.Transaction) error { return bad }); err != bad {
		t.Fatalf("seed: %v", err)
	}
	panics := metrics.Set.GetOrCreateCounter("rpc_recovered_panics_total")
	before := panics.Get()
	for i := 0; i < 3; i++ {
		_, err := SendRawTransaction(context.Background(), rpc.SendRawTransaction_Params{Tx_as_hex: h})
		if err == nil || !strings.Contains(err.Error(), "transaction statement 0 verification failed") || panics.Get() != before {
			t.Fatalf("known-invalid replay: err %v, recovered panics +%d", err, panics.Get()-before)
		}
	}
}

func TestR24RecentMinedScanWindow(t *testing.T) {
	// topo t holds a block at height t/2 (two blocks per height) carrying tx {t}
	blid_at := func(t int64) (crypto.Hash, bool) { return crypto.Hash{byte(t), byte(t >> 8)}, t >= 0 }
	block := func(b crypto.Hash) (int64, []crypto.Hash, bool) {
		t := int64(b[0]) | int64(b[1])<<8
		return t / 2, []crypto.Hash{{0xee, byte(t), byte(t >> 8)}}, true
	}
	set := recent_mined_scan(200, blid_at, block)
	// heights 100 down to 80 (= 100 - MINED_WINDOW): topo 200..160, 41 blocks
	if len(set) != 41 {
		t.Fatalf("collected %d txs, want 41", len(set))
	}
	if !set[crypto.Hash{0xee, 160}] || set[crypto.Hash{0xee, 159}] {
		t.Fatalf("window edge wrong")
	}
	// one height per topo: bounded by MINED_TOPO_SCAN, never the whole chain
	flat := func(b crypto.Hash) (int64, []crypto.Hash, bool) {
		return 1000, []crypto.Hash{{0xee, b[0], b[1]}}, true
	}
	if n := len(recent_mined_scan(500, blid_at, flat)); n != MINED_TOPO_SCAN {
		t.Fatalf("scan read %d blocks, bound %d", n, MINED_TOPO_SCAN)
	}
}

func TestR24DropMinedKeepsOrder(t *testing.T) {
	in := []mempool.TX_Sorting_struct{{Hash: crypto.Hash{1}, Size: 100}, {Hash: crypto.Hash{2}, Size: 100}, {Hash: crypto.Hash{3}, Size: 100}, {Hash: crypto.Hash{4}, Size: 100}}
	out, n := drop_mined(in, map[crypto.Hash]bool{{2}: true, {4}: true})
	if n != 2 || len(out) != 2 || out[0].Hash != (crypto.Hash{1}) || out[1].Hash != (crypto.Hash{3}) {
		t.Fatalf("drop_mined: %v dropped %d", out, n)
	}
	// a mined tx ahead of ours no longer counts as ahead
	ps := tx_pool_status(crypto.Hash{3}, r24_tx(100, 50), out, 50)
	if ps.PoolRank != 2 {
		t.Fatalf("rank %d, want 2", ps.PoolRank)
	}
}

func TestR24FeeEstimateSkipsMined(t *testing.T) {
	src, err := os.ReadFile("rpc_dero_getfeeestimate.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "entries, mined := fee_entries(chain.Mempool, RecentlyMined())") ||
		!strings.Contains(string(src), "sorted, dropped := drop_mined(pool.Mempool_List_TX_SortedInfo(), mined)") {
		t.Fatalf("GetFeeEstimate counts already-mined pool txs again")
	}
}
