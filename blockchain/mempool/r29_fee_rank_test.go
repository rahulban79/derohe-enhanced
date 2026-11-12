// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package mempool

import (
	"encoding/hex"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// Round 29 (decisions, dero-rft §7 B19, user decision 2026-11-08 (a)): the pool sorts by fee per byte in 1/1000
// atomic units, so two txs that both rank 0 by the integer fee/size are now ordered by their fee. The integer
// FeesPerByte (what RPC callers read, TestR28FeeRankIsIntegerPerByte) is unchanged.
func TestR29PoolOrdersByMilliFeePerByte(t *testing.T) {
	raw, _ := hex.DecodeString(r28_tx_hex)
	add := func(fee uint64) (*Mempool, TX_Sorting_struct) {
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatal(err)
		}
		tx.Payloads[0].Statement.Fees = fee
		pool, err := Init_Mempool(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !pool.Mempool_Add_TX(&tx, 0) {
			t.Fatal("add refused")
		}
		return pool, pool.Mempool_List_TX_SortedInfo()[0]
	}
	_, lo := add(1000)
	_, hi := add(2000)
	if lo.Size < 2000 || lo.FeesPerByte != 0 || hi.FeesPerByte != 0 {
		t.Fatalf("premise: %d-byte tx, integer ranks %d and %d (want 0 and 0)", lo.Size, lo.FeesPerByte, hi.FeesPerByte)
	}
	if lo.MilliFeesPerByte != 1000*1000/lo.Size || hi.MilliFeesPerByte != 2000*1000/hi.Size || hi.MilliFeesPerByte <= lo.MilliFeesPerByte {
		t.Fatalf("milli ranks %d (fee 1000) and %d (fee 2000) on %d/%d bytes", lo.MilliFeesPerByte, hi.MilliFeesPerByte, lo.Size, hi.Size)
	}
	// one pool holding both: the higher fee comes first whatever order the map ranges in
	pool, _ := add(1000)
	var h1, h2 crypto.Hash
	h1[0], h2[0] = 1, 2
	// r30 (closed-loop run 7: gm-r29-dc-b19-sort-integer MISSED once): with every integer rank 0 the integer sort only
	// keeps the map's range order, which put the fee-2000 entry first in all 20 rounds by chance. The fee-1000 entry
	// carries integer rank 1, so an integer-rank sort puts it first every time and the milli-rank sort never does.
	pool.txs.Store(h1, &mempool_object{Size: lo.Size, FEEperBYTE: 1, MilliFEEperBYTE: lo.MilliFeesPerByte})
	pool.txs.Store(h2, &mempool_object{Size: hi.Size, FEEperBYTE: 0, MilliFEEperBYTE: hi.MilliFeesPerByte})
	for round := 0; round < 20; round++ {
		info := pool.Mempool_List_TX_SortedInfo()
		if len(info) != 3 || info[0].MilliFeesPerByte != hi.MilliFeesPerByte {
			t.Fatalf("round %d: order %+v, want the fee-2000 entry first", round, info)
		}
	}
	// a fee whose *1000 overflows saturates instead of wrapping to a low rank
	var big transaction.Transaction
	_ = big.Deserialize(raw)
	big.Payloads[0].Statement.Fees = ^uint64(0) / 10
	bp, _ := Init_Mempool(nil)
	if !bp.Mempool_Add_TX(&big, 0) {
		t.Fatal("add refused")
	}
	if r := bp.Mempool_List_TX_SortedInfo()[0].MilliFeesPerByte; r != ^uint64(0) {
		t.Fatalf("overflowing fee ranks %d, want saturation", r)
	}
	t.Logf("B19: fee 1000 vs 2000 on %d bytes: integer rank 0/0, milli rank %d/%d", lo.Size, lo.MilliFeesPerByte, hi.MilliFeesPerByte)
}
