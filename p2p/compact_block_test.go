package p2p

import (
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

func reg_tx(n byte) *transaction.Transaction {
	tx := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.REGISTRATION}}
	tx.MinerAddress[0], tx.C[0] = n, n
	return tx
}

func TestCompactBlockTxsKeepsHashOrder(t *testing.T) {
	pool := map[crypto.Hash]*transaction.Transaction{}
	var hashes []crypto.Hash
	for _, n := range []byte{9, 3, 7, 1} {
		tx := reg_tx(n)
		pool[tx.GetHash()] = tx
		hashes = append(hashes, tx.GetHash())
	}
	lookup := func(h crypto.Hash) *transaction.Transaction { return pool[h] }
	txs, ok := compact_block_txs(hashes, lookup)
	if !ok || len(txs) != len(hashes) {
		t.Fatalf("all txs are pooled: ok=%v n=%d", ok, len(txs))
	}
	for i := range txs {
		if txs[i].GetHash() != hashes[i] { // Add_Complete_Block stores Txs[i] under Tx_hashes[i]
			t.Fatalf("slot %d holds %s, want %s", i, txs[i].GetHash(), hashes[i])
		}
		if txs[i] == pool[hashes[i]] {
			t.Fatalf("slot %d shares the mempool's *Transaction", i)
		}
	}
	missing := append(append([]crypto.Hash{}, hashes...), crypto.Hash{0xee})
	if _, ok := compact_block_txs(missing, lookup); ok {
		t.Fatal("a tx missing from the pools must abort the reconstruction")
	}
	wrong := func(h crypto.Hash) *transaction.Transaction { return reg_tx(42) } // pool answers with another tx
	if _, ok := compact_block_txs(hashes, wrong); ok {
		t.Fatal("a pool entry that does not hash to its slot must abort the reconstruction")
	}
	if _, ok := compact_block_txs(nil, lookup); ok {
		t.Fatal("a block without txs is complete on its first chunk; no reconstruction")
	}
}

func TestTryCompactOnceAndOnlyOnSuccess(t *testing.T) {
	bl := &block.Block{Tx_hashes: []crypto.Hash{{1}}}
	ok_txs := func() ([]*transaction.Transaction, [][]byte, bool) {
		return []*transaction.Transaction{reg_tx(1)}, [][]byte{reg_tx(1).Serialize()}, true
	}
	adds := 0
	add := func(ok bool) func([]*transaction.Transaction, [][]byte) bool {
		return func([]*transaction.Transaction, [][]byte) bool { adds++; return ok }
	}

	st := &Chunks_Per_Block_Data{bl: bl}
	if try_compact(st, 1, 16, ok_txs, add(false)) || st.Processed {
		t.Fatal("a refused block must not be marked processed (the chunk path continues)")
	}
	if try_compact(st, 2, 16, ok_txs, add(true)) || adds != 1 {
		t.Fatalf("reconstruction must be tried once per block, adds=%d", adds)
	}

	st = &Chunks_Per_Block_Data{bl: bl}
	if !try_compact(st, 1, 16, ok_txs, add(true)) || !st.Processed {
		t.Fatal("an accepted block must be marked processed")
	}

	st = &Chunks_Per_Block_Data{bl: bl}
	if try_compact(st, 1, 16, func() ([]*transaction.Transaction, [][]byte, bool) { return nil, nil, false }, add(true)) || st.Processed {
		t.Fatal("missing txs: wait for chunks")
	}

	st = &Chunks_Per_Block_Data{bl: bl}
	adds = 0
	if try_compact(st, 16, 16, ok_txs, add(true)) || adds != 0 {
		t.Fatal("with enough chunks the normal reconstruction runs; no compact attempt")
	}

	st = &Chunks_Per_Block_Data{bl: &block.Block{}}
	if try_compact(st, 1, 16, ok_txs, add(true)) || adds != 0 {
		t.Fatal("a block without txs never needs the compact path")
	}

	COMPACT_BLOCKS = false
	defer func() { COMPACT_BLOCKS = true }()
	st = &Chunks_Per_Block_Data{bl: bl}
	if try_compact(st, 1, 16, ok_txs, add(true)) || adds != 0 {
		t.Fatal("DERO_COMPACT_BLOCKS=0 must disable the path")
	}
}
