// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package txprecheck

import (
	"errors"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

func decode(raw []byte) (tx transaction.Transaction, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic")
		}
	}()
	err = tx.Deserialize(raw)
	return
}

func with_type(raw []byte, typ byte) []byte {
	b := append([]byte(nil), raw...)
	b[3] = typ // version, source, dest are one byte each in synth
	return b
}

// the header peek reads the same height Deserialize does, for every type that has one
func TestR23bPeekHeightMatchesDeserialize(t *testing.T) {
	for i := 0; i < 3; i++ {
		raw := (&synth{}).bytes()
		h, has, err := PeekHeight(raw)
		if err != nil || !has || h != fresh(t).Height || h != 1000 {
			t.Fatalf("peek %d %v %v, Deserialize height %d", h, has, err, fresh(t).Height)
		}
		burn := with_type(raw, byte(transaction.BURN_TX))
		if h, has, err = PeekHeight(burn); err != nil || !has || h != 1000 {
			t.Fatalf("burn: peek %d %v %v", h, has, err)
		}
		reg := (&transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.REGISTRATION}}).Serialize()
		if _, has, err = PeekHeight(reg); err != nil || has {
			t.Fatalf("registration carries no height: %v %v", has, err)
		}
		sc := &transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.SC_TX, Value: 300, Height: 4242}}
		if h, has, err = PeekHeight(sc.Serialize()); err != nil || !has || h != 4242 {
			t.Fatalf("SC tx (gas varint before the height): peek %d %v %v", h, has, err)
		}
	}
}

// a header the peek refuses is one Deserialize refuses (or panics on): the peek never refuses a decodable tx
func TestR23bPeekHeaderRefusalIsDeserializeRefusal(t *testing.T) {
	raw := (&synth{}).bytes()
	cases := map[string][]byte{
		"empty":        {},
		"version 2":    append([]byte{2}, raw[1:]...),
		"unknown type": with_type(raw, 9),
		"cut height":   raw[:4],
		"bad varint":   append(raw[:4:4], 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
	}
	for name, b := range cases {
		if _, _, err := PeekHeight(b); !errors.Is(err, ErrHeader) {
			t.Fatalf("%s: peek %v, want ErrHeader", name, err)
		}
		if _, err := decode(b); err == nil {
			t.Fatalf("%s: Deserialize accepted what the peek refused", name)
		}
	}
}

// the window bounds against blockchain.TX_VALIDITY_HEIGHT, and why a refused height can never be mined on our tip
func TestR23bWindowBounds(t *testing.T) {
	const tip = int64(7834113)
	v := uint64(blockchain.TX_VALIDITY_HEIGHT)
	if v != 11 {
		t.Fatalf("TX_VALIDITY_HEIGHT %d: re-derive the bounds below", v)
	}
	for i := 0; i < 3; i++ {
		if err := Window(uint64(tip)-v, tip); err != nil {
			t.Fatalf("tip-%d (the upstream p2p bound) refused: %v", v, err)
		}
		if err := Window(uint64(tip), tip); err != nil {
			t.Fatalf("a tx at the tip refused: %v", err)
		}
		if err := Window(uint64(tip)-v-1, tip); !errors.Is(err, ErrWindow) {
			t.Fatalf("tip-%d accepted: %v", v+1, err)
		}
		if err := Window(uint64(tip)+1, tip); !errors.Is(err, ErrWindow) {
			t.Fatalf("a height past our tip accepted: %v", err)
		}
		if err := Window(5, 0); !errors.Is(err, ErrWindow) {
			t.Fatalf("empty chain: a height past topoheight 0 accepted: %v", err)
		}
	}
	// consensus arithmetic: every refused-old height is outside the window of the lowest block that extends our tip
	for h := uint64(tip) - v - 50; h <= uint64(tip); h++ {
		refused := Window(h, tip) != nil
		next_block_rejects := (tip+1)-int64(h) >= blockchain.TX_VALIDITY_HEIGHT // blockchain.go:786
		if refused && h <= uint64(tip) && !next_block_rejects {
			t.Fatalf("height %d refused but a block at tip+1 could hold it", h)
		}
	}
}

// every one of the 75 grandfathered TXIDs is refused by TXID; other ids pass; the order is window, HF3, structure
func TestR23bHF3TableRefusedByTXID(t *testing.T) {
	n := 0
	for k := range blockchain.HF3_Affected_Txs {
		h := crypto.HashHexToHash(k)
		if h.String() != k {
			t.Fatalf("table key %s does not round-trip", k)
		}
		if err := HF3(h); !errors.Is(err, ErrHF3) {
			t.Fatalf("table txid %s not refused: %v", k, err)
		}
		n++
	}
	if n != 75 {
		t.Fatalf("%d table entries, want 75", n)
	}
	if err := HF3(crypto.Hash{0x42}); err != nil {
		t.Fatalf("an ordinary txid refused: %v", err)
	}

	tx := fresh(t)
	added := 0
	add := func(*transaction.Transaction) error { added++; return nil }
	if err := AdmitAt(tx, tx.GetHash(), 1000+12, add); !errors.Is(err, ErrWindow) || added != 0 {
		t.Fatalf("out-of-window tx: err %v added %d", err, added)
	}
	key := tx.GetHash().String()
	blockchain.HF3_Affected_Txs[key] = &blockchain.HF3_Tx_Data{Height: tx.Height}
	err := AdmitAt(tx, tx.GetHash(), 1000, add)
	delete(blockchain.HF3_Affected_Txs, key)
	if !errors.Is(err, ErrHF3) || added != 0 {
		t.Fatalf("HF3-table tx: err %v added %d", err, added)
	}
	if err := AdmitAt(tx, tx.GetHash(), 1000, add); err != nil || added != 1 {
		t.Fatalf("in-window well-formed tx: err %v added %d", err, added)
	}
	if errors.Is(ErrWindow, ErrStructure) || errors.Is(ErrHF3, ErrStructure) {
		t.Fatal("window/HF3 refusals must not be scored as structural (an honest relay can be late)")
	}
}

func FuzzR23bPeekHeight(f *testing.F) {
	raw := (&synth{}).bytes()
	f.Add(raw)
	f.Add(with_type(raw, byte(transaction.SC_TX)))
	f.Add(with_type(raw, 9))
	f.Add((&transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.COINBASE}}).Serialize())
	f.Fuzz(func(t *testing.T, b []byte) {
		h, has, err := PeekHeight(b)
		tx, derr := decode(b)
		if derr == nil && err != nil {
			t.Fatalf("peek refused a decodable tx: %v", err)
		}
		if derr == nil && has && h != tx.Height {
			t.Fatalf("peek height %d, Deserialize %d", h, tx.Height)
		}
	})
}

func BenchmarkR23bPeekWindow(b *testing.B) {
	raw := (&synth{}).bytes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if PeekWindow(raw, 1000) != nil {
			b.Fatal("refused")
		}
	}
}

func BenchmarkR23bDeserialize(b *testing.B) {
	raw := (&synth{}).bytes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var tx transaction.Transaction
		if tx.Deserialize(raw) != nil {
			b.Fatal("decode")
		}
	}
}

func BenchmarkR23bAdmitAtPolicy(b *testing.B) {
	tx := fresh(b)
	txid := tx.GetHash()
	add := func(*transaction.Transaction) error { return nil }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if AdmitAt(tx, txid, 1000, add) != nil {
			b.Fatal("refused")
		}
	}
}

// the r23b increment of AdmitAt over Admit: Window + HF3 (a map lookup of the txid the caller already has)
func BenchmarkR23bWindowHF3Only(b *testing.B) {
	tx := fresh(b)
	txid := tx.GetHash()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if Window(tx.Height, 1000) != nil || HF3(txid) != nil {
			b.Fatal("refused")
		}
	}
}

func BenchmarkR23bGetHash(b *testing.B) {
	tx := fresh(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = tx.GetHash()
	}
}

func BenchmarkR23bCheckOnly(b *testing.B) {
	tx := fresh(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if Check(tx) != nil {
			b.Fatal("refused")
		}
	}
}
