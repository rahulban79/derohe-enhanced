// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package txprecheck

// r28 (glue-global, decoder fuzz): the package's own claim is that it "can never keep a valid transaction out of the
// mempool". Pinned on real data: the 14 mined mainnet transactions of glue/txcanon/testdata (R25) all pass Check.
// FuzzR28PrecheckDecodedNoPanic seeds the engine with them; for any bytes the decoder accepts, Check must not panic
// and whatever it admits satisfies the structural rules restated independently below. TestR28PrecheckByteSweep is
// its deterministic complement (every byte of one mainnet tx, 3 values each).

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

func r28_mainnet_txs(t testing.TB) (raws [][]byte) {
	f, err := os.Open("../txcanon/testdata/r25_mainnet_txs.hex")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		b, err := hex.DecodeString(sc.Text())
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, b)
	}
	return
}

func r28_decode(raw []byte) (tx *transaction.Transaction, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decoder panic: %v", r)
		}
	}()
	tx = &transaction.Transaction{}
	err = tx.Deserialize(raw)
	return
}

// r28_admitted_property: an admitted transfer obeys the structural rules (an independent restatement of Check).
func r28_admitted_property(t *testing.T, tx *transaction.Transaction) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Check panicked: %v", r)
		}
	}()
	if Check(tx) != nil {
		return
	}
	switch tx.TransactionType {
	case transaction.NORMAL, transaction.SC_TX, transaction.BURN_TX:
	default:
		return
	}
	base := false
	for i := range tx.Payloads {
		st := &tx.Payloads[i].Statement
		base = base || tx.Payloads[i].SCID.IsZero()
		n := int(st.RingSize)
		if n < 2 || n > 128 || !crypto.IsPowerOf2(n) || st.D == nil || len(st.C) < n || tx.Payloads[i].Proof == nil ||
			int(st.Bytes_per_publickey)*n != len(st.Publickeylist_pointers) || st.Roothash != tx.Payloads[0].Statement.Roothash {
			t.Fatalf("admitted payload %d: ring %d, %d pointer bytes of %d", i, n, len(st.Publickeylist_pointers), st.Bytes_per_publickey)
		}
	}
	if tx.Version != 1 || len(tx.Payloads) == 0 || !base || (tx.TransactionType == transaction.BURN_TX && tx.Value == 0) {
		t.Fatalf("admitted tx: version %d, %d payloads, base %v, type %d value %d", tx.Version, len(tx.Payloads), base,
			tx.TransactionType, tx.Value)
	}
}

func TestR28PrecheckAdmitsEveryMainnetTx(t *testing.T) {
	raws := r28_mainnet_txs(t)
	if len(raws) != 14 {
		t.Fatalf("%d mainnet txs in the corpus, want 14", len(raws))
	}
	for i, raw := range raws {
		tx, err := r28_decode(raw)
		if err != nil {
			t.Fatalf("mainnet tx %d does not decode: %v", i, err)
		}
		if err := Check(tx); err != nil {
			t.Fatalf("mainnet tx %d (%s, mined) refused: %v", i, tx.GetHash(), err)
		}
		r28_admitted_property(t, tx)
	}
}

func FuzzR28PrecheckDecodedNoPanic(f *testing.F) {
	for _, raw := range r28_mainnet_txs(f) {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if tx, err := r28_decode(raw); err == nil {
			r28_admitted_property(t, tx)
		}
	})
}

func TestR28PrecheckByteSweep(t *testing.T) {
	raw := r28_mainnet_txs(t)[0]
	decoded, admitted := 0, 0
	for i := range raw {
		for _, v := range []byte{0x00, 0x01, 0xff} {
			if raw[i] == v {
				continue
			}
			m := append([]byte(nil), raw...)
			m[i] = v
			tx, err := r28_decode(m)
			if err != nil {
				continue
			}
			decoded++
			r28_admitted_property(t, tx)
			if Check(tx) == nil {
				admitted++
			}
		}
	}
	t.Logf("byte sweep over %d bytes: %d mutants decode, %d admitted by Check (each satisfying the restated rules)", len(raw), decoded, admitted)
}
