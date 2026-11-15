// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

// r31 dimension 2 (wallet fuzz-coverage, DF-fuzz-coverage-88d4d62a00 and -e2b6c41fec): DecodeEncryptedBalanceNow and
// DecodeEncryptedBalance_Memory were reached by no Go fuzz target. The target encrypts a fuzzed amount under a fuzzed
// blinding scalar for this wallet and decodes it back. Amounts stay below 2^22 atomic units: Lookup searches upward
// without a ceiling, so a ciphertext of a huge (or not small) value would make the decoder search for a very long
// time (booked as a fix-later row, dero-rft §7 by the R31 dimension-2 report, not exercised here).

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

const r31_decode_limit = 1 << 22

func r31_elgamal(pub *bn256.G1, v uint64, r *big.Int) *crypto.ElGamal {
	left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(v)), new(bn256.G1).ScalarMult(pub, r))
	return crypto.ConstructElGamal(left, new(bn256.G1).ScalarMult(crypto.G, r))
}

// FuzzR31DecodeEncryptedBalance: both decoders return the encrypted amount, also for two amounts under the same
// blinding scalar (equal Right halves) decoded one after the other through the per-wallet memo.
func FuzzR31DecodeEncryptedBalance(f *testing.F) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("QWER", r19_seed)
	if err != nil {
		f.Fatal(err)
	}
	pub := w.account.Keys.Public.G1()
	f.Add(uint64(0), uint64(1), []byte{3})
	f.Add(uint64(777777), uint64(777778), []byte{3})
	f.Add(uint64(1), uint64(0), []byte{0xff, 0xee, 0x01})
	f.Add(uint64(r31_decode_limit-1), uint64(65536), []byte{})
	f.Fuzz(func(t *testing.T, v1, v2 uint64, rb []byte) {
		v1, v2 = v1%r31_decode_limit, v2%r31_decode_limit
		r := new(big.Int).Mod(new(big.Int).SetBytes(rb), bn256.Order)
		if r.Sign() == 0 {
			r.SetInt64(1)
		}
		e1, e2 := r31_elgamal(pub, v1, r), r31_elgamal(pub, v2, r)
		if got := w.DecodeEncryptedBalance_Memory(e1, 0); got != v1 {
			t.Fatalf("Memory decoded %d, want %d", got, v1)
		}
		if got := w.DecodeEncryptedBalanceNow(e2); got != v2 {
			t.Fatalf("Now decoded %d, want %d (after %d under the same blinding)", got, v2, v1)
		}
		if got := w.DecodeEncryptedBalanceNow(e1); got != v1 {
			t.Fatalf("Now re-decoded %d, want %d", got, v1)
		}
	})
}
