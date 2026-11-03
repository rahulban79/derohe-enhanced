// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/walletapi/mnemonics"
)

// A checksum-valid 25-word seed can encode 0 or the group order; both give the identity public key.
func TestR23ZeroSeedRefused(t *testing.T) {
	for _, k := range []*big.Int{big.NewInt(0), new(big.Int).Set(bn256.Order)} {
		words := mnemonics.Key_To_Words(k, "English")
		if _, seed, err := mnemonics.Words_To_Key(words); err != nil || seed.Cmp(k) != 0 {
			t.Fatalf("premise: %x does not round-trip through words (%v)", k, err)
		}
		if acc, err := Generate_Account_From_Recovery_Words(words); err == nil {
			t.Fatalf("seed %x accepted, public key %s", k, acc.Keys.Public.G1().String())
		}
		if _, err := Generate_Account_From_Seed(crypto.GetBNRed(k)); err == nil {
			t.Fatalf("Generate_Account_From_Seed accepted %x", k)
		}
	}
	good := crypto.RandomScalar()
	acc, err := Generate_Account_From_Recovery_Words(mnemonics.Key_To_Words(good, "English"))
	if err != nil || acc.Keys.Secret.BigInt().Cmp(good) != 0 {
		t.Fatalf("a normal seed was refused or changed: %v", err)
	}
	// a seed >= order that is not 0 mod order is kept unreduced (v2 payload keys depend on its bytes)
	big1 := new(big.Int).Add(bn256.Order, big.NewInt(1))
	if acc, err := Generate_Account_From_Recovery_Words(mnemonics.Key_To_Words(big1, "English")); err != nil || acc.Keys.Secret.BigInt().Cmp(big1) != 0 {
		t.Fatalf("order+1 seed refused or reduced: %v", err)
	}
}
