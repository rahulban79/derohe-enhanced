// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// r23b_registration signs a registration for secret x exactly as walletapi.sign does (Schnorr over the decoded
// point's String and R's String), with key bytes enc.
func r23b_registration(x *big.Int, enc []byte) *transaction.Transaction {
	u := new(bn256.G1).ScalarMult(crypto.G, x)
	k := crypto.RandomScalar()
	r := new(bn256.G1).ScalarMult(crypto.G, k)
	c := crypto.ReducedHash([]byte(fmt.Sprintf("%s%s", u.String(), r.String())))
	s := new(big.Int).Mod(new(big.Int).Add(k, new(big.Int).Mul(c, x)), bn256.Order)
	var tx transaction.Transaction
	tx.Version = 1
	tx.TransactionType = transaction.REGISTRATION
	copy(tx.MinerAddress[:], enc)
	crypto.FillBytes(c, tx.C[:])
	crypto.FillBytes(s, tx.S[:])
	return &tx
}

// an alias flag byte of x's canonical encoding that decodes to the same point (r22: all 254 aliases decode to the
// root ModSqrt returns, which is the key itself for about half of all keys)
func r23b_alias(t *testing.T) (*big.Int, []byte, []byte) {
	for i := int64(2); i < 200; i++ {
		x := big.NewInt(i * 7919)
		u := new(bn256.G1).ScalarMult(crypto.G, x)
		canon := u.EncodeCompressed()
		alias := append([]byte{}, canon...)
		alias[32] = 0x05 // the flag is the LAST byte; only 0x00/0x01 are defined
		var back bn256.G1
		if back.DecodeCompressed(alias) == nil && bytes.Equal(back.EncodeCompressed(), canon) {
			return x, canon, alias
		}
	}
	t.Fatal("no key whose alias decodes to itself in 198 tries (p = 1/2 each)")
	return nil, nil, nil
}

func r23b_check(tx *transaction.Transaction) error {
	_, err := Check(tx.Serialize(), tx)
	return err
}

// Consensus (IsRegistrationValid) accepts the alias-keyed and the S+Order registrations; the relay policy admits only
// the canonical one. The honest registration must keep passing (no false refusal).
func TestR23bRegistrationCanonical(t *testing.T) {
	x, canon, alias := r23b_alias(t)

	good := r23b_registration(x, canon)
	if !good.IsRegistrationValid() {
		t.Fatal("canonical registration does not verify")
	}
	if err := r23b_check(good); err != nil {
		t.Fatalf("canonical registration refused: %v", err)
	}

	al := r23b_registration(x, alias)
	if !al.IsRegistrationValid() {
		t.Fatal("alias-keyed registration no longer verifies: the decoder or the signature changed; revisit this guard")
	}
	if al.GetHash() == good.GetHash() || bytes.Equal(al.MinerAddress[:], good.MinerAddress[:]) {
		t.Fatalf("alias registration is not a distinct tx / tree key: %x %x %s %s", al.MinerAddress[:], good.MinerAddress[:], al.GetHash(), good.GetHash())
	}
	if err := r23b_check(al); !errors.Is(err, ErrNonCanonicalRegistration) {
		t.Fatalf("alias-keyed registration admitted (err %v)", err)
	}

	mal := *good
	s := new(big.Int).Add(new(big.Int).SetBytes(good.S[:]), bn256.Order)
	if s.BitLen() > 256 {
		t.Skip("S+Order does not fit 32 bytes for this signature")
	}
	crypto.FillBytes(s, mal.S[:])
	if !mal.IsRegistrationValid() {
		t.Fatal("S+Order registration no longer verifies; revisit this guard")
	}
	if err := r23b_check(&mal); !errors.Is(err, ErrNonCanonicalRegistration) {
		t.Fatalf("unreduced-S registration admitted (err %v)", err)
	}

	// x + P (decodes to the identity, r22) and an undecodable key (33 zero bytes): refused
	xp := new(big.Int).Add(new(big.Int).SetBytes(canon[:32]), bn256.P)
	if xp.BitLen() <= 256 {
		enc := make([]byte, 33)
		xp.FillBytes(enc[:32])
		if err := r23b_check(r23b_registration(x, enc)); !errors.Is(err, ErrNonCanonicalRegistration) {
			t.Fatalf("x >= P key admitted (err %v)", err)
		}
	}
	if err := r23b_check(r23b_registration(x, make([]byte, 33))); !errors.Is(err, ErrNonCanonicalRegistration) {
		t.Fatalf("undecodable key admitted (err %v)", err)
	}

	// a NORMAL tx is not affected by this rule
	var n transaction.Transaction
	n.TransactionType = transaction.NORMAL
	if !registration_canonical(&n) {
		t.Fatal("non-registration refused by the registration rule")
	}
}
