// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// TestR31WalletOpenRefusesInconsistentKeys (rft §7 B283, finding DF-crypto-input-5325afeed7 at its only JSON caller):
// a wallet whose decrypted key pair is inconsistent (public key not Secret*G, or a key missing) is refused on open;
// an honest wallet opens with its keys unchanged.
func TestR31WalletOpenRefusesInconsistentKeys(t *testing.T) {
	seed := crypto.RandomScalarBNRed()
	w, err := Create_Encrypted_Wallet_Memory("r31", seed)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	good := w.Get_Encrypted_Wallet()
	w2, err := Open_Encrypted_Wallet_Memory("r31", good)
	if err != nil || w2 == nil || w2.account.Keys.Public.StringHex() != w.account.Keys.Public.StringHex() {
		t.Fatalf("honest wallet refused: %v", err)
	}

	other := new(crypto.Point).Set(crypto.GPoint.ScalarMult(crypto.GetBNRed(new(big.Int).Add(seed.BigInt(), big.NewInt(1)))))
	w.account.Keys.Public = other
	if w3, err := Open_Encrypted_Wallet_Memory("r31", w.Get_Encrypted_Wallet()); err != ErrWalletKeysMismatch || w3 != nil {
		t.Fatalf("mismatched public key: got %v, want ErrWalletKeysMismatch", err)
	}
	w.account.Keys.Public = nil
	if _, err := Open_Encrypted_Wallet_Memory("r31", w.Get_Encrypted_Wallet()); err != ErrWalletKeysMissing {
		t.Fatalf("missing public key: got %v, want ErrWalletKeysMissing", err)
	}

	// unit: a secret that is zero modulo the order is refused like at creation
	zero := crypto.GetBNRed(new(big.Int).Set(bn256.Order))
	if err := check_account_keys(_Keys{Secret: zero, Public: crypto.GPoint.ScalarMult(zero)}); err == nil {
		t.Fatalf("a zero-mod-order secret passed")
	}
	if err := check_account_keys(Generate_Keys_From_Seed(seed)); err != nil {
		t.Fatalf("honest keys refused: %v", err)
	}
}

// r31Address re-encodes an address string with its 33 key bytes replaced (the bech32 data of version byte 1, key
// and arguments; same layout as rpc.Address.MarshalText).
func r31Address(t *testing.T, hrp string, key []byte, args rpc.Arguments) string {
	t.Helper()
	data := append([]byte{1}, key...)
	if len(args) > 0 {
		b, err := args.MarshalBinary()
		if err != nil {
			t.Fatalf("args: %v", err)
		}
		data = append(data, b...)
	}
	var ints []int
	acc, bits := 0, uint(0)
	for _, v := range data {
		acc = acc<<8 | int(v)
		bits += 8
		for bits >= 5 {
			bits -= 5
			ints = append(ints, (acc>>bits)&31)
		}
	}
	if bits > 0 {
		ints = append(ints, (acc<<(5-bits))&31)
	}
	s, err := rpc.Encode(hrp, ints)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return s
}

// TestR31PaymentProofRefusesNonCanonicalKey (rft §7 B283): the receiver payment-proof check refuses a blinder or
// ring address whose key bytes are not the canonical encoding of the point they decode to. The premise is checked
// too: rpc.NewAddress (consensus-guarded rpc/, unchanged) accepts that string.
func TestR31PaymentProofRefusesNonCanonicalKey(t *testing.T) {
	b := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(424242))
	enc := b.EncodeCompressed()
	args := rpc.Arguments{{Name: rpc.RPC_VALUE_TRANSFER, DataType: rpc.DataUint64, Value: uint64(1000)}}
	honest := r31Address(t, "deroproof", enc, args)
	if _, amount, err := parse_payment_proof(honest); err != nil || amount != 1000 {
		t.Fatalf("honest proof string refused: %v", err)
	}
	alias := append([]byte{}, enc...)
	alias[32] = 0x02 // a key encoding other than the canonical one
	bad := r31Address(t, "deroproof", alias, args)
	if _, err := rpc.NewAddress(bad); err != nil {
		t.Fatalf("premise: rpc.NewAddress accepts the non-canonical key encoding (%v)", err)
	}
	if _, _, err := parse_payment_proof(bad); err != ErrNonCanonicalKey {
		t.Fatalf("non-canonical blinder: got %v, want ErrNonCanonicalKey", err)
	}

	member := r31Address(t, "deto", enc, nil)
	if _, err := canonical_address_key(member); err != nil {
		t.Fatalf("canonical ring address refused: %v", err)
	}
	if _, err := canonical_address_key(r31Address(t, "deto", alias, nil)); err != ErrNonCanonicalKey {
		t.Fatalf("non-canonical ring address: got %v, want ErrNonCanonicalKey", err)
	}
}
