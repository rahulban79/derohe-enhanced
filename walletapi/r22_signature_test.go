// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

func r22_wallet(t *testing.T) *Wallet_Memory {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func r22_resign(t *testing.T, signed []byte, edit func(h map[string]string)) []byte {
	p, _ := pem.Decode(signed)
	if p == nil {
		t.Fatal("no pem")
	}
	edit(p.Headers)
	return pem.EncodeToMemory(p)
}

// bech32 of version byte 1 + 33 key bytes, built by hand so a non-canonical key can be encoded
func r22_address(t *testing.T, hrp string, key []byte) string {
	in := append([]byte{1}, key...)
	var acc, bits uint
	var out []int
	for _, b := range in {
		acc = acc<<8 | uint(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, int(acc>>bits)&31)
		}
	}
	if bits > 0 {
		out = append(out, int(acc<<(5-bits))&31)
	}
	s, err := rpc.Encode(hrp, out)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckSignatureRejectsMalleableScalar(t *testing.T) {
	w := r22_wallet(t)
	signed := w.SignData([]byte("hello"))
	if _, _, err := w.CheckSignature(signed); err != nil {
		t.Fatalf("a genuine signature failed: %v", err)
	}
	p, _ := pem.Decode(signed)
	s, _ := new(big.Int).SetString(p.Headers["S"], 16)
	malleated := r22_resign(t, signed, func(h map[string]string) {
		h["S"] = fmt.Sprintf("%x", new(big.Int).Add(s, bn256.Order))
	})
	if _, _, err := w.CheckSignature(malleated); err == nil {
		t.Fatal("S + order verified: one signature has many encodings")
	}
}

// with the signer key decoding to the identity, s*G - c*identity = s*G for every c: a forgery needs no secret
func TestCheckSignatureRejectsIdentitySigner(t *testing.T) {
	w := r22_wallet(t)
	var key []byte
	for k := int64(1); k < 64 && key == nil; k++ {
		enc := new(bn256.G1).ScalarBaseMult(big.NewInt(k)).EncodeCompressed()
		x := new(big.Int).Add(new(big.Int).SetBytes(enc[:32]), bn256.P)
		if x.BitLen() <= 256 {
			key = make([]byte, 33)
			x.FillBytes(key[:32])
		}
	}
	astr := r22_address(t, "dero", key)
	addr, err := rpc.NewAddress(astr)
	if err != nil {
		t.Fatalf("premise changed: the non-canonical address no longer decodes: %v", err)
	}
	msg := []byte("forged")
	s := big.NewInt(12345)
	tmppoint := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, s), new(bn256.G1).ScalarMult(addr.PublicKey.G1(), big.NewInt(-1)))
	c := crypto.ReducedHash([]byte(fmt.Sprintf("%s%s%x", addr.PublicKey.G1().String(), tmppoint.String(), msg)))
	p := &pem.Block{Type: "DERO SIGNED MESSAGE", Headers: map[string]string{"Address": astr, "C": fmt.Sprintf("%x", c), "S": fmt.Sprintf("%x", s)}, Bytes: msg}
	if _, _, err := w.CheckSignature(pem.EncodeToMemory(p)); err == nil {
		t.Fatal("a signature by an identity-key address verified without any secret")
	}
	// the same forgery with the re-encoded (canonical-looking) address string is refused as well
	p.Headers["Address"] = addr.String()
	if _, _, err := w.CheckSignature(pem.EncodeToMemory(p)); err == nil {
		t.Fatal("a signature by the identity verified")
	}
}

// r22_sign is SignData's Schnorr signature for an arbitrary secret, with the address string given
func r22_sign(sk *big.Int, astr string, msg []byte) []byte {
	pub := new(bn256.G1).ScalarMult(crypto.G, sk)
	k := big.NewInt(987654321)
	R := new(bn256.G1).ScalarMult(crypto.G, k)
	c := crypto.ReducedHash([]byte(fmt.Sprintf("%s%s%x", pub.String(), R.String(), msg)))
	s := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(c, sk), k), bn256.Order)
	p := &pem.Block{Type: "DERO SIGNED MESSAGE", Headers: map[string]string{"Address": astr, "C": fmt.Sprintf("%x", c), "S": fmt.Sprintf("%x", s)}, Bytes: msg}
	return pem.EncodeToMemory(p)
}

// an undefined flag byte (0x02..0xff) decodes to the root ModSqrt returns first: for about half of all keys that
// is the key itself, so the same key has a second, non-canonical address string
func TestCheckSignatureRejectsAliasedAddress(t *testing.T) {
	w := r22_wallet(t)
	for k := int64(2); k < 200; k++ {
		sk := big.NewInt(k)
		pub := new(bn256.G1).ScalarMult(crypto.G, sk)
		key := pub.EncodeCompressed()
		canonical := r22_address(t, "dero", key)
		key[32] = 0x02
		alias := r22_address(t, "dero", key)
		a, err := rpc.NewAddress(alias)
		if err != nil || a.String() != canonical {
			continue // this key's alias names the negated key
		}
		if _, _, err := w.CheckSignature(r22_sign(sk, canonical, []byte("hi"))); err != nil {
			t.Fatalf("a genuine signature by %s failed: %v", canonical, err)
		}
		if _, _, err := w.CheckSignature(r22_sign(sk, alias, []byte("hi"))); err == nil {
			t.Fatal("a signature under an aliased address string verified")
		}
		return
	}
	t.Fatal("no key whose 0x02 alias decodes to itself")
}
