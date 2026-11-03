// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
)

func TestCanonicalAccountKey(t *testing.T) {
	good := new(bn256.G1).ScalarBaseMult(big.NewInt(12345)).EncodeCompressed()
	if p, ok := canonical_account_key(good); !ok || p == nil {
		t.Fatal("a canonical key was refused")
	}

	alias := append([]byte(nil), good...)
	alias[32] = 0x02 // decodes (consensus decoder) to the same point
	if _, ok := canonical_account_key(alias); ok {
		t.Fatal("an aliased flag byte was offered")
	}

	var noncanon []byte // x+P: decodes to the identity
	for k := int64(1); k < 64 && noncanon == nil; k++ {
		enc := new(bn256.G1).ScalarBaseMult(big.NewInt(k)).EncodeCompressed()
		x := new(big.Int).Add(new(big.Int).SetBytes(enc[:32]), bn256.P)
		if x.BitLen() <= 256 {
			noncanon = make([]byte, 33)
			x.FillBytes(noncanon[:32])
		}
	}
	var d bn256.G1
	if d.DecodeCompressed(noncanon) != nil {
		t.Fatal("premise changed: x >= P no longer decodes")
	}
	if _, ok := canonical_account_key(noncanon); ok {
		t.Fatal("a non-canonical x key was offered")
	}
	if _, ok := canonical_account_key(make([]byte, 33)); ok {
		t.Fatal("33 zero bytes were offered")
	}
	if _, ok := canonical_account_key(good[:32]); ok {
		t.Fatal("a short key was offered")
	}
}

func TestR22RPCWired(t *testing.T) {
	for file, want := range map[string]string{
		"rpc_dero_getrandomaddress.go":   "acckey, ok := canonical_account_key(k)",
		"rpc_dero_sendrawtransaction.go": "txcanon.Admit(tx_bytes, tx, chain.Add_TX_To_Pool)", // r23: inside txprecheck.Admit
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), want) {
			t.Fatalf("%s must contain %q", file, want)
		}
	}
}
