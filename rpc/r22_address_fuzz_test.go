// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// FuzzAddressDecode: address decoding never panics, and an accepted address re-encodes to a string that decodes
// to the same public key and network (r22 crypto audit; characterization only, rpc/ is consensus-guarded).
func FuzzAddressDecode(f *testing.F) {
	p := new(bn256.G1).ScalarBaseMult(big.NewInt(77))
	a := NewAddressFromKeys((*crypto.Point)(p))
	f.Add(a.String())
	a.Mainnet = false
	f.Add(a.String())
	f.Add("dero1")
	f.Add("deroi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		addr, err := NewAddress(s)
		if err != nil {
			return
		}
		again, err := NewAddress(addr.String())
		if err != nil {
			t.Fatalf("%q decoded but its re-encoding %q does not: %v", s, addr.String(), err)
		}
		if again.Mainnet != addr.Mainnet || again.PublicKey.String() != addr.PublicKey.String() {
			t.Fatalf("%q: re-encoding changed the key or network", s)
		}
	})
}
