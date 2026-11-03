// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// r22 merge (crypto C3 review fix): at ringsize 2 only 2 ring orders exist per receiver, so a third payload to one
// destination is refused up front with ErrRingOrderExhausted (not the generic "please retry"); two are fine, other
// destinations and larger rings are not limited by this check.
func TestR22RingOrderSpace(t *testing.T) {
	pt := func(k int64) *bn256.G1 { return new(bn256.G1).ScalarMult(crypto.G, big.NewInt(k)) }
	sender, a, b := pt(11), pt(22), pt(33)
	r2 := func(rcv *bn256.G1) []*bn256.G1 { return []*bn256.G1{sender, rcv} }
	if err := ring_order_space([][]*bn256.G1{r2(a), r2(a)}); err != nil {
		t.Fatalf("two payloads to one destination refused: %v", err)
	}
	if err := ring_order_space([][]*bn256.G1{r2(a), r2(b), r2(a), r2(b)}); err != nil {
		t.Fatalf("2+2 payloads to two destinations refused: %v", err)
	}
	if err := ring_order_space([][]*bn256.G1{r2(a), r2(b), r2(a), r2(a)}); err != ErrRingOrderExhausted {
		t.Fatalf("third payload to one destination at ringsize 2: err %v, want ErrRingOrderExhausted", err)
	}
	r4 := []*bn256.G1{sender, a, pt(44), pt(55)}
	if err := ring_order_space([][]*bn256.G1{r4, r4, r4}); err != nil {
		t.Fatalf("ringsize 4 limited: %v", err)
	}
}
