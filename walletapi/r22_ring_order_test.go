// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"bytes"
	"math/big"
	mathrand "math/rand"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/globals"
)

func r22_key(k int64) *bn256.G1 { return new(bn256.G1).ScalarBaseMult(big.NewInt(k)) }

// ringsize 2 has exactly two orders: two payloads to one destination get both, a third cannot be built
func TestPickRingOrderRing2NoReuse(t *testing.T) {
	sender, receiver := r22_key(11), r22_key(22)
	crand := mathrand.New(globals.NewCryptoRandSource())
	used := map[string]bool{}
	keyfn := func(wi []int) string { return ring_order_key(wi, sender, receiver, nil) }
	seen := map[string]bool{}
	for p := 0; p < 2; p++ {
		wi := []int{0, 1}
		if !pick_ring_order(crand, wi, used, keyfn) {
			t.Fatalf("payload %d: no order found", p)
		}
		k := keyfn(wi)
		if seen[k] {
			t.Fatalf("payload %d reused the ring order of an earlier payload", p)
		}
		seen[k] = true
	}
	if pick_ring_order(crand, []int{0, 1}, used, keyfn) {
		t.Fatal("a third ring-2 payload to the same destination got an order (it must reuse one)")
	}
}

// payloads with different rings never conflict, and the sender/receiver parity rule still holds
func TestPickRingOrderParityAndIndependence(t *testing.T) {
	crand := mathrand.New(globals.NewCryptoRandSource())
	used := map[string]bool{}
	for p := 0; p < 50; p++ {
		sender, receiver := r22_key(1), r22_key(int64(100+p))
		anon := []*bn256.G1{r22_key(int64(1000 + 6*p)), r22_key(int64(1001 + 6*p)), r22_key(int64(1002 + 6*p)),
			r22_key(int64(1003 + 6*p)), r22_key(int64(1004 + 6*p)), r22_key(int64(1005 + 6*p))}
		wi := []int{0, 1, 2, 3, 4, 5, 6, 7}
		if !pick_ring_order(crand, wi, used, func(w []int) string { return ring_order_key(w, sender, receiver, anon) }) {
			t.Fatalf("payload %d: no order", p)
		}
		if wi[0]%2 == wi[1]%2 {
			t.Fatalf("payload %d: sender and receiver have the same parity %v", p, wi)
		}
	}
	if len(used) != 50 {
		t.Fatalf("%d orders recorded, want 50", len(used))
	}
}

// the key is the ring exactly as BuildTransaction lays out publickeylist
func TestRingOrderKeyLayout(t *testing.T) {
	sender, receiver := r22_key(5), r22_key(6)
	anon := []*bn256.G1{r22_key(7), r22_key(8)}
	wi := []int{2, 1, 0, 3} // sender at 2, receiver at 1, anon at 0 and 3
	want := append(append(append(append([]byte{}, anon[0].EncodeCompressed()...), receiver.EncodeCompressed()...),
		sender.EncodeCompressed()...), anon[1].EncodeCompressed()...)
	if got := ring_order_key(wi, sender, receiver, anon); !bytes.Equal([]byte(got), want) {
		t.Fatal("ring_order_key does not match the publickeylist layout")
	}
	if len(anon) != 2 {
		t.Fatal("ring_order_key consumed the caller's anonset slice")
	}
}
