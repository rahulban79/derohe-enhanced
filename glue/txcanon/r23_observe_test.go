// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

import (
	"errors"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
)

// Observe (Round 23) counts block txs on the block counters only; the mempool counters must not move.
func TestR23ObserveCountsBlockTxOnly(t *testing.T) {
	r0, n0 := rejected.Get(), nonCanonical.Get()
	o0, b0, a0 := blockObserved.Get(), blockBroken.Get(), blockNonCanonical.Get()

	good := (&synth{}).bytes()
	if err := Observe(good, decoded(t, good)); err != nil {
		t.Fatalf("canonical: %v", err)
	}
	q := new(bn256.G1).ScalarBaseMult(big.NewInt(idxC0)).EncodeCompressed()
	q[32] = 0x7f
	alias := (&synth{override: map[int][]byte{idxC0: q}}).bytes()
	if err := Observe(alias, decoded(t, alias)); err != nil {
		t.Fatalf("flag alias: %v", err)
	}
	bad := (&synth{override: map[int][]byte{idxC0: noncanonicalX(t)}}).bytes()
	if err := Observe(bad, decoded(t, bad)); !errors.Is(err, ErrNotRoundTrip) {
		t.Fatalf("x >= P: %v, want ErrNotRoundTrip", err)
	}
	if blockObserved.Get() != o0+3 || blockNonCanonical.Get() != a0+1 || blockBroken.Get() != b0+1 {
		t.Fatalf("block counters: observed +%d alias +%d broken +%d, want +3 +1 +1",
			blockObserved.Get()-o0, blockNonCanonical.Get()-a0, blockBroken.Get()-b0)
	}
	if rejected.Get() != r0 || nonCanonical.Get() != n0 {
		t.Fatal("Observe moved the mempool counters")
	}
}
