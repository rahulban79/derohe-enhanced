// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package rpc_test

// r28 (glue-global, B144 'fix every copy', rft §10): rpc/wallet_rpc.go keeps its own copy of FormatMoney* (the 64-bit
// quotient globals has). Pinned here: (1) in the region where the 64-bit quotient is exact (every precision below
// 2^40, precisions 0/5/8 below 2^53) the copy equals globals.FormatMoneyPrecision whatever has landed; (2) in the defect
// region the copy prints the measured wrong digits while rpc_copy_landed is false, and the exact value once its held
// patch (harness/loop/held/r28_rpc_money_copy.patch) lands. A fix to one copy only fails here or in globals.

import (
	"math"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
)

// exact amount/1e5 with prec >= 5 decimals, or ties-to-even at 0 (the wrappers' precisions)
func r28_exact(a uint64, prec int) string {
	q, r := a/100000, a%100000
	if prec == 0 {
		if r > 50000 || (r == 50000 && q%2 == 1) {
			return new(big.Int).Add(new(big.Int).SetUint64(q), big.NewInt(1)).String()
		}
		return new(big.Int).SetUint64(q).String()
	}
	f := new(big.Int).SetUint64(r).String()
	return new(big.Int).SetUint64(q).String() + "." + strings.Repeat("0", 5-len(f)) + f + strings.Repeat("0", prec-5)
}

func TestR28RPCFormatMoneyCopy(t *testing.T) {
	rng := rand.New(rand.NewSource(144))
	for i := 0; i < 20000; i++ {
		a, b := rng.Uint64()%(1<<40), rng.Uint64()%(1<<53)
		for _, p := range []int{0, 5, 8, 12} {
			if r, g := rpc.FormatMoneyPrecision(a, p), globals.FormatMoneyPrecision(a, p); r != g || r != r28_exact(a, p) {
				t.Fatalf("FormatMoneyPrecision(%d, %d): rpc %s, globals %s, exact %s", a, p, r, g, r28_exact(a, p))
			}
			if p == 12 {
				continue
			}
			if r, g := rpc.FormatMoneyPrecision(b, p), globals.FormatMoneyPrecision(b, p); r != g {
				t.Fatalf("FormatMoneyPrecision(%d, %d): rpc %s, globals %s", b, p, r, g)
			}
		}
		if rpc.FormatMoney(a) != r28_exact(a, 5) || rpc.FormatMoney0(a) != r28_exact(a, 0) || rpc.FormatMoney5(a) != r28_exact(a, 5) ||
			rpc.FormatMoney8(a) != r28_exact(a, 8) || rpc.FormatMoney12(a) != r28_exact(a, 12) {
			t.Fatalf("rpc FormatMoney wrappers at %d", a)
		}
	}
	for _, c := range []struct {
		a    uint64
		p    int
		held string
	}{{math.MaxUint64, 5, "184467440737095.51614"}, {4468711520580859, 12, "44687115205.808589998633"},
		{2322686249184832139, 8, "23226862491848.32139015"}} {
		got, want := rpc.FormatMoneyPrecision(c.a, c.p), r28_exact(c.a, c.p)
		if rpc_copy_landed && got != want {
			t.Fatalf("landed: rpc FormatMoneyPrecision(%d, %d) = %s, want %s", c.a, c.p, got, want)
		}
		if !rpc_copy_landed && (got != c.held || got == want) {
			t.Fatalf("held: rpc FormatMoneyPrecision(%d, %d) = %s, pinned %s (exact %s): rpc/wallet_rpc.go changed "+
				"without its held patch", c.a, c.p, got, c.held, want)
		}
	}
}
