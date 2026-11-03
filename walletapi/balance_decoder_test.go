// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package walletapi

import (
	"math/big"
	"math/rand"
	"sort"
	"testing"

	"encoding/binary"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// lookupReference is the pre-r19 sequential Lookup, kept verbatim (minus
// comments) as the oracle for the batched/parallel implementation.
func lookupReference(t *LookupTable, p *bn256.G1, previous_balance uint64) (balance uint64) {
	var acc bn256.G1
	acc.ScalarMult(crypto.G, new(big.Int).SetUint64(previous_balance))
	if acc.String() == p.String() {
		return previous_balance
	}
	work_per_loop := new(bn256.G1)
	balance_part := uint64(0)
	balance_per_loop := uint64(len((*t)[0]) * len(*t))
	pcopy := new(bn256.G1).Set(p)
	work_per_loop.ScalarMult(crypto.G, new(big.Int).SetUint64(balance_per_loop))
	work_per_loop = new(bn256.G1).Neg(work_per_loop)
	loop_counter := 0
	for {
		if loop_counter != 0 {
			pcopy = new(bn256.G1).Add(pcopy, work_per_loop)
		}
		loop_counter++
		compressed := pcopy.EncodeCompressed()
		compressed[32] = 0
		compressed[31] = 0
		compressed[30] = 0
		big_part := binary.BigEndian.Uint64(compressed[25:])
		for i := range *t {
			index := sort.Search(len((*t)[i]), func(j int) bool { return ((*t)[i][j] & 0xffffffffff000000) >= big_part })
		check_again:
			if index < len((*t)[i]) && ((*t)[i][index]&0xffffffffff000000) == big_part {
				balance_part = ((*t)[i][index]) & 0xffffff
				acc.ScalarMult(crypto.G, new(big.Int).SetUint64(balance+balance_part))
				if acc.String() == p.String() {
					balance += balance_part
					return balance
				}
				index++
				goto check_again
			} else {
				balance += uint64(len((*t)[i]))
			}
		}
	}
}

func withTable(t testing.TB, count, size int, f func(tbl *LookupTable)) {
	old := Balance_lookup_table
	defer func() { Balance_lookup_table = old }()
	f(Initialize_LookupTable(count, size))
}

func pointOf(v uint64) *bn256.G1 {
	return new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(v))
}

// Test_Lookup_Matches_Reference checks the batched/parallel decoder against
// the original loop on balances that hit the hint, the first batch, batch
// boundaries, the parallel path and the second of two tables.
func Test_Lookup_Matches_Reference(t *testing.T) {
	for _, tc := range []struct{ count, size int }{{1, 1 << 10}, {2, 1 << 10}} {
		withTable(t, tc.count, tc.size, func(tbl *LookupTable) {
			n := uint64(tc.count * tc.size)
			f := uint64(lookupFirstBatch) * n   // balances covered by the first batch
			b := uint64(lookupBatchSize) * n    // balances covered by one full batch
			ps := f + lookupSequentialBatches*b // first balance of the parallel phase
			values := []uint64{0, 1, 2, n - 1, n, n + 1, f - 1, f, f + 1, f + b - 1, f + b, f + b + 1, b - 1, b, b + 1, 3*b + 17, 9*b - 1, 9*b + n/2 + 3,
				ps - 1, ps, ps + 1, ps + 3*b + 5}
			r := rand.New(rand.NewSource(19))
			for i := 0; i < 24; i++ {
				values = append(values, uint64(r.Int63n(int64(ps+4*b))))
			}
			for _, v := range values {
				for _, hint := range []uint64{0, v} {
					got := tbl.Lookup(pointOf(v), hint)
					want := lookupReference(tbl, pointOf(v), hint)
					if got != v || want != v {
						t.Fatalf("tables=%d size=%d value=%d hint=%d: got %d reference %d", tc.count, tc.size, v, hint, got, want)
					}
				}
			}
		})
	}
}

// the parallel path must also be right when forced to a single worker
func Test_Lookup_SingleWorker(t *testing.T) {
	old := lookupMaxWorkers
	lookupMaxWorkers = 1
	defer func() { lookupMaxWorkers = old }()
	withTable(t, 1, 1<<10, func(tbl *LookupTable) {
		v := uint64(lookupFirstBatch+lookupSequentialBatches*lookupBatchSize+3*lookupBatchSize)*(1<<10) + 12345
		if got := tbl.Lookup(pointOf(v), 0); got != v {
			t.Fatalf("got %d want %d", got, v)
		}
	})
}

// 1e8 atomic units = 1000 DERO with the 2^17 test table: 763 search steps
func benchLookup(b *testing.B, f func(*LookupTable, *bn256.G1, uint64) uint64) {
	withTable(b, 1, 1<<17, func(tbl *LookupTable) {
		p := pointOf(100000000)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if f(tbl, p, 0) != 100000000 {
				b.Fatal("wrong balance")
			}
		}
	})
}

func Benchmark_Lookup_Reference_1000DERO(b *testing.B) { benchLookup(b, lookupReference) }
func Benchmark_Lookup_1000DERO(b *testing.B) {
	benchLookup(b, func(t *LookupTable, p *bn256.G1, h uint64) uint64 { return t.Lookup(p, h) })
}

// 10 DERO = 1e6 units: 7 steps, inside the short first batch
func Benchmark_Lookup_Reference_10DERO(b *testing.B) { benchLookupV(b, 1000000, lookupReference) }
func Benchmark_Lookup_10DERO(b *testing.B) {
	benchLookupV(b, 1000000, func(t *LookupTable, p *bn256.G1, h uint64) uint64 { return t.Lookup(p, h) })
}

func benchLookupV(b *testing.B, v uint64, f func(*LookupTable, *bn256.G1, uint64) uint64) {
	withTable(b, 1, 1<<17, func(tbl *LookupTable) {
		p := pointOf(v)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if f(tbl, p, 0) != v {
				b.Fatal("wrong balance")
			}
		}
	})
}

// 20000 DERO = 2e9 units with the 2^17 table: 15258 steps, parallel phase
func Benchmark_Lookup_Reference_20000DERO(b *testing.B) {
	benchLookupV(b, 2000000000, lookupReference)
}
func Benchmark_Lookup_20000DERO(b *testing.B) {
	benchLookupV(b, 2000000000, func(t *LookupTable, p *bn256.G1, h uint64) uint64 { return t.Lookup(p, h) })
}

func Benchmark_Lookup_1000DERO_1worker(b *testing.B) {
	old := lookupMaxWorkers
	lookupMaxWorkers = 1
	defer func() { lookupMaxWorkers = old }()
	benchLookup(b, func(t *LookupTable, p *bn256.G1, h uint64) uint64 { return t.Lookup(p, h) })
}
