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

import "runtime"
import "fmt"
import "sort"
import "sync"
import "sync/atomic"
import "bytes"
import "math/big"
import "encoding/binary"

//import "github.com/mattn/go-isatty"
//import "github.com/cheggaaa/pb/v3"

import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/cryptography/bn256"

// this file implements balance decoder whih has to be bruteforced
// balance is a 64 bit field and total effort is 2^64
// but in reality, the balances are well distributed with the expectation that no one will ever be able to collect over 2 ^ 40
// However, 2^40 is solvable in less than 1 sec on a single core, with around 8 MB RAM, see below
// these tables are sharable between wallets

//type PreComputeTable [16*1024*1024]uint64 // each table is 128 MB in size

// table size cannot be more than 1<<24
const TABLE_SIZE = 1 << 19

type PreComputeTable []uint64 // each table is 2^TABLE_SIZE * 8  bytes  in size
// 2^15 * 8 = 32768 *8 = 256 Kib
// 2^16 * 8 =            512 Kib
// 2^17 * 8 =              1 Mib
// 2^18 * 8 =              2 Mib
// 2^19 * 8 =              4 Mib
// 2^20 * 8 =              8 Mib

type LookupTable []PreComputeTable // default is 1 table, if someone who owns 2^48 coins or more needs more speed, it is possible

// IntSlice attaches the methods of Interface to []int, sorting in increasing order.

//type UintSlice []uint64

func (p PreComputeTable) Len() int           { return len(p) }
func (p PreComputeTable) Less(i, j int) bool { return p[i] < p[j] }
func (p PreComputeTable) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// with some more smartness table can be condensed more to contain 16.3% more entries within the same size
func Initialize_LookupTable(count int, table_size int) *LookupTable {
	t := make([]PreComputeTable, count, count)

	if table_size&0xff != 0 {
		panic("table size must be multiple of 256")
	}

	//terminal := isatty.IsTerminal(os.Stdout.Fd())

	var acc bn256.G1 // avoid allocations every loop
	acc.ScalarMult(crypto.G, new(big.Int).SetUint64(0))

	small_table := make([]*bn256.G1, 256, 256)
	for k := range small_table {
		small_table[k] = new(bn256.G1)
	}

	var compressed [33]byte

	for i := range t {
		t[i] = make([]uint64, table_size, table_size)

		//bar := pb.New(table_size)
		//if terminal {
		//	bar.Start()
		//}
		for j := 0; j < table_size; j += 256 {

			for k := range small_table {
				small_table[k].Set(&acc)
				acc.Add(small_table[k], crypto.G)
			}
			(bn256.G1Array(small_table)).MakeAffine() // precompute everything ASAP

			//if terminal {
			//	bar.Add(256)
			//}

			for k := range small_table {
				// convert acc to compressed point and extract last 5 bytes
				//compressed := small_table[k].EncodeCompressed()
				small_table[k].EncodeCompressedToBuf(compressed[:])

				// replace last bytes by j in coded form
				compressed[32] = byte(uint64(j+k) & 0xff)
				compressed[31] = byte((uint64(j+k) >> 8) & 0xff)
				compressed[30] = byte((uint64(j+k) >> 16) & 0xff)

				(t)[i][j+k] = binary.BigEndian.Uint64(compressed[25:])
			}

			//  if j < 300  {
			//      fmt.Printf("%d[%d]th entry %x\n",i,j, (t)[i][j])
			// }

			if j%1000 == 0 && runtime.GOOS == "js" {
				fmt.Printf("completed %f (j %d)\n", float32(j)*100/float32(len((t)[i])), j)
				runtime.Gosched() // gives others opportunity to run
			}
		}

		//fmt.Printf("sorting start\n")
		sort.Sort(t[i])
		//fmt.Printf("sortingcomplete\n")
		//bar.Finish()
	}
	//fmt.Printf("lookuptable complete\n")
	t1 := LookupTable(t)

	Balance_lookup_table = &t1

	return &t1
}

// lookupBatchSize is the number of consecutive search steps whose candidate
// points are normalised with one shared field inversion (Montgomery's trick).
// Before this, every step paid a full inversion inside EncodeCompressed, which
// was ~80% of wallet history-sync CPU (pprof, Test_Sync_Bench).
const lookupBatchSize = 128

// lookupFirstBatch is the size of the very first batch (steps 0..7)
const lookupFirstBatch = 8

// lookupSequentialBatches full batches run before any goroutine is started
const lookupSequentialBatches = 8

// lookupMaxWorkers caps the goroutines a single large decode may use.
var lookupMaxWorkers = 8

// convert point to balance
// The search visits exactly the same candidates as the original sequential
// loop (step L checks p - L*N*G against every table, N = total table entries);
// a candidate is accepted only after the full point check G*balance == p, and
// that balance is unique for any value < group order, so batching and
// splitting the steps across goroutines cannot change the result.
func (t *LookupTable) Lookup(p *bn256.G1, previous_balance uint64) (balance uint64) {

	// wait till precompute table is ready
	// check if previous balance is still sane though it may have mutated

	if len(*Balance_lookup_table) < 1 {
		panic("precompute table is not ready")
	}

	target := new(bn256.G1).Set(p).Marshal() // affine x||y, all-zero for infinity

	var acc bn256.G1
	acc.ScalarMult(crypto.G, new(big.Int).SetUint64(previous_balance))
	if bytes.Equal(acc.Marshal(), target) {
		return previous_balance
	}

	balance_per_loop := uint64(len((*t)[0]) * len(*t))

	step := new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(balance_per_loop))
	step = new(bn256.G1).Neg(step)

	// small balances: a short first batch so tiny wallets pay ~no batching
	// overhead, then lookupSequentialBatches full batches, all on this
	// goroutine. Together they cover balances < (8+8*128)*N atomic units
	// (N = 2^21 in dero-wallet-cli: ~21,600 DERO). Measured on the live box
	// (miner using 90% CPU) one worker beat 6 workers for a 1000 DERO decode
	// (1.64 ms vs 2.42 ms/op), so goroutines are only used beyond that.
	if b, ok := t.lookupBatch(p, target, step, balance_per_loop, 0, lookupFirstBatch); ok {
		return b
	}
	for i := 0; i < lookupSequentialBatches; i++ {
		if b, ok := t.lookupBatch(p, target, step, balance_per_loop, uint64(lookupFirstBatch+i*lookupBatchSize), lookupBatchSize); ok {
			return b
		}
	}
	const parallel_start = lookupFirstBatch + lookupSequentialBatches*lookupBatchSize

	workers := runtime.GOMAXPROCS(0)
	if workers > lookupMaxWorkers {
		workers = lookupMaxWorkers
	}
	if runtime.GOOS == "js" || workers < 1 {
		workers = 1
	}

	if workers == 1 {
		for first := uint64(parallel_start); ; first += lookupBatchSize {
			if b, ok := t.lookupBatch(p, target, step, balance_per_loop, first, lookupBatchSize); ok {
				return b
			}
		}
	}

	var next uint64
	var found uint32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.LoadUint32(&found) == 0 {
				batch := atomic.AddUint64(&next, 1) - 1
				if b, ok := t.lookupBatch(p, target, step, balance_per_loop, parallel_start+batch*lookupBatchSize, lookupBatchSize); ok {
					if atomic.CompareAndSwapUint32(&found, 0, 1) {
						balance = b
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	return balance
}

// lookupBatch checks search steps [first, first+n) and returns the verified
// balance if one of them hits.
func (t *LookupTable) lookupBatch(p *bn256.G1, target []byte, step *bn256.G1, balance_per_loop uint64, first uint64, n int) (uint64, bool) {
	points := make([]*bn256.G1, n)

	// points[0] = p - first*N*G
	start := new(bn256.G1).Set(p)
	if first != 0 {
		offset := new(big.Int).Mul(new(big.Int).SetUint64(first), new(big.Int).SetUint64(balance_per_loop))
		offset.Mod(offset, bn256.Order)
		start.Add(start, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(crypto.G, offset)))
	}
	points[0] = start
	for k := 1; k < n; k++ {
		points[k] = new(bn256.G1).Add(points[k-1], step)
	}
	bn256.G1Array(points).MakeAffine() // one inversion for the whole batch

	var acc bn256.G1
	for k := range points {
		compressed := points[k].EncodeCompressed()

		compressed[32] = 0
		compressed[31] = 0
		compressed[30] = 0

		big_part := binary.BigEndian.Uint64(compressed[25:])

		balance := (first + uint64(k)) * balance_per_loop

		for i := range *t {
			index := sort.Search(len((*t)[i]), func(j int) bool { return ((*t)[i][j] & 0xffffffffff000000) >= big_part })
			for ; index < len((*t)[i]) && ((*t)[i][index]&0xffffffffff000000) == big_part; index++ {
				balance_part := ((*t)[i][index]) & 0xffffff
				acc.ScalarMult(crypto.G, new(big.Int).SetUint64(balance+balance_part))
				if bytes.Equal(acc.Marshal(), target) { // since we may have part collisions, make sure full point is checked
					return balance + balance_part, true
				}
			}
			balance += uint64(len((*t)[i]))
		}
	}
	return 0, false
}

// this should be tuned by anyone using this package
func init() {
	Initialize_LookupTable(1, 1<<16)
}
