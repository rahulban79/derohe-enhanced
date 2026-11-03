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
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// serial_leaves mirrors synchistory_internal_binary_search exactly, recording the topos passed to synchistory_block.
func serial_leaves(start int64, se []byte, end int64, ee []byte, registration int64, bal func(int64) []byte, out *[]int64) {
	if end < 0 {
		return
	}
	median := (start + end) / 2
	if start == median {
		*out = append(*out, start)
	}
	if end-start <= 1 {
		*out = append(*out, end)
		return
	}
	me := bal(median)
	if start == registration || !bytes.Equal(se, me) {
		serial_leaves(start, se, median, me, registration, bal, out)
	}
	if !bytes.Equal(me, ee) {
		serial_leaves(median, me, end, ee, registration, bal, out)
	}
}

func uniq_sorted(v []int64) []int64 {
	m := map[int64]bool{}
	out := []int64{}
	for _, t := range v {
		if !m[t] {
			m[t] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestDiscoverLeavesMatchesSerial: the parallel discovery visits exactly the blocks the serial walk processes, for
// random balance histories (sparse, dense, every block, registration at the start), at several parallelism levels.
func TestDiscoverLeavesMatchesSerial(t *testing.T) {
	rng := rand.New(rand.NewSource(20))
	for round := 0; round < 60; round++ {
		n := int64(2 + rng.Intn(400))
		start := int64(rng.Intn(50))
		end := start + n
		p := []float64{0.002, 0.05, 0.3, 1}[round%4]
		bal := map[int64][]byte{}
		v := 0
		for t := start; t <= end; t++ {
			if rng.Float64() < p {
				v++
			}
			bal[t] = []byte(fmt.Sprint(v))
		}
		get := func(t int64) []byte { return bal[t] }
		registration := int64(-5)
		se := get(start)
		switch round % 3 {
		case 0:
			registration = start // the serial walk always descends left of the registration topo, even when the
			// start balance equals the median's (only the registration rule then sends it left)
		case 1:
			registration = start
			se = []byte("zero-balance")
		}
		var want []int64
		serial_leaves(start, se, end, get(end), registration, get, &want)
		want = uniq_sorted(want)
		for _, par := range []int{1, 3, 8} {
			got := discover_leaves(start, se, end, get(end), registration, par, func(t int64) ([]byte, bool) { return get(t), true })
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round %d par %d: leaves differ\n got %v\nwant %v", round, par, got, want)
			}
		}
	}
}

// TestDiscoverLeavesBoundsInFlight: never more than par fetches at once, and a failing fetch prunes only its branch.
func TestDiscoverLeavesBoundsInFlight(t *testing.T) {
	var cur, peak int64
	fetch := func(t int64) ([]byte, bool) {
		c := atomic.AddInt64(&cur, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if c <= p || atomic.CompareAndSwapInt64(&peak, p, c) {
				break
			}
		}
		time.Sleep(200 * time.Microsecond)
		atomic.AddInt64(&cur, -1)
		return []byte(fmt.Sprint(t)), true // every block changed: the widest possible walk
	}
	leaves := discover_leaves(0, []byte("s"), 2000, []byte("e"), -1, 4, fetch)
	if len(leaves) != 2001 {
		t.Fatalf("every block changed: want 2001 leaves, got %d", len(leaves))
	}
	if peak > 4 || peak < 2 {
		t.Fatalf("in-flight fetches peaked at %d, want 2..4", peak)
	}
	failing := discover_leaves(0, []byte("s"), 64, []byte("e"), -1, 4, func(t int64) ([]byte, bool) { return nil, false })
	if len(failing) != 0 {
		t.Fatalf("a failed root fetch must prune everything, got %v", failing)
	}
}

// TestPrefetchWindowAndTake: blocks are fetched once each, in a window of at most `ahead` held blocks in front of the
// consumer; take() of an unknown topo is nil and a skipped leaf is never fetched later.
func TestPrefetchWindowAndTake(t *testing.T) {
	var leaves []int64
	for i := int64(0); i < 200; i++ {
		leaves = append(leaves, 10+3*i)
	}
	var mu sync.Mutex
	fills := map[int64]int{}
	fill := func(topo int64, s *blockSlot) {
		mu.Lock()
		fills[topo]++
		mu.Unlock()
		s.bres.Blob = fmt.Sprint(topo)
		s.ok = topo != 13 // a failed prefetch is reported as "not prefetched"
	}
	const ahead = 8
	p := newSyncPrefetch(crypto.Hash{}, leaves, ahead, 3, fill)
	p.ensure(0)
	if p.held() > ahead {
		t.Fatalf("held %d > ahead %d after ensure(0)", p.held(), ahead)
	}
	if p.take(11) != nil {
		t.Fatalf("topo 11 is not a leaf and must not be served")
	}
	for i, topo := range leaves {
		if i == 50 { // the consumer skips leaf 50 entirely
			continue
		}
		s := p.take(topo)
		if topo == 13 {
			if s != nil {
				t.Fatalf("failed prefetch served")
			}
		} else if s == nil || s.bres.Blob != fmt.Sprint(topo) {
			t.Fatalf("leaf %d: got %+v", topo, s)
		}
		if h := p.held(); h > ahead {
			t.Fatalf("after taking %d: %d blocks held, window is %d", topo, h, ahead)
		}
	}
	if p.take(leaves[3]) != nil {
		t.Fatalf("a block is served once")
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for topo, n := range fills {
		if n != 1 {
			t.Fatalf("leaf %d fetched %d times", topo, n)
		}
	}
	if len(fills) != len(leaves) && len(fills) != len(leaves)-1 {
		t.Fatalf("fetched %d of %d leaves", len(fills), len(leaves))
	}
	var nilp *syncPrefetch
	if nilp.take(5) != nil {
		t.Fatalf("nil prefetcher must serve nothing")
	}
}

// TestSplitTxBatch: a batched answer becomes single-hash answers only when its shape matches the request.
func TestSplitTxBatch(t *testing.T) {
	out := map[string]rpc.GetTransaction_Result{}
	split_tx_batch([]string{"a", "b"}, rpc.GetTransaction_Result{Txs_as_hex: []string{"01"}, Txs: []rpc.Tx_Related_Info{{}}}, out)
	if len(out) != 0 {
		t.Fatalf("short answer must add nothing, got %v", out)
	}
	split_tx_batch([]string{"a", "b"}, rpc.GetTransaction_Result{Txs_as_hex: []string{"01", "02"}, Txs: []rpc.Tx_Related_Info{{Block_Height: 1}, {Block_Height: 2}}, Status: "OK"}, out)
	if len(out) != 2 || out["b"].Txs_as_hex[0] != "02" || out["b"].Txs[0].Block_Height != 2 || out["a"].Status != "OK" {
		t.Fatalf("bad split %+v", out)
	}
	s := &blockSlot{txs: out}
	if r, ok := s.tx("a"); !ok || r.Txs_as_hex[0] != "01" {
		t.Fatalf("tx lookup failed")
	}
	if _, ok := s.tx("c"); ok {
		t.Fatalf("unknown hash served")
	}
	var ns *blockSlot
	if _, ok := ns.tx("a"); ok {
		t.Fatalf("nil slot served a tx")
	}
}

// TestPrefetchGenerationGuard: a balance that arrives after its run ended never seeds the next run's cache.
func TestPrefetchGenerationGuard(t *testing.T) {
	var s walletSyncState
	e := crypto.ConstructElGamal(crypto.G, crypto.G)
	s.begin()
	old := s.generation()
	s.end()
	s.begin()
	s.putBalanceGen(old, syncKey{crypto.Hash{}, 7}, 1, 2, crypto.Hash{}, e)
	if _, _, ok := s.getBalance(syncKey{crypto.Hash{}, 7}); ok {
		t.Fatalf("stale-generation balance was cached in the new run")
	}
	s.putBalanceGen(s.generation(), syncKey{crypto.Hash{}, 7}, 1, 2, crypto.Hash{}, e)
	if _, _, ok := s.getBalance(syncKey{crypto.Hash{}, 7}); !ok {
		t.Fatalf("current-generation balance not cached")
	}
	if s.setPrefetch(nil); s.prefetch(crypto.Hash{}) != nil {
		t.Fatalf("nil prefetcher returned")
	}
	s.end()
	if s.setPrefetch(newSyncPrefetch(crypto.Hash{}, nil, 1, 1, nil)) {
		t.Fatalf("prefetcher attached with no active run")
	}
}

func TestSyncParallelFromEnv(t *testing.T) {
	for in, want := range map[string]int{"": SYNC_PARALLEL, "1": 1, "8": 8, "0": SYNC_PARALLEL, "x": SYNC_PARALLEL, "65": SYNC_PARALLEL} {
		if got := sync_parallel_from_env(in); got != want {
			t.Fatalf("%q: got %d want %d", in, got, want)
		}
	}
}

// TestDaemonCallTimesOut: a daemon that accepts a call and never answers no longer blocks the wallet for ever.
func TestDaemonCallTimesOut(t *testing.T) {
	cch, sch := channel.Direct()
	srv := jrpc2.NewServer(handler.Map{"DERO.Hang": handler.New(func(ctx context.Context) (string, error) {
		<-ctx.Done() // never answers on its own
		return "", ctx.Err()
	})}, nil).Start(sch)
	defer srv.Stop()
	cli := &Client{RPC: jrpc2.NewClient(cch, nil)}
	defer cli.RPC.Close()
	old := daemon_call_timeout
	daemon_call_timeout = 200 * time.Millisecond
	defer func() { daemon_call_timeout = old }()
	done := make(chan error, 1)
	go func() {
		var r string
		done <- cli.Call("DERO.Hang", nil, &r)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("a call the daemon never answers must fail")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("daemon call still blocked after 10 s: no timeout")
	}
}

// r20 merge (RW-01 review): a batch where one hash is missing ("" plus a later found hash, which resets derod's
// error) or still in the pool must not serve that hash; the serial pass then asks for it alone and keeps its
// error-and-retry semantics instead of decoding "" and losing the entry.
func TestSplitTxBatchRefusesMissingAndPool(t *testing.T) {
	out := map[string]rpc.GetTransaction_Result{}
	split_tx_batch([]string{"missing", "found", "pooled"}, rpc.GetTransaction_Result{
		Txs_as_hex: []string{"", "02", "03"},
		Txs:        []rpc.Tx_Related_Info{{}, {Block_Height: 2}, {In_pool: true}},
		Status:     "OK"}, out)
	if _, ok := (&blockSlot{txs: out}).tx("missing"); ok {
		t.Fatal("prefetch serves an empty answer for a missing tx")
	}
	if _, ok := (&blockSlot{txs: out}).tx("pooled"); ok {
		t.Fatal("prefetch serves a pool answer the single call would not give")
	}
	if r, ok := (&blockSlot{txs: out}).tx("found"); !ok || r.Txs_as_hex[0] != "02" {
		t.Fatal("the found tx of the batch was not served")
	}
}
