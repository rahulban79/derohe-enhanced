// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r21 rpcws: foreign-websocket call rate (R-6), DERO.WatchTx / TxPool pushes, the once-per-job getwork frame.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
)

// ---- R-6: foreign websocket call rate ----------------------------------------------------------------------------

func TestForeignCostWeights(t *testing.T) {
	now := time.Unix(1000, 0)
	own := rate.NewLimiter(FOREIGN_WS_RATE, FOREIGN_WS_BURST)
	node := rate.NewLimiter(1e6, 1e6)
	n := 0
	for allow_foreign_call(own, node, "DERO.GetBlockHeadersRange", now) {
		n++
	}
	if n != FOREIGN_WS_BURST/8 {
		t.Fatalf("%d range calls at one instant, want burst/8 = %d", n, FOREIGN_WS_BURST/8)
	}
	own = rate.NewLimiter(FOREIGN_WS_RATE, FOREIGN_WS_BURST)
	n = 0
	for allow_foreign_call(own, node, "DERO.Ping", now) {
		n++
	}
	if n != FOREIGN_WS_BURST {
		t.Fatalf("%d pings at one instant, want %d", n, FOREIGN_WS_BURST)
	}
	if foreign_cost("no.such.method") != 1 || foreign_cost("DERO.WatchTx") < 2 {
		t.Fatal("cost table")
	}
	// the shared node bucket binds even when the socket's own bucket has room
	small := rate.NewLimiter(1, 3)
	n = 0
	for i := 0; i < 10; i++ {
		if allow_foreign_call(rate.NewLimiter(FOREIGN_WS_RATE, FOREIGN_WS_BURST), small, "DERO.Ping", now) {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("node bucket let %d calls through fresh sockets, want 3", n)
	}
}

func TestForeignAssignerOnlyForForeign(t *testing.T) {
	if _, ok := assigner_for(new_ws_client(nil, false, "127.0.0.1")).(dummyassigner); !ok {
		t.Fatal("a same-machine socket got the gated method table")
	}
	if _, ok := assigner_for(new_ws_client(nil, true, FOREIGN_LIMIT_KEY)).(foreign_assigner); !ok {
		t.Fatal("a cross-site socket kept the ungated method table")
	}
	if new_ws_client(nil, false, "127.0.0.1").limiter != nil || new_ws_client(nil, true, FOREIGN_LIMIT_KEY).limiter == nil {
		t.Fatal("only foreign sockets get a limiter")
	}
}

// End to end through rpc_guard and /ws: a cross-site socket is rate limited with RPC_CODE_RATE_LIMITED and stays
// open; a same-machine socket sending far more is never limited.
func TestForeignWebsocketRateLimited(t *testing.T) {
	// the shared bucket (burst FOREIGN_NODE_BURST) is not the binding one here: N < FOREIGN_NODE_BURST
	addr := guarded_test_server(t)

	foreign, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"https://evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	limited0 := foreign_rate_limited.Get()
	start := time.Now()
	ok, limited := 0, 0
	const N = 3 * FOREIGN_WS_BURST
	for i := 0; i < N; i++ {
		r := foreign.call(t, 100+i, "DERO.Ping", "")
		switch {
		case string(r["result"]) == `"Pong "`:
			ok++
		case strings.Contains(string(r["error"]), fmt.Sprint(int(RPC_CODE_RATE_LIMITED))):
			limited++
		default:
			t.Fatalf("unexpected answer %v", r)
		}
	}
	el := time.Since(start).Seconds()
	if limited == 0 {
		t.Fatalf("%d pings from a cross-site socket in %.2fs, none limited", N, el)
	}
	if max := FOREIGN_WS_BURST + int(FOREIGN_WS_RATE*el) + 1; ok > max {
		t.Fatalf("%d pings answered in %.2fs, budget allows %d", ok, el, max)
	}
	if got := foreign_rate_limited.Get() - limited0; got != uint64(limited) {
		t.Fatalf("rpc_foreign_rate_limited_total grew %d, %d refusals seen", got, limited)
	}
	time.Sleep(time.Second / FOREIGN_WS_RATE * 3) // tokens come back: the socket was not closed
	if r := foreign.call(t, 999, "DERO.Ping", ""); string(r["result"]) != `"Pong "` {
		t.Fatalf("foreign socket after refill: %v", r)
	}

	local, _, err := dial_ws_with(t, addr, http.Header{"Origin": {"http://127.0.0.1:10102"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4*FOREIGN_WS_BURST; i++ {
		if r := local.call(t, 2000+i, "DERO.Ping", ""); string(r["result"]) != `"Pong "` {
			t.Fatalf("same-machine socket call %d: %v", i, r)
		}
	}
}

// ---- WatchTx / TxPool -------------------------------------------------------------------------------------------

// push_pair starts a real jrpc2 server (registered as a /ws client) and a client that records pushes.
type push_rec struct {
	mu  sync.Mutex
	evs map[string][]json.RawMessage
}

func (p *push_rec) get(method string) []json.RawMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]json.RawMessage(nil), p.evs[method]...)
}

func (p *push_rec) wait(t *testing.T, method string, n int) []json.RawMessage {
	t.Helper()
	for i := 0; i < 300; i++ {
		if e := p.get(method); len(e) >= n {
			return e
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("got %d %s pushes, want %d", len(p.get(method)), method, n)
	return nil
}

func push_pair(t *testing.T, subs uint32) (*ws_client, *push_rec) {
	cch, sch := channel.Direct()
	srv := jrpc2.NewServer(d, &jrpc2.ServerOptions{AllowPush: true})
	rec := &push_rec{evs: map[string][]json.RawMessage{}}
	cli := jrpc2.NewClient(cch, &jrpc2.ClientOptions{OnNotify: func(req *jrpc2.Request) {
		var raw json.RawMessage
		req.UnmarshalParams(&raw)
		rec.mu.Lock()
		rec.evs[req.Method()] = append(rec.evs[req.Method()], raw)
		rec.mu.Unlock()
	}})
	c := new_ws_client(nil, false, "127.0.0.1")
	c.subs = subs
	client_connections.Store(srv, c)
	srv.Start(sch)
	t.Cleanup(func() {
		c.drop_watches()
		client_connections.Delete(srv)
		cli.Close()
		srv.Stop()
	})
	return c, rec
}

func TestWatchTxLifecycle(t *testing.T) {
	blk := hh(0xb1)
	src := fake_tx_src{valid: map[crypto.Hash]crypto.Hash{}, topo: map[crypto.Hash]int64{blk: 100},
		stores: map[crypto.Hash]bool{}, mem: map[crypto.Hash]bool{hh(1): true}, regs: map[crypto.Hash]bool{}}
	c, rec := push_pair(t, 0)
	total0 := atomic.LoadInt64(&watch_total)
	top := int64(100)
	topf := func() int64 { return top }
	res, err := watch_apply(c, []crypto.Hash{hh(1), hh(2)}, 3, false, src, top)
	if err != nil || res.Watching != 2 || res.Txs[0].State != "pool" || res.Txs[1].State != "unknown" {
		t.Fatalf("watch: %+v %v", res, err)
	}
	if atomic.LoadInt64(&watch_total)-total0 != 2 {
		t.Fatal("watch_total not counted")
	}
	var te tx_events
	te.tick(false, src, topf, func() []crypto.Hash { return nil })
	time.Sleep(50 * time.Millisecond)
	if n := len(rec.get("TxStatus")); n != 0 {
		t.Fatalf("%d TxStatus pushes without a change", n)
	}
	// hh(1) mined at topo 100 (1 confirmation), hh(2) reaches the pool
	src.valid[hh(1)] = blk
	delete(src.mem, hh(1))
	src.mem[hh(2)] = true
	te.tick(true, src, topf, func() []crypto.Hash { return nil })
	ev := rec.wait(t, "TxStatus", 1)
	var e TxStatus_Event
	json.Unmarshal(ev[0], &e)
	if len(e.Txs) != 2 || e.Txs[0].TxID != hh(1).String() || e.Txs[0].State != "mined" || e.Txs[0].Confirmations != 1 || e.Txs[1].State != "pool" {
		t.Fatalf("first change event %s", ev[0])
	}
	// a timer tick does not re-check mined txids; a block tick does, up to the target, then the watch ends
	top = 101
	te.tick(false, src, topf, func() []crypto.Hash { return nil })
	time.Sleep(50 * time.Millisecond)
	if len(rec.get("TxStatus")) != 1 {
		t.Fatal("timer tick re-checked a mined txid")
	}
	te.tick(true, src, topf, func() []crypto.Hash { return nil })
	rec.wait(t, "TxStatus", 2)
	top = 102
	te.tick(true, src, topf, func() []crypto.Hash { return nil })
	ev = rec.wait(t, "TxStatus", 3)
	json.Unmarshal(ev[2], &e)
	if len(e.Txs) != 1 || e.Txs[0].Confirmations != 3 {
		t.Fatalf("third event %s", ev[2])
	}
	c.watch_mu.Lock()
	_, still := c.watch[hh(1)]
	n := len(c.watch)
	c.watch_mu.Unlock()
	if still || n != 1 || atomic.LoadInt64(&watch_total)-total0 != 1 {
		t.Fatalf("watch did not end at its target: still=%v n=%d", still, n)
	}
	top = 103
	te.tick(true, src, topf, func() []crypto.Hash { return nil })
	time.Sleep(50 * time.Millisecond)
	if len(rec.get("TxStatus")) != 3 {
		t.Fatal("pushed after the watch ended")
	}
	// remove and close release the node-wide count
	if res, _ := watch_apply(c, []crypto.Hash{hh(2)}, 3, true, src, top); res.Watching != 0 {
		t.Fatalf("remove: %+v", res)
	}
	if atomic.LoadInt64(&watch_total) != total0 {
		t.Fatal("remove did not release watch_total")
	}
}

func TestWatchTxBounds(t *testing.T) {
	src := fake_tx_src{}
	c, _ := push_pair(t, 0)
	total0 := atomic.LoadInt64(&watch_total)
	var ids []crypto.Hash
	for i := 0; i < WATCH_MAX_PER_SOCKET; i++ {
		var h crypto.Hash
		h[0], h[1] = 7, byte(i)
		ids = append(ids, h)
	}
	if _, err := watch_apply(c, ids, 10, false, src, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := watch_apply(c, ids[:3], 10, false, src, 0); err != nil { // re-watching is not counted twice
		t.Fatal(err)
	}
	if _, err := watch_apply(c, []crypto.Hash{hh(9)}, 10, false, src, 0); err == nil {
		t.Fatal("65th watch on one socket accepted")
	}
	if got := atomic.LoadInt64(&watch_total) - total0; got != WATCH_MAX_PER_SOCKET {
		t.Fatalf("watch_total grew %d", got)
	}
	// node-wide cap
	atomic.AddInt64(&watch_total, WATCH_MAX_TOTAL)
	c2, _ := push_pair(t, 0)
	_, err := watch_apply(c2, []crypto.Hash{hh(9)}, 10, false, src, 0)
	atomic.AddInt64(&watch_total, -WATCH_MAX_TOTAL)
	if err == nil {
		t.Fatal("watch accepted over WATCH_MAX_TOTAL")
	}
	c.drop_watches()
	if atomic.LoadInt64(&watch_total) != total0 {
		t.Fatal("close did not release watch_total")
	}
	if _, err := watch_apply(c, ids[:1], 10, false, src, 0); err == nil || atomic.LoadInt64(&watch_total) != total0 {
		t.Fatal("watch accepted on a closed socket")
	}
	// parameter validation
	if _, err := parse_watch_ids(nil); err == nil {
		t.Fatal("empty txids")
	}
	if _, err := parse_watch_ids([]string{"zz"}); err == nil {
		t.Fatal("bad txid")
	}
	if _, err := parse_watch_ids([]string{strings.Repeat("0", 64)}); err == nil {
		t.Fatal("zero txid")
	}
	if got, _ := parse_watch_ids([]string{hh(1).String(), hh(1).String()}); len(got) != 1 {
		t.Fatal("duplicates not merged")
	}
	if _, err := watch_target(WATCH_MAX_CONFIRMATIONS + 1); err == nil {
		t.Fatal("confirmations above the max")
	}
	if n, _ := watch_target(0); n != WATCH_DEFAULT_CONFIRMATIONS {
		t.Fatal("default confirmations")
	}
	if _, err := WatchTx(context.Background(), WatchTx_Params{TxIDs: []string{hh(1).String()}}); err == nil || !strings.Contains(err.Error(), "websocket") {
		t.Fatalf("WatchTx over a non-websocket: %v", err)
	}
}

// A socket whose previous TxStatus push is still in flight keeps its old states and gets the change next time.
func TestWatchTxSkippedClientKeepsChange(t *testing.T) {
	src := fake_tx_src{valid: map[crypto.Hash]crypto.Hash{}, topo: map[crypto.Hash]int64{}, stores: map[crypto.Hash]bool{},
		mem: map[crypto.Hash]bool{}, regs: map[crypto.Hash]bool{}}
	c, rec := push_pair(t, 0)
	watch_apply(c, []crypto.Hash{hh(3)}, 1, false, src, 0)
	src.mem[hh(3)] = true
	atomic.StoreInt32(&c.busy_tx, 1)
	var te tx_events
	te.tick(false, src, func() int64 { return 0 }, func() []crypto.Hash { return nil })
	time.Sleep(30 * time.Millisecond)
	if len(rec.get("TxStatus")) != 0 {
		t.Fatal("pushed to a busy client")
	}
	atomic.StoreInt32(&c.busy_tx, 0)
	te.tick(false, src, func() int64 { return 0 }, func() []crypto.Hash { return nil })
	ev := rec.wait(t, "TxStatus", 1)
	if !bytes.Contains(ev[0], []byte(`"pool"`)) {
		t.Fatalf("change lost for a skipped client: %s", ev[0])
	}
}

// A shared txid watched by many sockets is checked once per tick.
func TestWatchTxChecksEachTxidOnce(t *testing.T) {
	src := fake_tx_src{}
	for i := 0; i < 5; i++ {
		c, _ := push_pair(t, 0)
		watch_apply(c, []crypto.Hash{hh(4), hh(5)}, 1, false, src, 0)
	}
	n0 := tx_status_checks.Get()
	var te tx_events
	te.tick(true, src, func() int64 { return 0 }, func() []crypto.Hash { return nil })
	if got := tx_status_checks.Get() - n0; got != 2 {
		t.Fatalf("%d status checks for 2 distinct txids on 5 sockets", got)
	}
}

func TestTxPoolEvents(t *testing.T) {
	_, rec := push_pair(t, SUB_TXPOOL)
	_, other := push_pair(t, SUB_BLOCKINFO)
	pool := []crypto.Hash{hh(1), hh(2)}
	list := func() []crypto.Hash { return pool }
	var te tx_events
	te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list) // baseline only
	time.Sleep(30 * time.Millisecond)
	if len(rec.get("TxPool")) != 0 {
		t.Fatal("baseline tick pushed")
	}
	pool = []crypto.Hash{hh(2), hh(3)}
	te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list)
	ev := rec.wait(t, "TxPool", 1)
	var e TxPool_Event
	json.Unmarshal(ev[0], &e)
	if len(e.Added) != 1 || e.Added[0] != hh(3).String() || len(e.Removed) != 1 || e.Removed[0] != hh(1).String() || e.PoolSize != 2 || e.Truncated {
		t.Fatalf("pool event %s", ev[0])
	}
	te.tick(false, fake_tx_src{}, func() int64 { return 0 }, list)
	time.Sleep(30 * time.Millisecond)
	if len(rec.get("TxPool")) != 1 || len(other.get("TxPool")) != 0 {
		t.Fatal("pushed without a change, or to a client that did not subscribe")
	}
	// clipping
	prev := map[crypto.Hash]struct{}{}
	cur := map[crypto.Hash]struct{}{}
	for i := 0; i < TXPOOL_EVENT_MAX+10; i++ {
		var h crypto.Hash
		h[0], h[1] = byte(i), byte(i>>8)
		cur[h] = struct{}{}
	}
	d, changed := pool_diff(prev, cur)
	if !changed || len(d.Added) != TXPOOL_EVENT_MAX || !d.Truncated || d.PoolSize != TXPOOL_EVENT_MAX+10 {
		t.Fatalf("clip: %d added, truncated %v", len(d.Added), d.Truncated)
	}
	if bits, _, err := parse_subscriptions([]string{"TxPool"}); err != nil || bits != SUB_TXPOOL {
		t.Fatal("TxPool subscription name")
	}
}

// ---- getwork job frame ------------------------------------------------------------------------------------------

func rand_str(r *rand.Rand) string {
	const alpha = "abc019<>&\"\\é\u2028 "
	rs := []rune(alpha)
	n := r.Intn(40)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(rs[r.Intn(len(rs))])
	}
	return b.String()
}

func TestJobFrameByteIdentical(t *testing.T) {
	r := rand.New(rand.NewSource(21))
	for i := 0; i < 2000; i++ {
		var base rpc.GetBlockTemplate_Result
		base.JobID = rand_str(r)
		base.Height = r.Uint64() >> uint(r.Intn(64))
		base.Prev_Hash = rand_str(r)
		base.Difficultyuint64 = r.Uint64()
		base.Difficulty = new(big.Int).SetUint64(r.Uint64()).String()
		if i%3 == 0 {
			base.LastError, base.Status, base.EpochMilli = rand_str(r), rand_str(r), r.Uint64()
		}
		var mbl block.MiniBlock
		mbl.Version = 1
		mbl.Final = i%2 == 0
		mbl.Timestamp = uint16(r.Uint32())
		mbl.Height = r.Uint64() % 0xffffffffff
		mbl.PastCount = uint8(1 + r.Intn(2))
		mbl.Past = [2]uint32{r.Uint32(), r.Uint32() | 1}
		mbl.Past[0] &^= 1 // never equal
		r.Read(mbl.KeyHash[:])
		fill_nonce(&mbl)
		blocks, minis, rej := r.Uint64()>>uint(r.Intn(64)), r.Uint64()>>uint(r.Intn(64)), uint64(r.Intn(3))
		jf := new_job_frame(base)
		for _, registered := range []bool{true, false} {
			params := base
			if !registered {
				params.LastError = job_unregistered_error
			}
			want := job_message(params, &mbl, blocks, minis, rej)
			got := jf.frame(&mbl, blocks, minis, rej, registered)
			if !bytes.Equal(want, got) {
				t.Fatalf("frame differs (registered=%v)\nwant %s\n got %s", registered, want, got)
			}
		}
	}
	var withtpl rpc.GetBlockTemplate_Result
	withtpl.Blocktemplate_blob = "00"
	if new_job_frame(withtpl) != nil {
		t.Fatal("a base with a field the frame does not carry must fall back to job_message")
	}
}

func TestFillNonceDiffers(t *testing.T) {
	var a, b block.MiniBlock
	fill_nonce(&a)
	fill_nonce(&b)
	if a.Nonce == b.Nonce || a.Nonce == [3]uint32{} {
		t.Fatalf("nonces %v %v", a.Nonce, b.Nonce)
	}
}

// per-miner cost of one job (encode only; the write is a buffered nbio write in both versions)
func BenchmarkJobPerMiner_R20(b *testing.B) {
	ts, h, ph, diff, mbl := sample_job()
	base := base_of(ts, h, ph, diff)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := mbl
		for j := range m.Nonce {
			m.Nonce[j] = globalsRandUint32()
		}
		_ = job_message(base, &m, 3, 41, 2)
	}
}

func BenchmarkJobPerMiner_R21(b *testing.B) {
	ts, h, ph, diff, mbl := sample_job()
	jf := new_job_frame(base_of(ts, h, ph, diff))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := mbl
		fill_nonce(&m)
		_ = jf.frame(&m, 3, 41, 2, true)
	}
}

func globalsRandUint32() uint32 { return globals.Global_Random.Uint32() }

// The check loop ends with its RPC server and never runs without a chain.
func TestTxEventsLoopExits(t *testing.T) {
	tx_events_loop(nil, nil) // returns at once
	exit := make(chan bool)
	done := make(chan struct{})
	go func() { tx_events_loop(&blockchain.Blockchain{}, exit); close(done) }()
	close(exit)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tx_events_loop kept running after its server stopped")
	}
}

// ---- r21 merge fixes (RPCWS21-A, RPCWS21-B) ------------------------------------------------------------------------

// RPCWS21-A: only loopback-foreign sockets (a page in a local browser, folded into FOREIGN_LIMIT_KEY) share the node
// bucket. A remote foreign socket (a web wallet on a public node, or a forged Origin) is limited by its own bucket and
// cannot drain the shared one.
func TestForeignNodeBucketOnlyForLoopbackForeign(t *testing.T) {
	saved := foreign_node_limiter
	defer func() { foreign_node_limiter = saved }()
	foreign_node_limiter = rate.NewLimiter(rate.Every(time.Hour), 3) // a node bucket with 3 tokens and ~no refill
	remote := new_ws_client(nil, true, "203.0.113.9")
	lo := new_ws_client(nil, true, FOREIGN_LIMIT_KEY)
	if remote.limiter == nil || remote.node_limiter != nil {
		t.Fatal("a remote foreign socket must have its own bucket and no share of the loopback node bucket")
	}
	if lo.node_limiter != foreign_node_limiter {
		t.Fatal("a loopback-foreign socket must draw on the node bucket")
	}
	now := time.Now()
	n := 0
	for allow_foreign_call(remote.limiter, remote.node_limiter, "DERO.Ping", now) {
		n++
	}
	if n != FOREIGN_WS_BURST {
		t.Fatalf("remote foreign socket: %d calls, want its own burst %d (the node bucket must not bind it)", n, FOREIGN_WS_BURST)
	}
	n = 0
	for allow_foreign_call(lo.limiter, lo.node_limiter, "DERO.Ping", now) {
		n++
	}
	if n != 3 {
		t.Fatalf("loopback-foreign socket: %d calls, want the node bucket's 3 (untouched by the remote socket)", n)
	}
}

// RPCWS21-B: foreign sockets together hold at most WATCH_MAX_FOREIGN watches; local sockets keep the rest, and a
// foreign socket's close releases its foreign share.
func TestWatchTxForeignSubCap(t *testing.T) {
	src := fake_tx_src{}
	f0, t0 := atomic.LoadInt64(&watch_foreign), atomic.LoadInt64(&watch_total)
	fc, _ := push_pair(t, 0)
	fc.foreign = true
	atomic.AddInt64(&watch_foreign, WATCH_MAX_FOREIGN-1) // other pages hold all but one foreign slot
	defer atomic.AddInt64(&watch_foreign, -(WATCH_MAX_FOREIGN - 1))
	if _, err := watch_apply(fc, []crypto.Hash{hh(0x41)}, 10, false, src, 0); err != nil {
		t.Fatalf("last foreign slot refused: %v", err)
	}
	if _, err := watch_apply(fc, []crypto.Hash{hh(0x42)}, 10, false, src, 0); err == nil {
		t.Fatal("foreign watch accepted over WATCH_MAX_FOREIGN")
	}
	if atomic.LoadInt64(&watch_total)-t0 != 1 || atomic.LoadInt64(&watch_foreign)-f0 != WATCH_MAX_FOREIGN {
		t.Fatal("a refused foreign watch must not stay counted")
	}
	lc, _ := push_pair(t, 0) // a local wallet is not affected by the foreign share
	if _, err := watch_apply(lc, []crypto.Hash{hh(0x43)}, 10, false, src, 0); err != nil {
		t.Fatalf("local watch refused while the foreign share is full: %v", err)
	}
	fc.drop_watches()
	lc.drop_watches()
	if atomic.LoadInt64(&watch_foreign)-f0 != WATCH_MAX_FOREIGN-1 || atomic.LoadInt64(&watch_total) != t0 {
		t.Fatal("close did not release the foreign share")
	}
}

// RPCWS21-B: a watch whose txid stays unknown for WATCH_UNKNOWN_TTL ends with one push listing it under "expired";
// a younger unknown watch stays.
func TestWatchTxUnknownExpires(t *testing.T) {
	src := fake_tx_src{}
	c, rec := push_pair(t, 0)
	t0 := atomic.LoadInt64(&watch_total)
	if _, err := watch_apply(c, []crypto.Hash{hh(0x51), hh(0x52)}, 10, false, src, 0); err != nil {
		t.Fatal(err)
	}
	c.watch_mu.Lock()
	c.watch[hh(0x51)].since = time.Now().Add(-WATCH_UNKNOWN_TTL - time.Second) // old enough
	c.watch_mu.Unlock()
	var te tx_events
	te.tick(false, src, func() int64 { return 0 }, func() []crypto.Hash { return nil })
	ev := rec.wait(t, "TxStatus", 1)
	var e TxStatus_Event
	json.Unmarshal(ev[0], &e)
	if len(e.Expired) != 1 || e.Expired[0] != hh(0x51).String() || len(e.Txs) != 0 {
		t.Fatalf("expiry event %s", ev[0])
	}
	c.watch_mu.Lock()
	_, gone := c.watch[hh(0x51)]
	_, kept := c.watch[hh(0x52)]
	c.watch_mu.Unlock()
	if gone || !kept || atomic.LoadInt64(&watch_total)-t0 != 1 {
		t.Fatalf("expired watch not removed or young one dropped: gone=%v kept=%v", !gone, kept)
	}
}
