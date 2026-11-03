// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// r24 (syncp2p): B18 compact-path observation, B34 prewarm accounting, the cross-response prewarm overlap, and the
// chain locator's read-error spin.

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// B18: the compact path hands add the pool bytes each copy was decoded from, in slot order.
func TestR24CompactBlockTxsRawMatchPool(t *testing.T) {
	pool := map[crypto.Hash]*transaction.Transaction{}
	var hashes []crypto.Hash
	for _, n := range []byte{5, 2, 8} {
		tx := reg_tx(n)
		pool[tx.GetHash()] = tx
		hashes = append(hashes, tx.GetHash())
	}
	txs, raws, ok := compact_block_txs_raw(hashes, func(h crypto.Hash) *transaction.Transaction { return pool[h] })
	if !ok || len(raws) != len(txs) || len(txs) != len(hashes) {
		t.Fatalf("ok=%v txs=%d raws=%d", ok, len(txs), len(raws))
	}
	for i := range hashes {
		if !bytes.Equal(raws[i], pool[hashes[i]].Serialize()) {
			t.Fatalf("raws[%d] are not the pool bytes of slot %d", i, i)
		}
		if txs[i].GetHash() != hashes[i] {
			t.Fatalf("slot %d out of order", i)
		}
	}
	if _, raws, ok := compact_block_txs_raw(append(hashes, crypto.Hash{0xee}), func(h crypto.Hash) *transaction.Transaction { return pool[h] }); ok || raws != nil {
		t.Fatal("a missing tx must abort with no bytes")
	}
}

// B18: try_compact passes the bytes from txs() through to add unchanged.
func TestR24TryCompactPassesRaws(t *testing.T) {
	want := [][]byte{{1, 2, 3}}
	var got [][]byte
	st := &Chunks_Per_Block_Data{bl: &block.Block{Tx_hashes: []crypto.Hash{{1}}}}
	ok := try_compact(st, 1, 16,
		func() ([]*transaction.Transaction, [][]byte, bool) {
			return []*transaction.Transaction{reg_tx(1)}, want, true
		},
		func(_ []*transaction.Transaction, raws [][]byte) bool { got = raws; return true })
	if !ok || len(got) != 1 || !bytes.Equal(got[0], want[0]) {
		t.Fatalf("add did not receive the pool bytes: ok=%v got=%v", ok, got)
	}
}

// B18: the compact add path observes the txs only after Add_Complete_Block_HF3 accepted the block.
func TestR24CompactPathObservesAfterAccept(t *testing.T) {
	src, err := os.ReadFile("compact_block.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	add := strings.Index(s, "if _, ok := Add_Complete_Block_HF3(chain, &cbl); !ok {\n\t\treturn false\n\t}")
	obs := strings.Index(s, "observe_block_txs(raws, txs)")
	if add < 0 || obs < 0 || obs < add {
		t.Fatal("add_compact_block must call observe_block_txs(raws, txs) after a successful Add_Complete_Block_HF3")
	}
	cs, err := os.ReadFile("chunk_server.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cs), "return compact_block_txs_raw(bl.Tx_hashes, pool_tx)") || !strings.Contains(string(cs), "return connection.add_compact_block(bl, txs, raws)") {
		t.Fatal("chunk_server.go must wire the pool bytes into add_compact_block")
	}
}

func TestR24OverlapCovered(t *testing.T) {
	var nilo *prewarm_overlap
	b := crypto.Hash{7}
	if nilo.covered(b) {
		t.Fatal("nil overlap covers nothing")
	}
	full := &prewarm_overlap{blid: b, ran: PREWARM_MINIBLOCKS}
	if !full.covered(b) {
		t.Fatal("a finished overlap that ran every miniblock of b covers b")
	}
	if full.covered(crypto.Hash{8}) {
		t.Fatal("an overlap covers only its own block")
	}
	if (&prewarm_overlap{blid: b, ran: PREWARM_MINIBLOCKS - 1}).covered(b) || (&prewarm_overlap{blid: b}).covered(b) {
		t.Fatal("a partial or missed overlap must leave the prewarm to the loop")
	}
	if (&prewarm_overlap{ran: PREWARM_MINIBLOCKS}).covered(crypto.Hash{}) {
		t.Fatal("an overlap with no block id covers nothing")
	}
}

func TestR24OverlapRecordsRan(t *testing.T) {
	o := start_prewarm_overlap(func() bool { return true }, func() int { return PREWARM_MINIBLOCKS })
	o.finish()
	if o.ran != PREWARM_MINIBLOCKS {
		t.Fatalf("ran=%d after an overlap that prewarmed everything", o.ran)
	}
	o = start_prewarm_overlap(func() bool { return false }, func() int { t.Fatal("prewarmed without ready"); return 0 })
	o.finish()
	if o.ran != 0 {
		t.Fatal("a missed overlap must report ran=0")
	}
	o = start_prewarm_overlap(func() bool { return true }, func() int { panic("x") })
	o.finish()
	if o.ran != 0 {
		t.Fatal("a panicking prewarm must report ran=0 (the loop prewarms again)")
	}
}

type r24_secs struct{ v float64 }

func (c *r24_secs) Add(x float64) { c.v += x }

// B34: the overlap's time goes to its own counter, not to p2p_sync_prewarm_seconds_total.
func TestR24PrewarmIntoOwnCounter(t *testing.T) {
	known := func(crypto.Hash) int64 { return 1 }
	before := prewarm_seconds.Get()
	var c r24_secs
	n := prewarm_pow_into(&c, known, ids_n(1), PREWARM_MINIBLOCKS, func(int) bool { time.Sleep(time.Millisecond); return true })
	if n != PREWARM_MINIBLOCKS || c.v <= 0 {
		t.Fatalf("n=%d secs=%v", n, c.v)
	}
	if prewarm_seconds.Get() != before {
		t.Fatal("prewarm_pow_into(own counter) moved p2p_sync_prewarm_seconds_total")
	}
	src, _ := os.ReadFile("sync_prewarm_overlap.go")
	// r24 merge: the overlap calls chainperf's prewarm_pow_with with prewarm_overlap_seconds.Add as its sink
	if !strings.Contains(string(src), "func() { chain.Get_Difficulty_At_Tips(nb.Tips) },\n\t\t\t\tprewarm_overlap_seconds.Add, func(k int) bool {") {
		t.Fatal("the overlap must account its prewarm time to p2p_sync_prewarm_overlap_seconds_total")
	}
}

// B34 wiring: a block the overlap covered is not prewarmed again, and only an accepted block's overlap is kept.
func TestR24SyncLoopSkipsCoveredBlock(t *testing.T) {
	src, err := os.ReadFile("chain_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, w := range []string{
		"prev := run.take_prev()",
		"if syncing && prev.covered(bl.GetHash()) {",
		"} else if syncing { // verify the miniblock PoWs in parallel first",
		"overlap = run.next_overlap(response.CBlocks, i, next_block_prewarm)",
		"if ok {\n\t\t\trun.keep(overlap)",
		"return connection.process_object_response_run(o, 0, true, nil, run)",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("chain_sync.go: missing %q", w)
		}
	}
}

// cross-response overlap: the last block of a response overlaps the next response's first block (peeked), and
// nothing else changes.
func TestR24NextOverlapUsesPeekOnlyForLastBlock(t *testing.T) {
	cbs := []Complete_Block{{Block: []byte{1}}, {Block: []byte{2}}}
	var started [][]byte
	start := func(raw []byte) *prewarm_overlap { started = append(started, raw); return &prewarm_overlap{} }
	peeks := 0
	run := &sync_run{peek: func() []byte { peeks++; return []byte{3} }}
	run.next_overlap(cbs, 0, start)
	if peeks != 0 || len(started) != 1 || started[0][0] != 2 {
		t.Fatalf("inside a response the next block is used, no peek: peeks=%d started=%v", peeks, started)
	}
	run.next_overlap(cbs, 1, start)
	if peeks != 1 || len(started) != 2 || started[1][0] != 3 {
		t.Fatalf("the last block must overlap the peeked first block of the next response: peeks=%d started=%v", peeks, started)
	}
	run.peek = func() []byte { return nil }
	if run.next_overlap(cbs, 1, start) != nil || len(started) != 2 {
		t.Fatal("nothing peeked: no overlap")
	}
	var nilrun *sync_run
	if nilrun.next_overlap(cbs, 1, start) != nil || nilrun.take_prev() != nil {
		t.Fatal("a nil run (every non-sync path) never peeks")
	}
	nilrun.keep(&prewarm_overlap{}) // nil-safe
	r := &sync_run{}
	o := &prewarm_overlap{}
	r.keep(o)
	if r.take_prev() != o || r.take_prev() != nil {
		t.Fatal("take_prev returns the kept overlap once")
	}
}

// peek returns the next response's first block only once it has arrived, never waits, and never changes the order
// or content of what process gets.
func TestR24FetchPeekNeverWaitsNorReorders(t *testing.T) {
	ids := ids_n(12)
	slow := make(chan struct{})
	fetch := func(b []crypto.Hash) (o Objects, err error) {
		if b[0][0] == 4 {
			<-slow // the second response (ids 4..7) is late
		}
		for _, id := range b {
			o.CBlocks = append(o.CBlocks, Complete_Block{Block: append([]byte{}, id[:]...)})
		}
		return
	}
	var got []byte
	var peeked [][]byte
	resp := 0
	n, err := fetch_pipelined_peek(ids, func() (int, int) { return 4, 2 }, fetch, func(o Objects, peek func() []byte) error {
		for _, b := range o.CBlocks {
			got = append(got, b.Block[0])
		}
		t0 := time.Now()
		p := peek()
		if time.Since(t0) > 50*time.Millisecond {
			t.Error("peek waited for a response")
		}
		if resp == 0 {
			if p != nil {
				t.Error("peek returned a response that had not arrived")
			}
			close(slow)
		}
		if resp < 2 { // a response follows: it arrives eventually
			deadline := time.Now().Add(5 * time.Second)
			for ; p == nil && time.Now().Before(deadline); p = peek() {
				time.Sleep(time.Millisecond)
			}
		}
		peeked = append(peeked, p)
		resp++
		return nil
	})
	if err != nil || n != 12 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for i := range ids {
		if got[i] != ids[i][0] {
			t.Fatalf("order changed at %d: %v", i, got)
		}
	}
	if len(peeked) != 3 || peeked[0] == nil || peeked[0][0] != 4 || peeked[1] == nil || peeked[1][0] != 8 || peeked[2] != nil {
		t.Fatalf("peek must return the first block of the next response (4, 8) and nil after the last: %v", peeked)
	}
}

// peek hides a response that will be refused (error or short), and the refusal still happens.
func TestR24FetchPeekHidesBadResponse(t *testing.T) {
	fetch := func(b []crypto.Hash) (o Objects, err error) {
		if b[0][0] == 4 {
			o.CBlocks = []Complete_Block{{Block: []byte{0xaa}}} // short: 1 block for 4 ids
			return
		}
		for _, id := range b {
			o.CBlocks = append(o.CBlocks, Complete_Block{Block: append([]byte{}, id[:]...)})
		}
		return
	}
	var p []byte
	_, err := fetch_pipelined_peek(ids_n(8), func() (int, int) { return 4, 2 }, fetch, func(o Objects, peek func() []byte) error {
		time.Sleep(50 * time.Millisecond) // the bad response has arrived by now
		p = peek()
		return nil
	})
	if err == nil {
		t.Fatal("a short response must still end the fetch")
	}
	if p != nil {
		t.Fatal("peek exposed a short response")
	}
	fetch_err := func(b []crypto.Hash) (o Objects, err error) {
		if b[0][0] == 4 {
			return o, errors.New("x")
		}
		return fetch(b)
	}
	_, err = fetch_pipelined_peek(ids_n(8), func() (int, int) { return 4, 2 }, fetch_err, func(o Objects, peek func() []byte) error {
		time.Sleep(50 * time.Millisecond)
		p = peek()
		return nil
	})
	if err == nil || p != nil {
		t.Fatalf("an erroring response must be hidden from peek and still end the fetch: err=%v p=%v", err, p)
	}
}

// the locator: unchanged shape when every record reads; a record that cannot be read is skipped, never retried
// forever (upstream spun on it).
func TestR24ChainLocatorSkipsUnreadableRecord(t *testing.T) {
	rec := func(i int64) blockchain.TopoRecord {
		var r blockchain.TopoRecord
		r.BLOCK_ID[0], r.BLOCK_ID[1], r.State_Version = byte(i), byte(i>>8), 1
		return r
	}
	reads := 0
	read := func(bad int64) func(int64) (blockchain.TopoRecord, error) {
		return func(i int64) (blockchain.TopoRecord, error) {
			if reads++; reads > 10000 {
				panic("chain_locator keeps reading: endless loop")
			}
			if i == bad {
				return blockchain.TopoRecord{}, errors.New("short read")
			}
			return rec(i), nil
		}
	}
	ids, hs := chain_locator(100000, read(-1))
	if len(ids) != len(hs) || hs[0] != 100000 || hs[19] != 99981 || hs[20] != 99980-4 || len(ids) < 80 {
		t.Fatalf("locator shape changed: n=%d first=%v", len(ids), hs[:22])
	}
	full := len(ids)
	reads = 0
	ids, hs = chain_locator(100000, read(99995))
	for _, h := range hs {
		if h == 99995 {
			t.Fatal("an unreadable record was listed")
		}
	}
	if hs[0] != 100000 || len(ids) != len(hs) || len(ids) < full-1 {
		t.Fatalf("skip changed the rest of the locator: n=%d (full %d)", len(ids), full)
	}
	reads = 0
	if ids, _ := chain_locator(5, func(int64) (blockchain.TopoRecord, error) { reads++; return blockchain.TopoRecord{}, errors.New("x") }); len(ids) != 0 || reads != 5 {
		t.Fatalf("all records unreadable: %d ids, %d reads (want 0, 5)", len(ids), reads)
	}
	if ids, _ := chain_locator(5, func(int64) (blockchain.TopoRecord, error) { return blockchain.TopoRecord{}, nil }); len(ids) != 0 {
		t.Fatal("a clean record ends the locator")
	}
}
