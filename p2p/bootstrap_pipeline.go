// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

// Pipelined TreeSection fetch for --fastsync (chain_bootstrap.go). Upstream asked for one tree section, wrote and
// committed it, and only then asked for the next: every one of the ~1,000+ balance-tree chunks and every one of the
// SC trees cost a full request/response round trip strictly in series with the local graviton commit.
//
// Here up to BOOTSTRAP_DEPTH requests are in flight while the previous response is written. Responses are still
// written and committed one at a time and in exactly the upstream order (chunk i before chunk i+1, SC tree j before
// SC tree j+1), so the resulting trees, the commit sequence and the in-memory resume point (state.Chunk) are the same
// as before. Only the transport overlaps. BOOTSTRAP_DEPTH=1 (and nested_depth(1) == 1) reproduces the old one-request-
// at-a-time behaviour.
//
// The server side is unchanged: upstream peers run every request on its own goroutine, and our own peers cap a
// connection at MAX_HEAVY_PER_CONNECTION (8) concurrent heavy handlers. The outer pipeline has up to depth requests in
// flight while it processes (it refills before the commit), so outer + nested_depth stays at
// MAX_HEAVY_PER_CONNECTION-1: one slot is always left for an INV-triggered GetObject on the same connection.
//
// Safety valves (r19 merge, verifier SYNC-1/SYNC-6): a pipelined request's timeout grows with the requests queued ahead
// of it (queueing on a bandwidth-limited link is not the peer's fault); after any fetch or process error the next
// bootstraps run at depth 1 until BOOTSTRAP_RECOVER_SECTIONS sections succeed in a row; and no new request is issued
// while BOOTSTRAP_BUFFER_MAX bytes of answers wait to be processed.
//
// Measured (r19 sync agent + verifier, --fastsync of mainnet state from an isolated loopback server, interleaved
// pairs): about 1.8-2.2x on the "Bootstrap in progress" -> "Bootstrap completed" console window and 1.7-2.3x on
// wall-clock boot_s at depth 7; on a 10 ms RTT link 987 s serial vs 284-307 s at depth 4 and 248 s at depth 7 (one
// non-interleaved control run).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/metrics"
	"golang.org/x/crypto/blake2s"
)

const BOOTSTRAP_DEPTH_MAX = MAX_HEAVY_PER_CONNECTION - 2

// default 4: on the 10 ms RTT link depth 4 already gave 284-307 s against 248 s at depth 7 (987 s serial), at about
// half the buffered memory and serving-peer load (verifier SYNC-6)
var BOOTSTRAP_DEPTH = env_int("DERO_BOOTSTRAP_DEPTH", 4, 1, BOOTSTRAP_DEPTH_MAX)

// nested_depth is the depth for a pipeline run from inside another one's process step (a huge SC tree fetched in
// chunks while the SC-tree pipeline waits). The outer pipeline then has up to depth requests in flight (it refills
// before processing), so depth + nested_depth(depth) <= MAX_HEAVY_PER_CONNECTION-1: a patched peer's per-connection cap
// is never reached and one slot stays free for an INV-triggered GetObject. nested_depth(1) == 1.
func nested_depth(depth int) int {
	n := MAX_HEAVY_PER_CONNECTION - 1 - depth
	if n > depth {
		n = depth
	}
	if n < 1 {
		n = 1
	}
	return n
}

// BOOTSTRAP_RECOVER_SECTIONS: after a bootstrap fetch or process error (a timeout, a refused or foreign answer), the
// following bootstraps run at depth 1 until this many sections in a row succeeded (like the r18 sync_size_tracker).
const BOOTSTRAP_RECOVER_SECTIONS = 256

var bootstrap_recover atomic.Int64 // sections still to succeed at depth 1 before the configured depth returns

func bootstrap_depth() int {
	if bootstrap_recover.Load() > 0 {
		return 1
	}
	return BOOTSTRAP_DEPTH
}

func bootstrap_failed() {
	bootstrap_recover.Store(BOOTSTRAP_RECOVER_SECTIONS)
	metrics.Set.GetOrCreateCounter("p2p_bootstrap_fallbacks_total").Inc()
}

func bootstrap_section_ok() {
	for {
		v := bootstrap_recover.Load()
		if v <= 0 || bootstrap_recover.CompareAndSwap(v, v-1) {
			return
		}
	}
}

// BOOTSTRAP_BUFFER_MAX bounds the answers waiting to be processed: no new request is issued above it (the head of
// line is always requested), so a bootstrap peer sending maximum-size frames cannot make us hold depth of them.
const BOOTSTRAP_BUFFER_MAX = 64 << 20

func section_bytes(r *Response_Tree_Section_Struct) (n int64) {
	for i := range r.Keys {
		n += int64(len(r.Keys[i]))
	}
	for i := range r.Values {
		n += int64(len(r.Values[i]))
	}
	return n
}

// pipelined_timeout: a request issued behind queued others waits for their answers on the same link first
func pipelined_timeout(method string, queued int) time.Duration {
	return call_timeout(method) * time.Duration(queued+1)
}

type section_result struct {
	resp Response_Tree_Section_Struct
	err  error
}

// fetch_sections_ordered requests the sections req(0) .. req(n-1) with up to depth requests outstanding and hands
// each response to process strictly in index order. It stops at the first fetch or process error; requests still in
// flight then finish into buffered channels and are dropped. fetch is the transport (connection.call in production,
// a fake in tests); queued is how many requests were ahead of this one when it was issued.
func fetch_sections_ordered(n, depth int, req func(i int) Request_Tree_Section_Struct,
	fetch func(r Request_Tree_Section_Struct, queued int) (Response_Tree_Section_Struct, error),
	process func(i int, resp *Response_Tree_Section_Struct) error) error {
	if depth < 1 {
		depth = 1
	}
	next := 0
	var inflight []chan section_result
	var buffered atomic.Int64 // bytes of answers received and not yet processed
	room := func() bool {
		return next < n && len(inflight) < depth && (len(inflight) == 0 || buffered.Load() < BOOTSTRAP_BUFFER_MAX)
	}
	issue := func() {
		r, queued := req(next), len(inflight)
		next++
		ch := make(chan section_result, 1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					ch <- section_result{err: fmt.Errorf("tree section fetch panic: %v", p)}
				}
			}()
			resp, err := fetch(r, queued)
			buffered.Add(section_bytes(&resp))
			ch <- section_result{resp: resp, err: err}
		}()
		inflight = append(inflight, ch)
	}
	for i := 0; i < n; i++ {
		for room() {
			issue()
		}
		t0 := time.Now()
		res := <-inflight[0]
		inflight = inflight[1:]
		metrics.Set.GetOrCreateFloatCounter("p2p_bootstrap_wait_seconds_total").Add(time.Since(t0).Seconds())
		if res.err != nil {
			return res.err
		}
		for room() { // keep the pipe full before spending time on the commit
			issue()
		}
		t1 := time.Now()
		err := process(i, &res.resp)
		buffered.Add(-section_bytes(&res.resp))
		metrics.Set.GetOrCreateFloatCounter("p2p_bootstrap_process_seconds_total").Add(time.Since(t1).Seconds())
		metrics.Set.GetOrCreateCounter("p2p_bootstrap_sections_total").Inc()
		if err != nil {
			return err
		}
	}
	return nil
}

// the production transport for fetch_sections_ordered: the deadline covers the requests queued ahead of this one
func (connection *Connection) fetch_tree_section(req Request_Tree_Section_Struct, queued int) (resp Response_Tree_Section_Struct, err error) {
	fill_common(&req.Common)
	err = connection.call_timeout("Peer.TreeSection", pipelined_timeout("Peer.TreeSection", queued), req, &resp)
	return
}

// bootstrap_sections is fetch_sections_ordered over this connection with the depth-1 fallback bookkeeping
func (connection *Connection) bootstrap_sections(n, depth int, req func(i int) Request_Tree_Section_Struct,
	process func(i int, resp *Response_Tree_Section_Struct) error) error {
	err := fetch_sections_ordered(n, depth, req, connection.fetch_tree_section, func(i int, resp *Response_Tree_Section_Struct) error {
		if err := process(i, resp); err != nil {
			return err
		}
		bootstrap_section_ok()
		return nil
	})
	if err != nil {
		bootstrap_failed()
	}
	return err
}

// apply_section checks an answer (section_check) and only then writes its pairs; every bootstrap write of a fetched
// section goes through it (chain_bootstrap.go), the SC_META chunk aside, which is checked before its SC trees are
// fetched.
func apply_section(section []byte, path_length uint64, resp *Response_Tree_Section_Struct, put func(k, v []byte)) error {
	if err := section_check(section, path_length, resp); err != nil {
		return err
	}
	for i := range resp.Keys {
		put(resp.Keys[i], resp.Values[i])
	}
	return nil
}

// section_path is the request path chain_bootstrap.go has always used for chunk i: the bit-reversed index, so that
// chunk i covers the keys whose blake2s key-hash starts with the low path_length bits of i, most significant first.
func section_path(i int64) []byte {
	var section [8]byte
	binary.BigEndian.PutUint64(section[:], bits.Reverse64(uint64(i)))
	return section[:]
}

// section_check validates a TreeSection answer before anything is written: keys and values pair up, and every key
// lies inside the requested section, i.e. the first path_length bits of its graviton key-hash (blake2s-256,
// graviton/hash.go) equal the request path (graviton/special.go SpecialFirst walks exactly those bits). An honest
// peer's answer always passes; upstream wrote whatever came back, so a peer could plant keys anywhere in the tree.
// This does not prove the values (DERO blocks carry no state root), it only confines what one answer can touch.
func section_check(section []byte, path_length uint64, resp *Response_Tree_Section_Struct) error {
	if len(resp.Keys) != len(resp.Values) {
		return fmt.Errorf("mismatched key and value count")
	}
	if path_length == 0 {
		return nil
	}
	if path_length > uint64(len(section))*8 {
		return fmt.Errorf("section path too short")
	}
	for _, k := range resp.Keys {
		h := blake2s.Sum256(k)
		for b := uint64(0); b < path_length; b++ {
			if isbit(h[:], b) != isbit(section, b) {
				metrics.Set.GetOrCreateCounter("p2p_bootstrap_foreign_keys_total").Inc()
				return fmt.Errorf("peer returned key %x outside the requested tree section", k)
			}
		}
	}
	return nil
}

// same bit order as graviton's isBitSet (node.go): bit 0 is the most significant bit of byte 0
func isbit(b []byte, index uint64) bool {
	return b[index/8]&(1<<(7-index%8)) != 0
}

// BOOTSTRAP_PREFILL (env DERO_BOOTSTRAP_PREFILL=0 disables): after the state trees are in, bootstrap marks every
// topoheight 0..T as "state present, block pruned" by calling Topo_store.Write once per topoheight, i.e. one 48-byte
// pwrite per record: ~7.8 million syscalls on mainnet. The records are all identical, so prefill_topo writes records
// 0..T-1 with large sequential writes instead, reads samples back through the chain's own Topo_store.Read, and only
// then lets the store write the last record itself (so its in-memory last_state_version ends as before). The file
// bytes are the same as the per-record loop's; on any error or mismatch bootstrap runs the original loop.
var BOOTSTRAP_PREFILL = os.Getenv("DERO_BOOTSTRAP_PREFILL") != "0"

const prefill_batch = 1 << 16 // records per write: 3 MiB

// topo_record encodes one record exactly like storetopofs.Write (blockchain/storetopo.go): blid, then the state
// version and the height as little-endian uint64.
func topo_record(blid [32]byte, version uint64, height int64) []byte {
	rec := make([]byte, blockchain.TOPORECORD_SIZE)
	copy(rec, blid[:])
	binary.LittleEndian.PutUint64(rec[32:], version)
	binary.LittleEndian.PutUint64(rec[40:], uint64(height))
	return rec
}

// prefill_topo writes records 0..count-1 as (zero blid, version, height 0) into the existing topo file at path.
func prefill_topo(path string, count int64, version uint64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0) // never creates: the chain opened (and created) it at startup
	if err != nil {
		return err
	}
	rec := topo_record([32]byte{}, version, 0)
	buf := bytes.Repeat(rec, prefill_batch)
	for off := int64(0); off < count; off += prefill_batch {
		n := count - off
		if n > prefill_batch {
			n = prefill_batch
		}
		if _, err = f.WriteAt(buf[:n*blockchain.TOPORECORD_SIZE], off*blockchain.TOPORECORD_SIZE); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// topo_store is the part of the chain's Topo_store that bootstrap uses
type topo_store interface {
	Read(index int64) (blockchain.TopoRecord, error)
	Write(index int64, blid [32]byte, state_version uint64, height int64) error
}

// write_bootstrap_topo marks topoheights 0..last as committed at version, with no block (pruned). It tries the
// prefill and verifies it through the store; whatever goes wrong it falls back to the original per-record loop,
// which rewrites every record, so the outcome never depends on the fast path.
func write_bootstrap_topo(store topo_store, path string, last int64, version uint64) (fast bool) {
	var zerohash [32]byte
	if BOOTSTRAP_PREFILL && last > 0 && prefill_topo(path, last, version) == nil {
		fast = true
		for _, i := range []int64{0, last / 2, last - 1} {
			if r, err := store.Read(i); err != nil || r.BLOCK_ID != zerohash || r.State_Version != version || r.Height != 0 {
				fast = false
				metrics.Set.GetOrCreateCounter("p2p_bootstrap_prefill_fallbacks_total").Inc()
				break
			}
		}
	}
	if fast {
		store.Write(last, zerohash, version, 0)
		return true
	}
	for i := int64(0); i <= last; i++ {
		store.Write(i, zerohash, version, 0) // commit everything
	}
	return false
}
