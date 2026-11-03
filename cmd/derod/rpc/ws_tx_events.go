// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r21 (rpcws): websocket pushes that wallets and explorers otherwise poll for.
//
//   - DERO.WatchTx {txids, confirmations, remove}: the socket is sent a "TxStatus" event whenever the state of a
//     watched txid changes (unknown -> pool -> mined, or back after a reorg) and, once mined, at every new
//     confirmation until it reaches `confirmations` (default 10); then the watch ends by itself. The states are
//     exactly DERO.GetTxStatus's (tx_status), and WatchTx answers with the current status, so a client that watches
//     and then waits for events cannot miss the transition that happened in between.
//   - DERO.Subscribe {"events":["TxPool"]}: a "TxPool" event {added, removed, pool_size, truncated} each time the
//     mempool's txid set changed (checked every TX_EVENT_INTERVAL and at every block). The first check after the
//     first subscriber only takes the baseline: a client gets the starting set with DERO.GetTxPool.
//
// Cost bounds (nothing here touches consensus state, it only reads the stores and pools as GetTxStatus does):
//   - at most WATCH_MAX_PER_SOCKET watched txids per socket and WATCH_MAX_TOTAL on the node; more is an error;
//   - cross-site (foreign Origin) sockets together hold at most WATCH_MAX_FOREIGN of WATCH_MAX_TOTAL, so one page
//     cannot fill the node's table and lock local wallets out (r21 merge, RPCWS21-B fix);
//   - a watch whose txid stays "unknown" (in no pool and no block) for WATCH_UNKNOWN_TTL ends with one last push that
//     lists it under "expired": random txids cannot be re-checked every second forever (r21 merge, RPCWS21-B fix);
//   - each check computes the status of each distinct watched txid ONCE, however many sockets watch it; on the 1 s
//     timer only txids that are not yet mined are re-checked (a mined tx changes only when a block arrives);
//   - a TxPool event lists at most TXPOOL_EVENT_MAX txids per direction (truncated=true says to re-read the pool);
//   - with no watch and no TxPool subscriber a check is one atomic load plus one walk of the client map (any_subscriber);
//   - pushes use their own in-flight flag (busy_tx) or queue (q_pool, r23c push_queue) and the write deadline of every
//     /ws push, so a client that does not read is skipped and later closed, never waited for. A skipped TxStatus
//     client keeps its old states, so it is sent the change at the next check instead of losing it; a TxPool diff
//     waits behind the one being written (r23c: before, it was dropped and its txids never reached that client).

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	dmetrics "github.com/deroproject/derohe/metrics"
)

const WATCH_MAX_PER_SOCKET = 64
const WATCH_MAX_TOTAL = 4096
const WATCH_MAX_FOREIGN = 512 // r21 merge: foreign sockets' share of WATCH_MAX_TOTAL

// WATCH_UNKNOWN_TTL: a watch whose txid has been "unknown" this long is expired. A broadcast tx reaches the pool in
// seconds; 10 minutes covers a wallet that watches before it sends.
var WATCH_UNKNOWN_TTL = 10 * time.Minute

const WATCH_DEFAULT_CONFIRMATIONS = 10
const WATCH_MAX_CONFIRMATIONS = 128
const TXPOOL_EVENT_MAX = 256

var TX_EVENT_INTERVAL = time.Second

var watch_total int64   // atomic: watched txids over all sockets
var watch_foreign int64 // atomic: the part of watch_total held by foreign sockets

var tx_status_checks = dmetrics.Set.GetOrCreateCounter("rpc_tx_events_status_checks_total")
var tx_events_sent = dmetrics.Set.GetOrCreateCounter("rpc_tx_events_sent_total")

func init() {
	dmetrics.Set.NewGauge("rpc_watched_txids", func() float64 { return float64(atomic.LoadInt64(&watch_total)) })
}

type watch_entry struct {
	state  string    // last state sent (or answered by WatchTx)
	conf   int64     // last confirmations sent
	target int64     // the watch ends once mined with this many confirmations
	since  time.Time // when state last became "unknown" (WATCH_UNKNOWN_TTL)
}

func (e *watch_entry) done() bool { return e.state == "mined" && e.conf >= e.target }

type WatchTx_Params struct {
	TxIDs         []string `json:"txids"`
	Confirmations int64    `json:"confirmations"` // 0 = WATCH_DEFAULT_CONFIRMATIONS, at most WATCH_MAX_CONFIRMATIONS
	Remove        bool     `json:"remove"`        // stop watching these txids
}

type WatchTx_Result struct {
	Watching int        `json:"watching"` // txids this socket watches after the call
	Txs      []TxStatus `json:"txs"`      // current status of every txid in the call (empty for remove)
	Status   string     `json:"status"`
}

type TxStatus_Event struct {
	TopoHeight int64      `json:"topoheight"`
	Txs        []TxStatus `json:"txs"`
	Expired    []string   `json:"expired,omitempty"` // watches ended because the txid stayed unknown WATCH_UNKNOWN_TTL
}

type TxPool_Event struct {
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	PoolSize  int      `json:"pool_size"`
	Truncated bool     `json:"truncated"`
}

func invalid_params(format string, a ...interface{}) error {
	return &jrpc2.Error{Code: code.InvalidParams, Message: fmt.Sprintf(format, a...)}
}

// parse_watch_ids validates and dedupes the txids of a WatchTx call.
func parse_watch_ids(ids []string) ([]crypto.Hash, error) {
	if len(ids) == 0 || len(ids) > WATCH_MAX_PER_SOCKET {
		return nil, invalid_params("txids must hold 1..%d transaction ids, got %d", WATCH_MAX_PER_SOCKET, len(ids))
	}
	seen := map[crypto.Hash]bool{}
	var out []crypto.Hash
	for _, id := range ids {
		if len(id) != 64 {
			return nil, invalid_params("invalid txid %q", id)
		}
		h := crypto.HashHexToHash(id)
		if h.IsZero() {
			return nil, invalid_params("invalid txid %q", id)
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out, nil
}

func watch_target(conf int64) (int64, error) {
	if conf == 0 {
		return WATCH_DEFAULT_CONFIRMATIONS, nil
	}
	if conf < 1 || conf > WATCH_MAX_CONFIRMATIONS {
		return 0, invalid_params("confirmations must be 1..%d, got %d", WATCH_MAX_CONFIRMATIONS, conf)
	}
	return conf, nil
}

// watch_apply adds (or removes) watches on one socket and answers with the current status of each txid.
func watch_apply(c *ws_client, ids []crypto.Hash, target int64, remove bool, src tx_status_source, top int64) (WatchTx_Result, error) {
	c.watch_mu.Lock()
	defer c.watch_mu.Unlock()
	res := WatchTx_Result{Txs: []TxStatus{}, Status: "OK"}
	if c.watch_closed { // a call still running while its socket closes must not leak WATCH_MAX_TOTAL
		return res, &jrpc2.Error{Code: code.InvalidRequest, Message: "websocket is closing"}
	}
	if remove {
		for _, h := range ids {
			if _, ok := c.watch[h]; ok {
				delete(c.watch, h)
				c.watch_release(1)
			}
		}
		res.Watching = len(c.watch)
		return res, nil
	}
	fresh := int64(0)
	for _, h := range ids {
		if _, ok := c.watch[h]; !ok {
			fresh++
		}
	}
	if len(c.watch)+int(fresh) > WATCH_MAX_PER_SOCKET {
		return res, invalid_params("a socket may watch at most %d txids (watching %d, adding %d)", WATCH_MAX_PER_SOCKET, len(c.watch), fresh)
	}
	if c.foreign && atomic.AddInt64(&watch_foreign, fresh) > WATCH_MAX_FOREIGN {
		atomic.AddInt64(&watch_foreign, -fresh)
		return res, &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: fmt.Sprintf("cross-site websockets already watch %d txids; retry later", WATCH_MAX_FOREIGN)}
	}
	if atomic.AddInt64(&watch_total, fresh) > WATCH_MAX_TOTAL {
		atomic.AddInt64(&watch_total, -fresh)
		if c.foreign {
			atomic.AddInt64(&watch_foreign, -fresh)
		}
		return res, &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: fmt.Sprintf("the node already watches %d txids for websockets; retry later", WATCH_MAX_TOTAL)}
	}
	if c.watch == nil {
		c.watch = map[crypto.Hash]*watch_entry{}
	}
	now := time.Now()
	apply := func(*TxStatus) {}
	if fs, ok := src.(tx_finality_source); ok {
		apply, _, _, _ = finality(src, fs.chain_height()) // r23: same fields as GetTxStatus
	}
	for _, h := range ids {
		s := tx_status(h.String(), top, src)
		apply(&s)
		tx_status_checks.Inc()
		res.Txs = append(res.Txs, s)
		e := &watch_entry{state: s.State, conf: s.Confirmations, target: target, since: now}
		if old, ok := c.watch[h]; ok && old.state == "unknown" && s.State == "unknown" {
			e.since = old.since // re-watching does not restart the unknown clock
		}
		if e.done() { // already as confirmed as asked: answered, nothing left to watch
			delete(c.watch, h)
			c.watch_release(1) // it was counted, as fresh or as an existing entry
			continue
		}
		c.watch[h] = e // re-watching keeps one entry (counted once) with the new target
	}
	res.Watching = len(c.watch)
	return res, nil
}

// watch_release returns n of c's watches to the node totals (caller holds c.watch_mu).
func (c *ws_client) watch_release(n int64) {
	atomic.AddInt64(&watch_total, -n)
	if c.foreign {
		atomic.AddInt64(&watch_foreign, -n)
	}
}

// drop_watches releases a closing socket's share of WATCH_MAX_TOTAL.
func (c *ws_client) drop_watches() {
	c.watch_mu.Lock()
	c.watch_release(int64(len(c.watch)))
	c.watch = nil
	c.watch_closed = true
	c.watch_mu.Unlock()
}

// WatchTx: see the file comment.
func WatchTx(ctx context.Context, p WatchTx_Params) (result WatchTx_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = rpc_internal_error(r)
		}
	}()
	c := ws_client_of(ctx)
	if c == nil {
		return result, &jrpc2.Error{Code: code.InvalidRequest, Message: "WatchTx needs a websocket connection (/ws); over HTTP poll DERO.GetTxStatus"}
	}
	ids, err := parse_watch_ids(p.TxIDs)
	if err != nil {
		return result, err
	}
	target, err := watch_target(p.Confirmations)
	if err != nil {
		return result, err
	}
	return watch_apply(c, ids, target, p.Remove, chain_tx_status{}, chain.Load_TOPO_HEIGHT())
}

// ---- the check loop ----------------------------------------------------------------------------------------------

var tx_events_kick = make(chan struct{}, 1)

// kick_tx_events asks for a full check now (a block arrived). Never blocks.
func kick_tx_events() {
	select {
	case tx_events_kick <- struct{}{}:
	default:
	}
}

type tx_events struct {
	pool_prev map[crypto.Hash]struct{} // nil = no baseline (no TxPool subscriber at the last check)
}

// pool_diff returns the sorted txids added to and removed from prev, each clipped to TXPOOL_EVENT_MAX.
func pool_diff(prev map[crypto.Hash]struct{}, cur map[crypto.Hash]struct{}) (ev TxPool_Event, changed bool) {
	ev.Added, ev.Removed = []string{}, []string{}
	for h := range cur {
		if _, ok := prev[h]; !ok {
			ev.Added = append(ev.Added, h.String())
		}
	}
	for h := range prev {
		if _, ok := cur[h]; !ok {
			ev.Removed = append(ev.Removed, h.String())
		}
	}
	changed = len(ev.Added)+len(ev.Removed) > 0
	sort.Strings(ev.Added)
	sort.Strings(ev.Removed)
	if len(ev.Added) > TXPOOL_EVENT_MAX {
		ev.Added, ev.Truncated = ev.Added[:TXPOOL_EVENT_MAX], true
	}
	if len(ev.Removed) > TXPOOL_EVENT_MAX {
		ev.Removed, ev.Truncated = ev.Removed[:TXPOOL_EVENT_MAX], true
	}
	ev.PoolSize = len(cur)
	return
}

// tick runs one check. full: a block arrived, so mined txids are re-checked too.
func (te *tx_events) tick(full bool, src tx_status_source, top func() int64, list_pool func() []crypto.Hash) {
	if any_subscriber(SUB_TXPOOL) {
		cur := map[crypto.Hash]struct{}{}
		for _, h := range list_pool() {
			cur[h] = struct{}{}
		}
		if te.pool_prev != nil {
			if ev, changed := pool_diff(te.pool_prev, cur); changed {
				// r23c: queued per client (push_queue); a diff written after dropped ones says truncated=true (re-read the pool)
				notify_clients_q(SUB_TXPOOL, func(c *ws_client) *push_queue { return &c.q_pool }, func(s *jrpc2.Server, c *ws_client, lost bool) error {
					tx_events_sent.Inc()
					e := ev
					e.Truncated = e.Truncated || lost
					return s.Notify(context.Background(), "TxPool", e)
				})
			}
		}
		te.pool_prev = cur
	} else {
		te.pool_prev = nil
	}

	if atomic.LoadInt64(&watch_total) == 0 {
		return
	}
	// 1. the distinct txids due for a check, over all sockets
	due := map[crypto.Hash]struct{}{}
	client_connections.Range(func(k, v interface{}) bool {
		c := v.(*ws_client)
		c.watch_mu.Lock()
		for h, e := range c.watch {
			if full || e.state != "mined" {
				due[h] = struct{}{}
			}
		}
		c.watch_mu.Unlock()
		return true
	})
	if len(due) == 0 {
		return
	}
	// 2. one status per distinct txid
	t := top()
	now := time.Now()
	st := make(map[crypto.Hash]TxStatus, len(due))
	apply := func(*TxStatus) {}
	if fs, ok := src.(tx_finality_source); ok {
		apply, _, _, _ = finality(src, fs.chain_height()) // r23: pushes carry height/final like GetTxStatus
	}
	for h := range due {
		s := tx_status(h.String(), t, src)
		apply(&s)
		st[h] = s
	}
	tx_status_checks.Add(len(due))
	// 3. per socket: the changes, one push each
	client_connections.Range(func(k, v interface{}) bool {
		s, c := k.(*jrpc2.Server), v.(*ws_client)
		if !atomic.CompareAndSwapInt32(&c.busy_tx, 0, 1) {
			ws_push_skipped.Inc() // its entries keep their old state: the change is sent at the next check
			return true
		}
		changes, expired := watch_changes(c, st, now)
		if len(changes) == 0 && len(expired) == 0 {
			atomic.StoreInt32(&c.busy_tx, 0)
			return true
		}
		if changes == nil {
			changes = []TxStatus{}
		}
		ev := TxStatus_Event{TopoHeight: t, Txs: changes, Expired: expired}
		go func() {
			defer atomic.StoreInt32(&c.busy_tx, 0)
			defer globals.Recover(2)
			tx_events_sent.Inc()
			if err := s.Notify(context.Background(), "TxStatus", ev); err != nil && c.conn != nil {
				c.conn.Close()
			}
		}()
		return true
	})
}

// watch_changes records the new states of one socket's watches and returns those that changed (sorted by txid).
// A watch that reached its confirmation target is sent one last time and removed; one whose txid stayed "unknown"
// for WATCH_UNKNOWN_TTL is removed and returned in expired (sorted).
func watch_changes(c *ws_client, st map[crypto.Hash]TxStatus, now time.Time) (changes []TxStatus, expired []string) {
	c.watch_mu.Lock()
	defer c.watch_mu.Unlock()
	for h, e := range c.watch {
		s, ok := st[h]
		if !ok {
			continue
		}
		if s.State == "unknown" && e.state == "unknown" && now.Sub(e.since) >= WATCH_UNKNOWN_TTL {
			expired = append(expired, s.TxID)
			delete(c.watch, h)
			c.watch_release(1)
			continue
		}
		if s.State == e.state && (s.State != "mined" || s.Confirmations == e.conf) {
			continue
		}
		changes = append(changes, s)
		if s.State == "unknown" {
			e.since = now // back to unknown (evicted, reorged out): the TTL starts again
		}
		e.state, e.conf = s.State, s.Confirmations
		if e.done() {
			delete(c.watch, h)
			c.watch_release(1)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].TxID < changes[j].TxID })
	sort.Strings(expired)
	return
}

// tx_events_loop runs the checks: every TX_EVENT_INTERVAL, and at once (full) when a block arrives. It reads only
// the chain it was started with and ends with its RPC server (exit closed by RPCServer_Stop).
func tx_events_loop(c *blockchain.Blockchain, exit chan bool) {
	if c == nil {
		return
	}
	var te tx_events
	src := chain_tx_status{c: c}
	t := time.NewTicker(TX_EVENT_INTERVAL)
	defer t.Stop()
	for {
		full := false
		select {
		case <-exit:
			return
		case <-t.C:
		case <-tx_events_kick:
			full = true
		}
		func() {
			defer globals.Recover(2)
			te.tick(full, src, c.Load_TOPO_HEIGHT, c.Mempool.Mempool_List_TX)
		}()
	}
}
