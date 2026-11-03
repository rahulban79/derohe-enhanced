// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// r23c (rpcws): per-call item bounds for callers that are not this machine's own programs.
//
// The r21/r23 call buckets charge a flat cost per METHOD (GetTransaction 2 tokens, GetSC 2), but DERO.GetTransaction
// takes any number of txids and DERO.GetSC any number of keys, and one /ws message or /json_rpc body may be 32 MiB.
// Measured on a simulator chain (evidence/gettx_amplification.txt): 100,000 unknown txids in one call = 0.97 s CPU,
// 421 MB allocated, a 22.4 MB response from a 6.7 MB request; a full 32 MiB request holds ~500,000 txids (~5 s CPU,
// ~2 GB allocated) for the price of one 2-token call. A cross-site web page can open /ws on 127.0.0.1 (r20 allows it,
// rate-limited per call), so this reached a loopback-only node too.
//
// For a remote caller (non-loopback /json_rpc or /ws) and a cross-site (foreign Origin) websocket, a call may name at
// most MAX_REMOTE_TX_HASHES txids and MAX_REMOTE_SC_KEYS keys; more is an invalid-params error, never a silent clip.
// The node's own wallet sends at most SYNC_TX_BATCH = 32 txids per call (walletapi/sync_prefetch.go) and its fallback
// one, so no shipped client is affected. Loopback programs (wallets, explorers, miners on this machine) keep no limit.
// Nothing here is consensus-visible.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	dmetrics "github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

const MAX_REMOTE_TX_HASHES = 256
const MAX_REMOTE_SC_KEYS = 256

var param_bound_refused = dmetrics.Set.GetOrCreateCounter("rpc_param_bound_refused_total")

func tx_hashes_bound_error(n int) error {
	param_bound_refused.Inc()
	return &jrpc2.Error{Code: code.InvalidParams, Message: fmt.Sprintf("txs_hashes holds %d ids; at most %d per call for a remote caller", n, MAX_REMOTE_TX_HASHES)}
}

func sc_keys_bound_error(n int) error {
	param_bound_refused.Inc()
	return &jrpc2.Error{Code: code.InvalidParams, Message: fmt.Sprintf("%d keys requested; at most %d per call for a remote caller", n, MAX_REMOTE_SC_KEYS)}
}

func sc_keys(p rpc.GetSC_Params) int { return len(p.KeysUint64) + len(p.KeysString) + len(p.KeysBytes) }

// check_tx_hashes and check_sc_keys are the handler-side checks (websocket callers). r24: they also reserve the
// socket's in-flight items and charge item_cost (admit_call_items, r24_rpcws.go); the caller runs release at the end.
func check_tx_hashes(ctx context.Context, n int) (release func(), err error) {
	return admit_call_items(ctx, n, MAX_REMOTE_TX_HASHES, tx_hashes_bound_error)
}

func check_sc_keys(ctx context.Context, p rpc.GetSC_Params) (release func(), err error) {
	return admit_call_items(ctx, sc_keys(p), MAX_REMOTE_SC_KEYS, sc_keys_bound_error)
}

type bounded_params struct {
	TxHashes []json.RawMessage `json:"txs_hashes"`
}

type bounded_request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// remote_body_over_bounds reports the first request of a remote /json_rpc body (single or batch) that names more items
// than a remote caller may, as the error to answer. Params that do not decode as an object are left to the bridge.
func remote_body_over_bounds(body []byte) error {
	_, err := remote_body_items(body)
	return err
}

// request_items (r24 verify) is how many txids / SC keys one request names, decoded into the handler's OWN param
// type exactly as jrpc2 decodes it for the handler (jrpc2 base.go UnmarshalParams: json.Unmarshal, unknown keys
// ignored). Before, the params went only into one bounded_params struct holding all four lists for both methods, so
// a field the handler ignores but that did not decode as a list ("keysuint64":0 on a GetTransaction) failed the
// precheck decode and the call reached the bridge unbounded (evidence/verify_smuggle_base.txt, r23c too). When the
// handler type does not decode, the handler answers -32602 without running, so nothing is counted.
func request_items(method string, params json.RawMessage) (n int, err error) {
	if len(params) == 0 {
		return 0, nil
	}
	switch method {
	case "DERO.GetTransaction", "gettransactions", "DERO.GetSC", "getsc":
	default:
		return 0, nil
	}
	var bp bounded_params // the r23c txs_hashes check, kept: over MAX_REMOTE_TX_HASHES refuses either method's call
	if json.Unmarshal(params, &bp) == nil {
		if n := len(bp.TxHashes); n > MAX_REMOTE_TX_HASHES {
			return 0, tx_hashes_bound_error(n)
		}
	}
	switch method { // r24 verify: then what the handler itself will decode
	case "DERO.GetTransaction", "gettransactions":
		var p rpc.GetTransaction_Params
		if json.Unmarshal(params, &p) != nil {
			return 0, nil
		}
		if n = len(p.Tx_Hashes); n > MAX_REMOTE_TX_HASHES {
			return 0, tx_hashes_bound_error(n)
		}
	case "DERO.GetSC", "getsc":
		var p rpc.GetSC_Params
		if json.Unmarshal(params, &p) != nil {
			return 0, nil
		}
		if n = sc_keys(p); n > MAX_REMOTE_SC_KEYS {
			return 0, sc_keys_bound_error(n)
		}
	}
	return n, nil
}

// remote_body_items (r24 rpcws B29) is remote_body_over_bounds that also returns how many txids / SC keys each request
// of the body names (nil when none can), and refuses a body whose requests TOGETHER name more than
// MAX_REMOTE_BODY_ITEMS: before r24 the bound was per call only, so a batch of HTTP_MAX_BATCH_REMOTE calls of
// MAX_REMOTE_TX_HASHES txids each (65,536) passed (measured 5.3 s CPU, 470 MB allocated, evidence/b29_base_body_cost.txt).
// r24 verify: a batch is split per element as jrpc2 splits it (decode_requests), so one non-object element no longer
// hides the rest of the batch from the bound.
func remote_body_items(body []byte) ([]int, error) {
	if !body_may_name_bounded(body) { // r23c verify: most remote bodies (SendRawTransaction hex, GetInfo) skip the decode
		return nil, nil
	}
	var reqs []bounded_request
	if decode_requests(body, func(n int) { reqs = make([]bounded_request, n) }, func(i int, el []byte) error {
		return json.Unmarshal(el, &reqs[i])
	}) != nil {
		return nil, nil // not JSON: the bridge refuses the whole body without running any of it
	}
	var items []int
	total := 0
	for i, r := range reqs {
		n, err := request_items(r.Method, r.Params)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		if items == nil {
			items = make([]int, len(reqs))
		}
		items[i] = n
		if total += n; total > MAX_REMOTE_BODY_ITEMS { // r24 (B29): the body as a whole
			return nil, body_items_bound_error(total)
		}
	}
	return items, nil
}

// write_bound_error answers a refused remote body with one JSON-RPC error (the batch is refused whole, like admit_http).
func write_bound_error(w interface {
	Write([]byte) (int, error)
}, err error) {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": err})
	w.Write(body)
}

// answer_bound_refusal answers a refused remote /json_rpc body (r23c verify). The refusal happens before the bridge, so
// before this the abuse table never saw it: a remote key could send over-bound bodies (a 31 MiB one costs ~0.38 s of
// precheck CPU) forever without being scored or banned, while the same request on /ws is scored by observe_ws. Now it
// is scored as one InvalidParams reply, a banned key gets the ban answer, and an exempt or guard-off key is answered
// as before.
func answer_bound_refusal(w http.ResponseWriter, ip string, err error) {
	if !abuse_exempt(ip, false) && rpc_abuse.is_enabled() {
		now := time.Now()
		if d := rpc_abuse.banned_for(ip, now); d > 0 {
			write_abuse_http(w, abuse_banned, d)
			return
		}
		if d := rpc_abuse.observe(ip, code.InvalidParams, now); d > 0 {
			write_abuse_http(w, abuse_banned, d)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	write_bound_error(w, err)
}

// body_may_name_bounded (r23c verify): jrpc2 resolves method names by exact match (handler.Map, ServiceMap), so a body
// can reach GetTransaction or GetSC only if it spells one of the four names literally, or hides it in a JSON escape
// (any backslash). Bodies with neither skip the precheck decode: measured ~37 us for a 5 KB SendRawTransaction body,
// on top of the ~29 us batch_len + request_methods already spend (evidence/bound_precheck_bench.txt).
func body_may_name_bounded(b []byte) bool {
	if bytes.IndexByte(b, '\\') >= 0 {
		return true
	}
	for _, m := range bounded_method_literals {
		if bytes.Contains(b, m) {
			return true
		}
	}
	return false
}

var bounded_method_literals = [][]byte{[]byte("GetTransaction"), []byte("gettransactions"), []byte("GetSC"), []byte("getsc")}
