// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// r24 (rpcws): two RPC-edge fixes. Nothing here is consensus-visible.
//
// B29, item-weighted cost and a per-body total. r23c bounded ONE call to MAX_REMOTE_TX_HASHES txids, but the call
// buckets charge a flat cost per method (GetTransaction 2 tokens), so one remote /json_rpc batch of
// HTTP_MAX_BATCH_REMOTE x MAX_REMOTE_TX_HASHES = 65,536 txids cost 512 tokens of a 2,000 burst and measured 5.3 s
// CPU / 470 MB allocated on a simulator chain (evidence/b29_base_body_cost.txt), repeatable every ~2.6 s per key. Now
//   - a remote /json_rpc body may name at most MAX_REMOTE_BODY_ITEMS txids + SC keys in all its requests together
//     (more is one -32602 refusal, scored like the r23c per-call one);
//   - every remote call pays item_cost(n) = ceil(n / REMOTE_ITEMS_PER_TOKEN) extra tokens for the n items it names,
//     on /json_rpc (admit_http) and on remote and cross-site websockets (admit_call_items, from its handler);
//   - a remote or cross-site websocket may have at most MAX_REMOTE_BODY_ITEMS items in calls running at once (a ws
//     message batch runs in parallel), so one message cannot do what one HTTP body may not.
// The shipped wallet names at most SYNC_TX_BATCH = 32 txids per call (walletapi/sync_prefetch.go): 2 + 4 tokens.
// Loopback programs are never charged, bounded or counted (the r23c rule).
//
// B38, JSON-RPC over HTTP without "Content-Type: application/json". The jhttp bridge (vendored jrpc2, unchanged since
// the testnet releases: vendor/github.com/creachadair/jrpc2/jhttp/bridge.go:58-65) answers a non-POST with 405 and
// any Content-Type other than the exact string "application/json" with 415, both with an EMPTY body. `curl -s` shows
// nothing, so on 2026-11-02 it read as "an empty answer" (evidence/b38_live_content_type.txt). Upstream behaviour, not
// a regression, and in part a useful one: requiring a non-CORS-safelisted type means a cross-site page cannot send a
// "simple" (unpreflighted) request; rpc_guard already refuses a foreign Origin on /json_rpc (403). But the exact
// match also refused "application/json; charset=utf-8" (what many HTTP libraries send) and "Application/JSON".
// Now the media type is parsed (RFC 9110: case-insensitive, parameters allowed); application/json with no charset or
// charset=utf-8 is served, and the header is normalised so the bridge accepts it. Everything else (none, text/plain,
// form types, another charset) is still refused, now with a JSON-RPC error body (-32600) that says what to send, and
// a GET/PUT/... gets 405 with Allow: POST and the same kind of body. Still-refused types keep the CSRF property.

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"

	dmetrics "github.com/deroproject/derohe/metrics"
)

// MAX_REMOTE_BODY_ITEMS: txids + SC keys one remote body (or one remote/cross-site socket at once) may name. Four
// full per-call bounds; measured 33 ms CPU for 1,024 unknown txids in one body (evidence/b29_base_body_cost.txt).
const MAX_REMOTE_BODY_ITEMS = 4 * MAX_REMOTE_TX_HASHES

// REMOTE_ITEMS_PER_TOKEN: items one extra bucket token pays for. 256 txids = 2 + 32 tokens, so a key's sustained
// 200 tokens/s (ABUSE_DEFAULT_RATE) buys ~1,500 txids/s instead of ~25,600.
const REMOTE_ITEMS_PER_TOKEN = 8

// item_cost: extra tokens for a call naming n items (0 for none).
func item_cost(n int) int {
	if n <= 0 {
		return 0
	}
	return (n + REMOTE_ITEMS_PER_TOKEN - 1) / REMOTE_ITEMS_PER_TOKEN
}

// ws_items_inflight_max is MAX_REMOTE_BODY_ITEMS; a variable only so a test can lower it (read atomically).
var ws_items_inflight_max int64 = MAX_REMOTE_BODY_ITEMS

var body_items_refused = dmetrics.Set.GetOrCreateCounter("rpc_param_bound_body_refused_total")
var ws_items_inflight_refused = dmetrics.Set.GetOrCreateCounter("rpc_ws_items_inflight_refused_total")

func body_items_bound_error(n int) error {
	param_bound_refused.Inc()
	body_items_refused.Inc()
	return &jrpc2.Error{Code: code.InvalidParams, Message: fmt.Sprintf("request body names %d txids/keys in all; at most %d per body for a remote caller", n, MAX_REMOTE_BODY_ITEMS)}
}

func no_release() {}

// admit_call_items is the handler-side check of a call naming n items (txids or SC keys) with per-call bound max.
// For a loopback caller (or the HTTP bridge, already checked by remote_body_items) it costs nothing. For a remote or
// cross-site websocket it refuses n > max (-32602, the r23c bound), then reserves n items of the socket's in-flight
// budget and charges item_cost(n) tokens to the socket's bucket(s). The caller runs release when the call ends.
func admit_call_items(ctx context.Context, n, max int, bound_error func(int) error) (release func(), err error) {
	if n <= 0 {
		return no_release, nil
	}
	return admit_client_items(ws_client_of(ctx), n, max, bound_error)
}

// admit_client_items is admit_call_items for the socket c (nil = not a websocket).
func admit_client_items(c *ws_client, n, max int, bound_error func(int) error) (release func(), err error) {
	if n <= 0 || c == nil || (c.abuse_key == "" && !c.foreign) {
		return no_release, nil
	}
	if n > max {
		return no_release, bound_error(n)
	}
	if c.items_held.Add(int64(n)) > atomic.LoadInt64(&ws_items_inflight_max) {
		c.items_held.Add(-int64(n))
		ws_items_inflight_refused.Inc()
		return no_release, &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: fmt.Sprintf("rate limited: more than %d txids/keys in calls running at once on this socket", MAX_REMOTE_BODY_ITEMS)}
	}
	release = func() { c.items_held.Add(-int64(n)) }
	extra, now := item_cost(n), time.Now()
	if c.abuse_key != "" {
		if v, d := rpc_abuse.charge(c.abuse_key, extra, now); v != abuse_ok {
			release()
			if v == abuse_banned {
				c.close_banned()
			}
			return no_release, abuse_error(v, d)
		}
	}
	if c.foreign && c.limiter != nil {
		if !c.limiter.AllowN(now, extra) || (c.node_limiter != nil && !c.node_limiter.AllowN(now, extra)) {
			release()
			foreign_rate_limited.Inc()
			return no_release, &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: "rate limited: too many txids/keys from this cross-site (foreign Origin) websocket; retry later"}
		}
	}
	return release, nil
}

// charge spends tokens from key's bucket (and its aggregate's, for an untrusted key) without counting a call: the
// item part of a websocket call whose base cost admit already charged. A short bucket is a refusal (scored like one).
func (t *abuse_table) charge(key string, tokens int, now time.Time) (abuse_verdict, time.Duration) {
	if tokens <= 0 {
		return abuse_ok, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.enabled {
		return abuse_ok, 0
	}
	e := t.entry(key, now)
	e.last_seen = now
	if now.Before(e.banned_until) {
		abuse_refused_banned.Inc()
		return abuse_banned, e.banned_until.Sub(now)
	}
	var g *abuse_entry
	if !trusted_locked(e, now) {
		g = t.agg_locked(e, now)
	}
	rate, burst := t.rate, t.burst
	if e.overflow {
		rate, burst = rate*ABUSE_OVERFLOW_SCALE, burst*ABUSE_OVERFLOW_SCALE
	}
	refill(e, rate, burst, now)
	cost := float64(tokens)
	short, short_rate := cost-e.tokens, rate
	if g != nil {
		grate := t.rate * ABUSE_AGG_SCALE
		refill(g, grate, t.burst*ABUSE_AGG_SCALE, now)
		if gs := cost - g.tokens; gs > 0 && gs/grate > short/short_rate {
			short, short_rate = gs, grate
		}
	}
	if short > 0 {
		abuse_refused_rate.Inc()
		if d := t.score_locked(e, g, ABUSE_PTS_REFUSED, ABUSE_PTS_REFUSED, now); d > 0 {
			abuse_refused_banned.Inc()
			return abuse_banned, d
		}
		return abuse_rate_limited, time.Duration(short / short_rate * float64(time.Second))
	}
	e.tokens -= cost
	if g != nil {
		g.tokens -= cost
	}
	return abuse_ok, 0
}

// ---- B38: request shape on /json_rpc ---------------------------------------------------------------------------

var http_shape_refused_method = dmetrics.Set.GetOrCreateCounter(`rpc_http_shape_refused_total{reason="method"}`)
var http_shape_refused_type = dmetrics.Set.GetOrCreateCounter(`rpc_http_shape_refused_total{reason="content_type"}`)
var http_shape_normalised = dmetrics.Set.GetOrCreateCounter("rpc_http_content_type_normalised_total")

// json_content_type: the Content-Type value names application/json, with no charset or charset=utf-8 (JSON is
// UTF-8, RFC 8259 §8.1). exact reports the bridge's own spelling (no rewrite needed).
func json_content_type(v string) (ok, exact bool) {
	if v == "application/json" {
		return true, true
	}
	mt, params, err := mime.ParseMediaType(v)
	if err != nil || mt != "application/json" { // ParseMediaType lower-cases the type
		return false, false
	}
	for k, pv := range params {
		if k != "charset" || !(strings.EqualFold(pv, "utf-8") || strings.EqualFold(pv, "utf8")) {
			return false, false
		}
	}
	return true, false
}

// http_request_shape_ok answers a /json_rpc request the bridge would refuse with an empty body, and normalises an
// accepted application/json variant to the bridge's spelling. A remote key's refusal is scored as an invalid request
// (a scanner cycling methods and media types is the r23 "probe for free" pattern); loopback is never scored.
func http_request_shape_ok(w http.ResponseWriter, req *http.Request, ip string, loopback bool) bool {
	status, msg := 0, ""
	if req.Method != http.MethodPost {
		http_shape_refused_method.Inc()
		w.Header().Set("Allow", http.MethodPost)
		status, msg = http.StatusMethodNotAllowed, "JSON-RPC over HTTP needs POST with Content-Type: application/json"
	} else if ok, exact := json_content_type(req.Header.Get("Content-Type")); !ok {
		http_shape_refused_type.Inc()
		status, msg = http.StatusUnsupportedMediaType, "Content-Type must be application/json (charset, if given, utf-8)"
	} else if !exact {
		http_shape_normalised.Inc()
		req.Header.Set("Content-Type", "application/json")
		return true
	} else {
		return true
	}
	if !loopback && !abuse_exempt(ip, false) && rpc_abuse.is_enabled() {
		now := time.Now()
		d := rpc_abuse.banned_for(ip, now)
		if d == 0 {
			d = rpc_abuse.observe(ip, code.InvalidRequest, now)
		}
		if d > 0 {
			write_abuse_http(w, abuse_banned, d)
			return false
		}
	}
	e := &jrpc2.Error{Code: code.InvalidRequest, Message: msg}
	count_error_code(e) // r28: a 405/415 body is written outside jrpc2 (rpc_error_responses_total{code="-32600"})
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": e})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
	return false
}
