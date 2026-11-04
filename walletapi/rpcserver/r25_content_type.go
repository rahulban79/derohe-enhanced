// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package rpcserver

// r25 (rpcrobust, B40 = RPCWS24-7): the wallet's /json_rpc uses the same jhttp bridge as derod did before r24 B38
// (vendor/github.com/creachadair/jrpc2/jhttp/bridge.go: a non-POST gets 405 and any Content-Type other than the exact
// string "application/json" gets 415, both with an EMPTY body). So "application/json; charset=utf-8" (what many HTTP
// libraries send) was refused with nothing to read. Same rule as derod (cmd/derod/rpc/r24_rpcws.go json_content_type):
// application/json with no charset or charset=utf-8 is served (the header is normalised to the bridge's spelling);
// everything else is still refused (a cross-site page still cannot send a simple, unpreflighted request), now with a
// JSON-RPC -32600 body that says what to send, and a non-POST gets 405 with Allow: POST. Authentication runs first,
// as before: an unauthenticated caller learns nothing new.

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
)

// counters (read by tests; the wallet has no metrics endpoint)
var http_shape_refused, http_shape_normalised atomic.Uint64

// json_content_type: the value names application/json with no charset or charset=utf-8; exact = the bridge's spelling.
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

// wallet_http_shape_ok answers a request the bridge would refuse with an empty body, and normalises an accepted
// application/json variant. true = hand the request to the bridge.
func wallet_http_shape_ok(w http.ResponseWriter, req *http.Request) bool {
	status, msg := 0, ""
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		status, msg = http.StatusMethodNotAllowed, "JSON-RPC over HTTP needs POST with Content-Type: application/json"
	} else if ok, exact := json_content_type(req.Header.Get("Content-Type")); !ok {
		status, msg = http.StatusUnsupportedMediaType, "Content-Type must be application/json (charset, if given, utf-8)"
	} else {
		if !exact {
			http_shape_normalised.Add(1)
			req.Header.Set("Content-Type", "application/json")
		}
		return true
	}
	http_shape_refused.Add(1)
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": nil, "error": &jrpc2.Error{Code: code.InvalidRequest, Message: msg}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
	return false
}

// wallet_json_rpc_handler is the wallet's /json_rpc: authentication, then the request shape, then the bridge.
func wallet_json_rpc_handler(rpcserver *RPCServer, bridge http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hasbasicauthfailed(rpcserver, w, r) {
			return
		}
		if !wallet_http_shape_ok(w, r) { // r25 B40
			return
		}
		bridge.ServeHTTP(w, r)
	}
}
