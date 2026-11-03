// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r21 (rpcws, closes r20 residual R-6): a call-rate limit for websockets that a cross-site page opened (foreign
// Origin, see rpc_guard). r20 capped how many such sockets exist (64 node-wide) and refused the local-only methods,
// but each socket could still send requests as fast as the node answered them, and one page could keep the 2
// node-wide range slots busy so explorers queued. Now every foreign socket has its own token bucket, and the foreign
// sockets that reach the node over LOOPBACK (a page in a local browser: remote_ip folds them all into
// FOREIGN_LIMIT_KEY) together share one more, so such pages cost at most FOREIGN_NODE_RATE weighted calls per second
// whatever they open. Range and block reads cost more tokens than a Ping (foreign_cost).
//
// Loopback programs (wallet CLI, miner, explorer on this machine) and remote non-browser clients are not affected:
// the limit applies only to sockets with ws_client.foreign set (an Origin header naming another host). REMOTE browser
// sockets (a web wallet using a public node) are foreign too: each gets its own per-socket bucket, but they do NOT
// share the loopback node bucket (r21 merge, RPCWS21-A fix: one remote client sending a forged Origin could otherwise
// drain it and starve every other remote web wallet, which before r21 had their own per-IP budgets). An operator who
// lists an Origin in DERO_RPC_ALLOWED_ORIGINS makes it local again. A refused call gets JSON-RPC error RPC_CODE_RATE_LIMITED; the socket stays open, so a web
// wallet that retries a little later simply works.

import (
	"context"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/creachadair/jrpc2/handler"
	"golang.org/x/time/rate"

	dmetrics "github.com/deroproject/derohe/metrics"
)

// Per foreign socket: 20 weighted calls/s, burst 40 (a web wallet's refresh after a block is ~5-10 calls).
const FOREIGN_WS_RATE = 20
const FOREIGN_WS_BURST = 40

// All foreign sockets together: 200 weighted calls/s, burst 400 (the 64-socket cap times 20/s would be 1280/s).
const FOREIGN_NODE_RATE = 200
const FOREIGN_NODE_BURST = 400

// RPC_CODE_RATE_LIMITED is in the JSON-RPC server-error range (-32000..-32099).
const RPC_CODE_RATE_LIMITED = code.Code(-32029)

var foreign_node_limiter = rate.NewLimiter(FOREIGN_NODE_RATE, FOREIGN_NODE_BURST)

var foreign_rate_limited = dmetrics.Set.GetOrCreateCounter("rpc_foreign_rate_limited_total")

// foreign_method_cost: tokens per call for the methods that read many records or whole blocks. Everything else costs 1,
// including unknown names, so a page cannot spam method names for free.
var foreign_method_cost = map[string]int{
	"DERO.GetBlockHeadersRange": 8,
	"DERO.GetDifficultyHistory": 8,
	"DERO.GetMiniBlocks":        4,
	"DERO.GetTxPoolDetail":      4,
	"DERO.GetTxStatus":          4,
	"DERO.GetFeeEstimate":       2, // r23: one pool pass, cached 1 s
	"DERO.WatchTx":              4,
	"DERO.GetBlock":             2,
	"DERO.GetTransaction":       2,
	"DERO.GetEncryptedBalance":  2,
	"DERO.GetSC":                2,
	"getblock":                  2,
	"gettransactions":           2,
	"getencryptedbalance":       2,
	"getsc":                     2,
}

func foreign_cost(method string) int {
	if n, ok := foreign_method_cost[method]; ok {
		return n
	}
	return 1
}

func new_foreign_limiter() *rate.Limiter { return rate.NewLimiter(FOREIGN_WS_RATE, FOREIGN_WS_BURST) }

// foreign_node_bucket is the shared bucket a foreign socket also draws on: the node-wide one for loopback-foreign
// sockets (remote_ip key FOREIGN_LIMIT_KEY), none for remote ones, whose per-IP connection cap (WS_MAX_CONNS_PER_IP)
// times the per-socket rate already bounds each address without letting one address starve the others.
func foreign_node_bucket(ip string) *rate.Limiter {
	if ip == FOREIGN_LIMIT_KEY {
		return foreign_node_limiter
	}
	return nil
}

// allow_foreign_call spends the call's tokens from the socket's bucket and then from the shared one (if any). A call
// refused by the shared bucket has already spent its socket tokens: that only slows the page over the node limit.
func allow_foreign_call(own, node *rate.Limiter, method string, now time.Time) bool {
	n := foreign_cost(method)
	if own != nil && !own.AllowN(now, n) {
		return false
	}
	if node == nil {
		return true
	}
	return node.AllowN(now, n)
}

// ws_client_of returns the websocket client a request arrived on, nil for the HTTP bridge and direct Go calls.
func ws_client_of(ctx context.Context) *ws_client {
	if s := server_of(ctx); s != nil {
		if v, ok := client_connections.Load(s); ok {
			return v.(*ws_client)
		}
	}
	return nil
}

// r23: a raw handler.Func. handler.New(func(ctx) error) first checks that the request has NO params and answered a
// refused call that carried params (GetBlock, GetTransaction, ... nearly all of them) with -32602 "invalid params",
// so a web wallet never saw RPC_CODE_RATE_LIMITED and could not tell it should back off.
var rate_limited_handler = handler.Func(func(ctx context.Context, _ *jrpc2.Request) (interface{}, error) {
	return nil, &jrpc2.Error{Code: RPC_CODE_RATE_LIMITED, Message: "rate limited: too many calls from this cross-site (foreign Origin) websocket; retry later"}
})

// foreign_assigner is the method table of one foreign socket: the usual one behind the socket's call budget. jrpc2
// calls Assign once per request (each element of a batch too) before the handler runs; the context it passes does not
// carry the server yet, so the socket is bound here instead of being looked up.
type foreign_assigner struct{ c *ws_client }

func (f foreign_assigner) Assign(ctx context.Context, method string) jrpc2.Handler {
	if !allow_foreign_call(f.c.limiter, f.c.node_limiter, method, time.Now()) {
		foreign_rate_limited.Inc()
		return rate_limited_handler
	}
	return d.Assign(ctx, method)
}

func (f foreign_assigner) Names() []string { return d.Names() }

// assigner_for: local sockets keep the shared table with no per-call cost; foreign ones get the gated table.
func assigner_for(c *ws_client) jrpc2.Assigner {
	if c.foreign && c.limiter != nil {
		return foreign_assigner{c}
	}
	return d
}
