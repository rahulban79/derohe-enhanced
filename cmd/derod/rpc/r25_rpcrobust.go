// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// r25 (rpcrobust): typed errors instead of recovered panics on input a caller controls. Nothing here is
// consensus-visible: it changes only what an RPC caller is told and what the node logs.
//
// B85. A state read (GetEncryptedBalance, GetSC) at a topoheight below the prune point read the topo record of a
// pruned height (all-zero block id, the bootstrap state version: topo.map records 0..prunedheight-1 read
// "0000.. (4225, 0)" on the live datadir, 2026-11-03), then chain.ReadBlockSnapshotVersion(zero id) failed with "file
// does not exist" and GetEncryptedBalance panic(err)'d on purpose. The handler's deferred recover turned that into
// -32098 "internal error: file does not exist" plus an ERROR line with a full stack (4 such lines at 2026-11-03
// 08:37:44, which fail gate G15 for the whole derod run). GetSC did not panic: it silently answered from the
// bootstrap state under the requested topoheight. Now both refuse BEFORE any read with
//     code -32031, "state not available: topoheight N is below pruned topoheight P"
// count it in rpc_state_unavailable_total{method=...} and log at most one WARNING line (INFO level, no stack) per
// method per STATE_UNAVAILABLE_LOG_EVERY, carrying the number of refusals it stood for.
//
// B86. The other panic(err) sites a caller reaches with ordinary input become typed -32602 errors with a counter
// (rpc_input_refused_total{method=...,kind=...}): an unparsable address (GetEncryptedBalance logged a stack for every
// typo), an SCID whose first byte is ':' (0x3a; graviton refuses such a tree name, snapshot.go check_tree_name, so
// GetEncryptedBalance and GetRandomAddress panicked), and a name-service value that does not decode to a key
// (NameToAddress dereferenced a nil address). The remaining panics are store invariants (a topo record or snapshot
// of a topoheight at or above the prune point that cannot be read means a damaged store): they keep the loud ERROR +
// stack on purpose. The audit table is evidence/b86_panic_audit.txt of the r25 rpcrobust dimension.
//
// B80. GetBlockHeaderByHash wrote `block_header, err := GetBlockHeader(...)` inside an if, which shadows the named
// result err: an unknown or pruned hash returned status "" and an all-zero header with NO error. Now -32032
// "block not found: <hash>".
//
// GetTransaction (rpc_dero_gettransactions.go:59) answers a missing txid with status OK, as_hex "" and
// block_height 0: indistinguishable from a real answer unless the caller reads as_hex. rpc.Tx_Related_Info is in the
// consensus-listed rpc/ package (frozen), so the per-tx state is an ADDITIVE parallel array `txs_status`
// ("in_chain", "in_pool", "not_found"), index-aligned with txs/txs_as_hex. Old clients decode into
// rpc.GetTransaction_Result and ignore the field; the call still succeeds with status OK (compat kept on purpose:
// the wallet asks for batches and must not lose the found ones because one is missing).
//
// BD6 (disclosure FX-N9). GetInfo's total_supply is blockchain.CalcSupply(height) / 100000, the emission formula, not
// a count of coins: the additive field `total_supply_basis` says so in every answer. The value is unchanged.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/creachadair/jrpc2/code"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/rpc"
)

const RPC_CODE_STATE_UNAVAILABLE = code.Code(-32031) // r25 B85 (-32029 rate limited, -32030 banned)
const RPC_CODE_NOT_FOUND = code.Code(-32032)         // r25 B80

// StateUnavailableError is the typed refusal of a state read below the prune point (r25 B85). errors.As finds it in
// Go; jrpc2 sends its ErrCode and Error() to the client.
type StateUnavailableError struct {
	Method     string
	TopoHeight int64
	PrunedTopo int64
}

func (e *StateUnavailableError) Error() string {
	return fmt.Sprintf("state not available: topoheight %d is below pruned topoheight %d", e.TopoHeight, e.PrunedTopo)
}

func (e *StateUnavailableError) ErrCode() code.Code { return RPC_CODE_STATE_UNAVAILABLE }

// InputRefusedError is the typed refusal of a parameter that used to reach a panic(err) (r25 B86).
type InputRefusedError struct {
	Method string
	Kind   string // fixed literal per call site: "address", "scid", "name_value"
	Detail string
}

func (e *InputRefusedError) Error() string { return fmt.Sprintf("invalid %s: %s", e.Kind, e.Detail) }

func (e *InputRefusedError) ErrCode() code.Code { return code.InvalidParams }

// NotFoundError is the typed answer for an object this node does not hold (r25 B80).
type NotFoundError struct {
	What string
	ID   string
}

func (e *NotFoundError) Error() string { return fmt.Sprintf("%s not found: %s", e.What, e.ID) }

func (e *NotFoundError) ErrCode() code.Code { return RPC_CODE_NOT_FOUND }

// state_prune_floor is the lowest topoheight whose state this node still holds (0 = unpruned). A variable so a test
// can forge a pruned node on a simulator chain; chain.LocatePruneTopo caches its answer process-wide.
var state_prune_floor = func() int64 { return chain.LocatePruneTopo() }

const STATE_UNAVAILABLE_LOG_EVERY = time.Minute

// state_unavailable_log is the WARNING sink (a variable so a test can count lines and inspect the key/values).
var state_unavailable_log = func(msg string, kv ...interface{}) { logger.Info(msg, kv...) }

type rate_limited_warn struct {
	mu         sync.Mutex
	last       map[string]time.Time
	suppressed map[string]uint64
	now        func() time.Time
}

var state_warn = &rate_limited_warn{last: map[string]time.Time{}, suppressed: map[string]uint64{}, now: time.Now}

// allow reports whether a line may be written for key now and how many refusals since the last line it stands for.
func (w *rate_limited_warn) allow(key string) (bool, uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t := w.now()
	if last, ok := w.last[key]; ok && t.Sub(last) < STATE_UNAVAILABLE_LOG_EVERY {
		w.suppressed[key]++
		return false, 0
	}
	n := w.suppressed[key]
	w.suppressed[key] = 0
	w.last[key] = t
	return true, n
}

// refuse_state builds, counts and (rate-limited) logs one StateUnavailableError. method is a literal of the caller.
func refuse_state(method string, topoheight, floor int64) error {
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`rpc_state_unavailable_total{method=%q}`, method)).Inc()
	if ok, suppressed := state_warn.allow(method); ok {
		state_unavailable_log("WARNING: state read below the prune point refused", "method", method,
			"topoheight", topoheight, "prunedheight", floor, "suppressed_since_last", suppressed)
	}
	return &StateUnavailableError{Method: method, TopoHeight: topoheight, PrunedTopo: floor}
}

// check_state_topo refuses a state read at topoheight when the node pruned it (r25 B85). Called BEFORE any store read.
func check_state_topo(method string, topoheight int64) error {
	if floor := state_prune_floor(); floor > 0 && topoheight < floor {
		return refuse_state(method, topoheight, floor)
	}
	return nil
}

// check_state_record is the second line: a topo record with an all-zero block id names no block (a pruned or never
// committed slot), so no snapshot of it can be trusted even if check_state_topo let it through (r25 B85).
func check_state_record(method string, topoheight int64, blid crypto.Hash) error {
	if blid.IsZero() {
		return refuse_state(method, topoheight, state_prune_floor())
	}
	return nil
}

// refuse_input counts and returns one InputRefusedError (r25 B86). method and kind are literals of the call site,
// so the metric's series are bounded.
func refuse_input(method, kind, detail string) error {
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`rpc_input_refused_total{method=%q,kind=%q}`, method, kind)).Inc()
	return &InputRefusedError{Method: method, Kind: kind, Detail: detail}
}

// check_scid_tree refuses an SCID graviton cannot open as a tree name (its first byte is ':'; snapshot.go
// check_tree_name). The zero SCID means the base balance tree and is always fine.
func check_scid_tree(method string, scid crypto.Hash) error {
	if !scid.IsZero() && scid[0] == ':' {
		return refuse_input(method, "scid", "an scid starting with byte 0x3a cannot name a tree")
	}
	return nil
}

// GetTransaction_Result_R25 is GetTransaction's answer plus the additive per-tx state (r25).
type GetTransaction_Result_R25 struct {
	rpc.GetTransaction_Result
	Txs_Status []string `json:"txs_status"` // per txs_hashes[i]: "in_chain", "in_pool" or "not_found"
}

// tx_lookup_states derives the per-tx state from an upstream-shaped answer. Pure.
func tx_lookup_states(r rpc.GetTransaction_Result) []string {
	out := make([]string, 0, len(r.Txs_as_hex))
	for i := range r.Txs_as_hex {
		switch {
		case r.Txs_as_hex[i] == "":
			out = append(out, "not_found")
		case i < len(r.Txs) && r.Txs[i].In_pool:
			out = append(out, "in_pool")
		default:
			out = append(out, "in_chain")
		}
	}
	return out
}

// GetTransactionR25 is what DERO.GetTransaction / gettransactions serve from r25 (websocket_server.go).
func GetTransactionR25(ctx context.Context, p rpc.GetTransaction_Params) (result GetTransaction_Result_R25, err error) {
	result.GetTransaction_Result, err = GetTransaction(ctx, p)
	result.Txs_Status = tx_lookup_states(result.GetTransaction_Result)
	for _, st := range result.Txs_Status {
		if st == "not_found" {
			metrics.Set.GetOrCreateCounter(`rpc_tx_not_found_total`).Inc()
		}
	}
	return
}

// TOTAL_SUPPLY_BASIS is the text of GetInfo's additive total_supply_basis field (r25 BD6 / FX-N9).
const TOTAL_SUPPLY_BASIS = "formula: blockchain.CalcSupply(height) / 100000 (whole DERO); the emission schedule, not a count of coins"

// GetInfo_Result_R25 is GetInfo's answer plus total_supply_basis (r25 BD6).
type GetInfo_Result_R25 struct {
	rpc.GetInfo_Result
	Total_Supply_Basis string `json:"total_supply_basis"`
}

// GetInfoR25 is what DERO.GetInfo / getinfo / get_info serve from r25 (websocket_server.go).
func GetInfoR25(ctx context.Context) (result GetInfo_Result_R25, err error) {
	result.GetInfo_Result, err = GetInfo(ctx)
	result.Total_Supply_Basis = TOTAL_SUPPLY_BASIS
	return
}
