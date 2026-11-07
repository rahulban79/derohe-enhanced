package rpc

// r28 (rpc-metrics; dero-rft §7 B42, B85 and the R28 rpc/metrics sweep).
//
// 1. rpc_error_responses_total{code} (r27) was counted in jrpc2's LogResponse only, while five answers carry a
//    JSON-RPC error body written by the HTTP layer before the bridge: the 405/415 shape refusals (-32600,
//    http_request_shape_ok), the abuse table's 429 rate-limit/ban answers (-32029/-32030, write_abuse_http, also on a
//    refused websocket upgrade), the over-bound remote body (-32602, write_bound_error) and (r28 verify) the reserved
//    rpc.* name on a remote /json_rpc body (-32601, write_method_not_found). RPC_METHODS.md says the
//    series counts every error response; those were invisible in it (each had only its own reason counter). They are
//    now counted at the writer, exactly once per answer (the bridge never sees these requests).
// 2. B42: GetInfo tx_pool_size counts every tx the mempool lists, including txs already mined until HouseKeeping
//    drops them at stable height >= the tx's height (upstream meaning, kept). The additive tx_pool_unmined is the same
//    list minus the txs of the recent blocks (RecentlyMined: the window GetTxPool and the fee estimate already skip),
//    so a reader can tell "pending" from "mined, not yet purged" without a GetTxPool walk.

import (
	"errors"

	"github.com/creachadair/jrpc2"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// count_error_answer counts an error answered outside jrpc2 by its JSON-RPC code (a non-jrpc2 error: "other").
func count_error_answer(err error) {
	if err == nil {
		return
	}
	var je *jrpc2.Error
	if errors.As(err, &je) {
		count_error_code(je)
		return
	}
	rpc_error_code_other.Inc()
}

// pool_unmined counts the pool txs not in mined (pure).
func pool_unmined(pool []crypto.Hash, mined map[crypto.Hash]bool) (n uint64) {
	for _, h := range pool {
		if !mined[h] {
			n++
		}
	}
	return
}

// recently_mined is RecentlyMined, replaceable by a test.
var recently_mined = RecentlyMined
