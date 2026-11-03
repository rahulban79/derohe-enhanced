// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package walletapi

// r23c (RPCWS23B-E): where SyncHistory resumes after the daemon's chain moved under the wallet's history.
//
// Before, SyncHistory checked the newest entry's block hash, and on a mismatch dropped that entry group, then compared
// the SAME stale header against the next older entry (different topoheight, so it never matched) and returned without
// syncing anything. SyncHistory runs only when the encrypted balance changes, so a reorg that replaced k entry groups
// needed k+1 balance changes before history was rescanned, and the entries of the replacing blocks stayed missing in
// between. When the mismatch left one entry (index 0), that entry was discarded unchecked and history was rebuilt
// from the registration topoheight, and a wallet whose history was a single matching entry rescanned from
// registration on every balance change. An entry above the daemon's topoheight (the daemon's chain is now shorter,
// or a different daemon) made GetBlockHeaderByTopoHeight fail, so SyncHistory returned on every call and history
// never moved again.
//
// plan_history_sync walks the entries newest first, one header call per entry group, dropping every group whose
// block hash the daemon no longer has at that topoheight, until a group matches (resume after it) or none is left
// (rescan from registration). Pure apart from header, so it is tested without a daemon. Not consensus-visible: it
// only decides which topoheights this wallet asks its daemon about.

import (
	"fmt"

	"github.com/deroproject/derohe/rpc"
)

type history_sync_plan struct {
	keep  int   // entries[:keep] stay; entries[keep:] were on blocks the daemon no longer has
	start int64 // first topoheight to rescan
	calls int   // header lookups made
}

// plan_history_sync: entries sorted by topoheight (InsertReplace keeps them so); registration as in
// GetEncryptedBalance; end_topo is the topoheight SyncHistory syncs to. header returns the hash of the daemon's block
// at topo. On a header error the plan keeps what was already proven stale removed and returns the error.
func plan_history_sync(entries []rpc.Entry, registration, end_topo int64, header func(topo int64) (string, error)) (p history_sync_plan, err error) {
	i := len(entries) - 1
	for i >= 0 {
		topo := entries[i].TopoHeight
		if registration >= topo { // chain pruned on the server: keep old history, rescan from registration (as before)
			return history_sync_plan{keep: i + 1, start: registration, calls: p.calls}, nil
		}
		hash, herr := header(topo)
		p.calls++
		stale := false
		switch {
		case herr != nil && topo > end_topo: // the daemon's chain no longer reaches this entry
			stale = true
		case herr != nil:
			return history_sync_plan{keep: i + 1, start: registration, calls: p.calls}, herr
		case hash != entries[i].BlockHash:
			stale = true
		}
		if !stale { // a matching block: everything up to here stands, resume right after it
			return history_sync_plan{keep: i + 1, start: topo + 1, calls: p.calls}, nil
		}
		for i >= 0 && entries[i].TopoHeight == topo { // the whole group of that block
			i--
		}
	}
	return history_sync_plan{keep: 0, start: registration, calls: p.calls}, nil
}

// history_block_hash is the daemon lookup plan_history_sync uses (a seam for tests).
var history_block_hash = func(topo int64) (string, error) {
	var result rpc.GetBlockHeaderByHeight_Result
	if err := rpc_client.Call("DERO.GetBlockHeaderByTopoHeight", rpc.GetBlockHeaderByTopoHeight_Params{TopoHeight: uint64(topo)}, &result); err != nil {
		return "", err
	}
	if result.Status != "OK" {
		return "", fmt.Errorf("GetBlockHeaderByTopoHeight %d status %q", topo, result.Status)
	}
	return result.Block_Header.Hash, nil
}
