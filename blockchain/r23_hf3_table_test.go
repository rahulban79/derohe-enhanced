// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package blockchain

import (
	"encoding/hex"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// R23 (HF3 exemption audit): the 75 grandfathered txids are a historical set, all mined below the mainnet HF3 height.
// The proof-skip they get (transaction_verify.go:232 stores the TXID in transaction_valid_cache) is only consulted
// under the TXID for tx.Height < MAJOR_HF3_HEIGHT (transaction_verify.go:434); from HF3 the cache key is
// Keccak256(full serialization). The end-to-end replay is walletapi/r23_hf3_replay_test.go.
func TestR23HF3TableIsHistorical(t *testing.T) {
	if n := len(HF3_Affected_Txs); n != 75 {
		t.Fatalf("HF3 table has %d entries, want 75 (the reviewed set)", n)
	}
	hf3 := uint64(config.Mainnet.MAJOR_HF3_HEIGHT)
	if hf3 != 7504640 {
		t.Fatalf("mainnet MAJOR_HF3_HEIGHT %d, want 7504640", hf3)
	}
	lo, hi := ^uint64(0), uint64(0)
	for txid, e := range HF3_Affected_Txs {
		if b, err := hex.DecodeString(txid); err != nil || len(b) != 32 {
			t.Fatalf("txid %q is not 32 hex bytes", txid)
		}
		if b, err := hex.DecodeString(e.Bl_Tips); err != nil || len(b) != 32 {
			t.Fatalf("txid %s: Bl_Tips %q is not one 32-byte tip (the nonce bypass is pinned to it)", txid, e.Bl_Tips)
		}
		if e.Height >= hf3 {
			t.Fatalf("txid %s at height %d is not below HF3 %d", txid, e.Height, hf3)
		}
		if e.Height < lo {
			lo = e.Height
		}
		if e.Height > hi {
			hi = e.Height
		}
	}
	if lo != 7415466 || hi != 7497942 {
		t.Fatalf("height span %d..%d, want 7415466..7497942", lo, hi)
	}
}

// The TXID commits to the header (height, BLID, payload statements) and excludes the proof: a table TXID can only be
// carried by the historical header, so a transaction built at a post-HF3 height cannot match an entry without a
// Keccak256 preimage, while two bodies that differ only in their proof share one TXID (the pre-HF3 duplicate class).
func TestR23TxidCommitsToHeightNotProof(t *testing.T) {
	tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, TransactionType: transaction.NORMAL, Height: 7497942}}
	h0 := tx.GetHash()
	tx.Height = 7504640
	if tx.GetHash() == h0 {
		t.Fatal("TXID does not commit to tx.Height")
	}
	tx.Height = 7497942
	tx.BLID = crypto.Hash{1}
	if tx.GetHash() == h0 {
		t.Fatal("TXID does not commit to tx.BLID")
	}
}
