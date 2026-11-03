// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

func refused(reason string) uint64 {
	return metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="` + reason + `"}`).Get()
}

func window_fixture(t *testing.T) ([]byte, *transaction.Transaction) {
	raw, _ := hex.DecodeString(r23FixtureTx)
	var tx transaction.Transaction
	if err := tx.Deserialize(raw); err != nil || tx.TransactionType != transaction.NORMAL {
		t.Fatalf("fixture: %v type %d", err, tx.TransactionType)
	}
	return raw, &tx
}

func with_relay_tip(t *testing.T, height int64) {
	old := relay_tip
	relay_tip = func() int64 { return height }
	t.Cleanup(func() { relay_tip = old })
}

// A relayed tx too old (or too new) for any block on top of our tip is dropped by the r23b window before the mempool
// is touched (chain is nil here: a tx reaching Mempool_TX_Exist would panic, be recovered, and end the loop, so the
// second copy would never be counted), unscored.
func TestR23bRelayWindowDropsBeforeMempool(t *testing.T) {
	raw, tx := window_fixture(t)
	reset_penalties()
	const ip = "198.51.100.91"
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 11011}}
	for i := 0; i < 3; i++ {
		with_relay_tip(t, int64(tx.Height)+blockchain.TX_VALIDITY_HEIGHT+1)
		before := refused("too_old")
		c.process_object_response_want(Objects{Txs: [][]byte{raw, raw}}, 0, false, nil)
		if got := refused("too_old") - before; got != 2 {
			t.Fatalf("too_old refusals %d, want 2 (both copies dropped before the mempool)", got)
		}
		with_relay_tip(t, int64(tx.Height)-1)
		before = refused("too_new")
		c.process_object_response_want(Objects{Txs: [][]byte{raw, raw}}, 0, false, nil)
		if got := refused("too_new") - before; got != 2 {
			t.Fatalf("too_new refusals %d, want 2", got)
		}
	}
	if s := penalty_of(ip); s != 0 {
		t.Fatalf("a late relay must not be scored: %.1f", s)
	}
}

// A relayed copy of a grandfathered HF3 TXID is refused by TXID even when its height is inside the window (a node
// syncing below HF3), before verification could reach the exemption's proof-cache entry.
func TestR23bRelayHF3TableRefused(t *testing.T) {
	raw, tx := window_fixture(t)
	key := tx.GetHash().String()
	if _, clash := blockchain.HF3_Affected_Txs[key]; clash {
		t.Fatal("fixture collides with a real HF3 entry")
	}
	blockchain.HF3_Affected_Txs[key] = &blockchain.HF3_Tx_Data{Height: tx.Height}
	defer delete(blockchain.HF3_Affected_Txs, key)
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.92"), Port: 11011}}
	for i := 0; i < 3; i++ {
		with_relay_tip(t, int64(tx.Height))
		before := refused("hf3_table")
		c.process_object_response_want(Objects{Txs: [][]byte{raw, raw}}, 0, false, nil)
		if got := refused("hf3_table") - before; got != 2 {
			t.Fatalf("hf3_table refusals %d, want 2", got)
		}
	}
}

// control: an in-window, non-table tx passes the window (and so reaches the nil chain: nothing is counted)
func TestR23bRelayWindowPassesInWindow(t *testing.T) {
	raw, tx := window_fixture(t)
	with_relay_tip(t, int64(tx.Height)+blockchain.TX_VALIDITY_HEIGHT)
	if err := relay_window(tx, tx.GetHash()); err != nil {
		t.Fatalf("in-window relayed tx refused: %v", err)
	}
	a, b, h := refused("too_old"), refused("too_new"), refused("hf3_table")
	c := &Connection{logger: globals.Logger, Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.93"), Port: 11011}}
	c.process_object_response_want(Objects{Txs: [][]byte{raw}}, 0, false, nil)
	if refused("too_old") != a || refused("too_new") != b || refused("hf3_table") != h {
		t.Fatal("an in-window tx was counted as refused")
	}
}
