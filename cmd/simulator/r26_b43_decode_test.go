// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// r26 (node-rpc, dero-rft §7 B43): the two simulator txs that TestR24TxpoolLoad captured when they failed (r25
// secpool load run tree/3, testdata/r26_b43_failures.jsonl, byte-identical copy), decoded. Every account of that
// harness is deterministic (seed 2000003+i*7919; mk(0) = genesis miner, ws[i] = mk(i+1)), so each ring pointer
// (the first Bytes_per_publickey bytes of graviton.Sum(compressed key)) can be named.
//
// Setup of that run: block 1 and block 26 mined by the genesis miner, blocks 2..25 by ws[0..23] (one each), 61
// registered accounts plus the ~1,326 static accounts of the simulator's genesis state (they never transact).
//
//   record 0, round 0, sender 15: "transaction statement 0 verification failed". BLID = topoheight 23, tip 26. The
//     ring holds ws[23], which mined block 25: its balance changed between the BLID and the tip. The wallet builds
//     at tip-3 (walletapi/wallet_transfer.go:238-239) but fetches decoy balances at the tip (TopoHeight -1,
//     walletapi/ring_fetch.go:73), so the statement carried ws[23]'s tip balance where the chain has its topoheight-23
//     balance. GetRandomAddress is meant to offer only accounts unchanged over the last 5 topoheights, but upstream
//     skipped that window up to topoheight 100 (cmd/derod/rpc/rpc_dero_getrandomaddress.go before r26).
//   record 1, round 1, sender 15: "Invalid Nonce, not usable, expected 27 actual 0" for a static genesis-state account.
//     BLID = 25, tip 28. That account sits on the ring's checked side (even index, parity true) and had been marked
//     as a sender-side ring member of a round-0 tx mined in block 27 (blockchain/transaction_execute.go:248-249): the
//     same stale-decoy window, seen by the nonce check instead of the proof.
//
// Neither is a walletapi flake or a proof defect: both follow from the decoy window. r26 applies it at every height
// (decoy_window_topo, cmd/derod/rpc/r26_noderpc_test.go).

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/deroproject/graviton"
)

// the address in the record-1 refusal text (r25 secpool evidence load/load_tree_3.raw, the "nonce verification
// failed" line of round 1, sender 15)
const r26_b43_nonce_addr = "deto1qygtjupmd4q9rkq2laqf42tul0zseg5u7n4knc8rcvj60pr8u0znzqqkzaffm"

type r26_b43_record struct {
	Hex      string `json:"hex"`
	Round    int    `json:"round"`
	Sender   int    `json:"sender"`
	TxHeight uint64 `json:"tx_height"`
	BlidTopo int64  `json:"blid_topo"`
	TipTopo  int64  `json:"tip_topo"`
}

// members names each ring slot: ws index (>= 0), -1 for the genesis miner, -2 for an account outside the 61
func r26_b43_members(t *testing.T, st *crypto.Statement, keys map[string]int) (names []int, ptrs [][]byte) {
	n := int(st.Bytes_per_publickey)
	for i := 0; i < int(st.RingSize); i++ {
		ptr := st.Publickeylist_pointers[i*n : (i+1)*n]
		name := -2
		for k, v := range keys {
			if h := graviton.Sum([]byte(k)); string(h[:n]) == string(ptr) {
				name = v
			}
		}
		names = append(names, name)
		ptrs = append(ptrs, ptr)
	}
	return
}

func TestR26B43CapturedFailuresDecoded(t *testing.T) {
	keys := map[string]int{}
	for i := 0; i <= 60; i++ {
		w, err := walletapi.Create_Encrypted_Wallet_Memory("", new(crypto.BNRed).SetBytes(big.NewInt(int64(2000003+i*7919)).Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		keys[string(w.GetAddress().PublicKey.EncodeCompressed())] = i - 1
	}
	f, err := os.Open("testdata/r26_b43_failures.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []r26_b43_record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r r26_b43_record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("%d records, want the 2 captured failures", len(recs))
	}
	decode := func(r r26_b43_record) *transaction.Transaction {
		raw, err := hex.DecodeString(r.Hex)
		if err != nil {
			t.Fatal(err)
		}
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatal(err)
		}
		if tx.Height != r.TxHeight || len(tx.Payloads) != 1 || tx.Payloads[0].Statement.RingSize != 16 {
			t.Fatalf("record round %d: height %d payloads %d", r.Round, tx.Height, len(tx.Payloads))
		}
		return &tx
	}
	// the miner of each block of the run's setup (block h for h in 2..25 is ws[h-2])
	miner_of := func(h int64) int {
		if h == 1 || h == 26 {
			return -1
		}
		return int(h - 2)
	}

	// record 0: the statement failure
	r0 := recs[0]
	tx0 := decode(r0)
	names0, _ := r26_b43_members(t, &tx0.Payloads[0].Statement, keys)
	changed := map[int]bool{} // accounts whose balance changed in (BLID, tip]: the miners of those blocks
	for h := r0.BlidTopo + 1; h <= r0.TipTopo; h++ {
		changed[miner_of(h)] = true
	}
	var stale []int
	have := map[int]bool{}
	for _, m := range names0 {
		have[m] = true
		if m != -2 && changed[m] {
			stale = append(stale, m)
		}
	}
	if !have[r0.Sender] || !have[(r0.Sender+24)%60] {
		t.Fatalf("record 0 ring %v lacks the sender ws[%d] or its destination", names0, r0.Sender)
	}
	if len(stale) != 1 || stale[0] != 23 {
		t.Fatalf("record 0 (BLID %d, tip %d): ring %v, changed members %v; want exactly ws[23] (mined block 25)",
			r0.BlidTopo, r0.TipTopo, names0, stale)
	}

	// record 1: the nonce failure names a static genesis-state account on the checked side of the ring
	r1 := recs[1]
	tx1 := decode(r1)
	names1, ptrs1 := r26_b43_members(t, &tx1.Payloads[0].Statement, keys)
	a, err := rpc.NewAddress(r26_b43_nonce_addr)
	if err != nil {
		t.Fatal(err)
	}
	h := graviton.Sum(a.PublicKey.EncodeCompressed())
	parity := tx1.Payloads[0].Proof.Parity()
	slot := -1
	for i, p := range ptrs1 {
		if string(p) == string(h[:len(p)]) {
			slot = i
		}
	}
	if slot < 0 || names1[slot] != -2 {
		t.Fatalf("record 1: refused account %x in slot %d (name %v) of ring %v", h[:3], slot, names1, names1)
	}
	if checked := (slot%2 == 0) == parity; !checked { // blockchain/transaction_verify.go:157 skips the other side
		t.Fatalf("record 1: slot %d with parity %v is not on the side the nonce check reads", slot, parity)
	}
	if r1.TipTopo-int64(r1.TxHeight) != 3 || r0.TipTopo-int64(r0.TxHeight) != 3 {
		t.Fatalf("both txs should be built at tip-3: %d/%d, %d/%d", r0.TxHeight, r0.TipTopo, r1.TxHeight, r1.TipTopo)
	}
}
