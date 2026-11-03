// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package txprecheck

// Admission window and HF3 replay refusal (Round 23b). Node-local mempool-admission policy for transactions that
// arrive by relay (p2p GetObject replies) or by SendRawTransaction. Blocks never pass through here: a block's
// transactions are decoded by decode_block_tx / chain_bootstrap and verified by the unchanged consensus code, and a
// compact-block reconstruction that misses a refused transaction falls back to the block's chunks. So nothing here
// can make this node reject a block the network accepts.
//
// Rules, and why each refuses only transactions that can never be mined on top of our chain:
//   - too_old: tip_height > tx.Height + TX_VALIDITY_HEIGHT. Every block extending our tip has height >= tip+1, and
//     blockchain.go:786 refuses a block holding a tx with block_height - tx.Height >= TX_VALIDITY_HEIGHT; miner_block.go
//     :275 never selects one either. p2p chain_sync.go has used this same bound for relayed txs since upstream; r23b
//     shares it with SendRawTransaction, which had none, and moves it before Deserialize there.
//   - too_new: tx.Height > tip_height. blockchain.go:778 requires tx.BLID in the block's 25-block history and :782
//     requires tx.Height == the height of that BLID; every block in the history of a block extending our tip is at
//     a height <= tip_height. (Add_TX_To_Pool refuses these too: it reads Topo_store at tx.Height, and topoheight
//     >= height, so a record past our topoheight is missing: "height reference not found".) One height read serves
//     both bounds (upstream's too-old check already made it); a Load_TOPO_HEIGHT would be a second store read.
//   - hf3_table: the TXID is one of the 75 grandfathered HF3 transactions (blockchain/hardfork_fixes.go). Every one is
//     mined at height <= 7,497,942, so a copy is refused by the pool's already-mined guard (blockchain.go:1300) and by
//     the validity window; but transaction_verify.go:232 seeds the proof cache for a table TXID before verification,
//     so on a node still syncing below HF3 a same-TXID body with a changed proof could otherwise reach the mempool.
//     Refused by TXID, before any verification.
//
// PeekHeight reads the height from the raw bytes exactly as transaction.Deserialize does (same field order and
// varint decoding) without decoding a single curve point, so an out-of-window body costs a few varint reads instead
// of a full decode. A body PeekHeight cannot read (bad varint, unknown type) is refused as "header": Deserialize
// refuses those too (an unknown type panics there, transaction.go:321), and the RPC path would otherwise log a full
// recovered-panic stack at ERROR for every such call.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// ErrWindow wraps every window refusal; ErrHF3 the HF3-table refusal. Neither wraps ErrStructure: an honest relay can
// deliver a late transaction, so p2p does not score these against the peer.
var ErrWindow = errors.New("transaction refused: outside the validity window of our chain tip")
var ErrHF3 = errors.New("transaction refused: grandfathered HF3 transaction")
var ErrHeader = errors.New("transaction refused: header cannot be decoded")

var (
	window_too_old = metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="too_old"}`)
	window_too_new = metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="too_new"}`)
	window_header  = metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="header"}`)
	hf3_table      = metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="hf3_table"}`)
)

// PeekHeight returns the height field of a serialized transaction and whether the type carries one (registration,
// premine and coinbase do not). err is ErrHeader when Deserialize would refuse (or panic on) the header.
func PeekHeight(raw []byte) (height uint64, has bool, err error) {
	field := func() (uint64, bool) {
		v, n := binary.Uvarint(raw)
		if n <= 0 {
			return 0, false
		}
		raw = raw[n:]
		return v, true
	}
	version, ok := field()
	if !ok || version != 1 {
		return 0, false, header_refused()
	}
	if _, ok = field(); !ok { // SourceNetwork
		return 0, false, header_refused()
	}
	if _, ok = field(); !ok { // DestNetwork
		return 0, false, header_refused()
	}
	t, ok := field()
	if !ok {
		return 0, false, header_refused()
	}
	switch transaction.TransactionType(t) {
	case transaction.PREMINE, transaction.REGISTRATION, transaction.COINBASE:
		return 0, false, nil
	case transaction.BURN_TX, transaction.NORMAL:
	case transaction.SC_TX:
		if _, ok = field(); !ok { // Value (gas)
			return 0, false, header_refused()
		}
	default:
		return 0, false, header_refused()
	}
	if height, ok = field(); !ok {
		return 0, false, header_refused()
	}
	return height, true, nil
}

func header_refused() error {
	window_header.Inc()
	return ErrHeader
}

// Window refuses a transaction height that no block extending our tip (at tip_height) can hold.
func Window(tx_height uint64, tip_height int64) error {
	if tip_height < 0 {
		return nil
	}
	if uint64(tip_height) > tx_height+blockchain.TX_VALIDITY_HEIGHT {
		window_too_old.Inc()
		return ErrWindow
	}
	if tx_height > uint64(tip_height) {
		window_too_new.Inc()
		return ErrWindow
	}
	return nil
}

// PeekWindow is Window on raw bytes, before Deserialize. Types without a height pass.
func PeekWindow(raw []byte, tip_height int64) error {
	h, has, err := PeekHeight(raw)
	if err != nil || !has {
		return err
	}
	return Window(h, tip_height)
}

// HF3 refuses a transaction whose TXID is in the HF3 grandfather table.
func HF3(txid crypto.Hash) error {
	var key [64]byte
	hex.Encode(key[:], txid[:]) // the table is keyed by lower-case hex; m[string(b)] does not allocate
	if _, ok := blockchain.HF3_Affected_Txs[string(key[:])]; ok {
		hf3_table.Inc()
		return ErrHF3
	}
	return nil
}

// AdmitAt is the full relay/RPC admission policy for a decoded transaction against our tip: window, HF3 table, then
// the structural rules of Check, then add. txid is tx.GetHash(), passed in because the callers need it anyway (a
// GetHash re-serializes the header, ~7.6 us at ring 2), so the policy adds no hash computation to the honest path.
func AdmitAt(tx *transaction.Transaction, txid crypto.Hash, tip_height int64, add func(*transaction.Transaction) error) error {
	checked.Inc() // r23b merge: a window/HF3 refusal is a checked admission too
	if tx != nil && !tx.IsRegistration() && !tx.IsCoinbase() && !tx.IsPremine() {
		if err := Window(tx.Height, tip_height); err != nil {
			return err
		}
		if err := HF3(txid); err != nil {
			return err
		}
	}
	return admit(tx, add)
}
