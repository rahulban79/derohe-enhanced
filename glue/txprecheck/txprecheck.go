// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package txprecheck is a node-local mempool-admission policy (Round 23): it refuses, before any state is read, a
// transfer that consensus is certain to refuse for its structure.
//
// Why: blockchain.Add_TX_To_Pool runs Verify_Transaction_NonCoinbase_CheckNonce_Tips (blockchain.go:1344: a block
// file directory scan for tx.BLID, a balance snapshot load per tip and graviton lookups per ring member) BEFORE
// verify_Transaction_NonCoinbase_internal reaches its pure structural checks (transaction_verify.go:225-319). A
// relayed transaction with, say, a duplicated ring member or no DERO payload therefore costs state reads before it
// is refused. Every rule here is one of those structural checks restated, so this package refuses exactly a subset
// of what consensus refuses: it can never keep a valid transaction out of the mempool, and it has no effect on
// block validation (blocks are verified by the unchanged consensus code whoever mined them).
//
// Rules, with the consensus line (blockchain/transaction_verify.go) that refuses the same transaction:
//   - version != 1                                       :226
//   - BURN_TX with Value 0                               :263
//   - no payload                                         :273
//   - no DERO (zero SCID) payload                        :285
//   - payloads with different Roothash                   :290
//   - Bytes_per_publickey 0 (division by zero; the recover at :218 refuses)
//   - RingSize != len(pointers)/Bytes_per_publickey      :297
//   - RingSize < 2 or > 128                              :301, :305
//   - ring size not a power of two                       :309
//   - duplicate ring member pointers                     :319
//   - fewer commitments than ring members or nil D (indexed at :419/:421 under the recover at :218), nil proof
//     (Proof.Parity() at :140 under the recover in CheckNonce_Tips)
//
// The decoder (crypto.Statement.Deserialize) already forces a power-of-two ring <= 128 and an exact pointer count,
// so for decoded traffic the live rules are: version, zero burn, missing base, roothash, ring size 1, duplicates.
//
// Registration, premine and coinbase transactions are passed through untouched.
package txprecheck

import (
	"errors"
	"fmt"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// ErrStructure wraps every refusal.
var ErrStructure = errors.New("transaction refused before verification: consensus rejects its structure")

func refuse(reason string, f string, a ...interface{}) error {
	metrics.Set.GetOrCreateCounter(fmt.Sprintf(`tx_precheck_refused_total{reason=%q}`, reason)).Inc()
	return fmt.Errorf("%w: %s", ErrStructure, fmt.Sprintf(f, a...))
}

// Check returns nil when tx may go on to full verification, or an ErrStructure error naming the rule it breaks.
func Check(tx *transaction.Transaction) error {
	if tx == nil {
		return refuse("nil", "nil transaction")
	}
	switch tx.TransactionType {
	case transaction.NORMAL, transaction.SC_TX, transaction.BURN_TX:
	default:
		return nil
	}
	if tx.Version != 1 {
		return refuse("version", "version %d", tx.Version)
	}
	if tx.TransactionType == transaction.BURN_TX && tx.Value == 0 {
		return refuse("burn_zero", "burn value is zero")
	}
	if len(tx.Payloads) < 1 {
		return refuse("no_payload", "no payload")
	}
	hasBase := false
	for i := range tx.Payloads {
		if tx.Payloads[i].SCID.IsZero() {
			hasBase = true
		}
	}
	if !hasBase {
		return refuse("no_base", "no DERO payload to pay the fee from")
	}
	for t := range tx.Payloads {
		if tx.Payloads[t].Statement.Roothash != tx.Payloads[0].Statement.Roothash {
			return refuse("roothash", "payload %d built on a different state", t)
		}
	}
	for t := range tx.Payloads {
		st := &tx.Payloads[t].Statement
		bpp := int(st.Bytes_per_publickey)
		if bpp == 0 {
			return refuse("ring", "payload %d: zero bytes per key pointer", t)
		}
		n := len(st.Publickeylist_pointers) / bpp
		if st.RingSize != uint64(n) {
			return refuse("ring", "payload %d: ring size %d but %d pointers", t, st.RingSize, n)
		}
		if st.RingSize < 2 || st.RingSize > 128 {
			return refuse("ring", "payload %d: ring size %d outside 2..128", t, st.RingSize)
		}
		if !crypto.IsPowerOf2(n) {
			return refuse("ring", "payload %d: ring size %d not a power of two", t, n)
		}
		seen := make(map[string]bool, n)
		for i := 0; i < n; i++ {
			seen[string(st.Publickeylist_pointers[i*bpp:(i+1)*bpp])] = true
		}
		if len(seen) != n {
			return refuse("ring_duplicate", "payload %d: duplicate ring member", t)
		}
		if uint64(len(st.C)) < st.RingSize || st.D == nil || tx.Payloads[t].Proof == nil {
			return refuse("statement", "payload %d: incomplete statement", t)
		}
	}
	return nil
}

// checked counts every Admit/AdmitAt call (the relay and RPC paths; r23b forensics). Txs that re-enter the pool
// another way (a popped block's txs) are not counted. The refusal counters are created
// on first use, so before this counter a live node showed no tx_precheck metric at all and the precheck's presence
// on the relay and RPC paths could not be told from its absence (live r23, 2026-10-30: 0 refusals in 12 h).
var checked = metrics.Set.NewCounter("tx_precheck_checked_total")

// Admit wraps a mempool admission function with Check.
func Admit(tx *transaction.Transaction, add func(*transaction.Transaction) error) error {
	checked.Inc()
	return admit(tx, add)
}

func admit(tx *transaction.Transaction, add func(*transaction.Transaction) error) error {
	if err := Check(tx); err != nil {
		return err
	}
	return add(tx)
}
