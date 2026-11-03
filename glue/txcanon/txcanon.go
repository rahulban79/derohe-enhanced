// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package txcanon is a node-local relay policy (Round 22): a transaction is admitted to the mempool only if the
// bytes this node will later send for it (Transaction.Serialize, used by relays, chunk/compact block propagation
// and the tx store) decode back to the same transaction.
//
// Why: the compressed-point decoder (cryptography/bn256 changes.go, consensus code) accepts an x coordinate >= P
// and silently returns the point at infinity, while the point at infinity itself compresses to 33 zero bytes
// that do NOT decode (3 is a quadratic non-residue mod P). A transaction that carries such an encoding decodes
// and may pass every consensus check (not tested end to end), but its re-serialization is undecodable by every node. If it entered our
// mempool, a block template built from it would yield a block whose transactions no peer can decode: our mined
// block would not propagate.
//
// Consensus effect: none. Which transactions and blocks are valid is unchanged (blocks are validated exactly as
// before, whoever mined them); this only decides what this node puts into its own mempool and relays. Every
// transaction relayed by a stock node is already in Serialize form (p2p/rpc_object_request.go), so honest traffic
// always takes the fast path (one Serialize and a byte compare).
//
// Residual hazard (r22 merge, C1 review), not covered here: blockchain.go:911 stores tx.Serialize() bytes for every tx
// of an accepted block, including blocks mined by OTHERS. If another miner ever included an x >= P tx, this node's own
// tx store would hold undecodable bytes for it. This package only protects our mempool and our block templates; the
// fix is upstream (reject x >= P and flag bytes > 1 in Decompress, with coordinated activation). Also unverified: that
// such a tx passes every consensus check end to end - the decode behaviour is tested, the full acceptance is not.
package txcanon

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/glue/txpolicy"
	"github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/transaction"
)

// ErrNotRoundTrip is returned for a transaction whose canonical bytes do not decode back to it.
var ErrNotRoundTrip = errors.New("transaction encoding does not survive re-serialization (non-canonical point encoding); not relayed")

var (
	nonCanonical = metrics.Set.NewCounter("tx_noncanonical_encoding_total")           // accepted: re-encodes to an equivalent tx
	rejected     = metrics.Set.NewCounter("tx_noncanonical_roundtrip_rejected_total") // refused: re-encoding is undecodable/different
)

// decode is transaction.Deserialize with its panics turned into errors (the decoder panics on several inputs).
func decode(tx *transaction.Transaction, buf []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("transaction could not be decoded: %v", r)
		}
	}()
	return tx.Deserialize(buf)
}

// serialize is tx.Serialize with its panics turned into errors.
func serialize(tx *transaction.Transaction) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("transaction could not be serialized: %v", r)
		}
	}()
	return tx.Serialize(), nil
}

// ErrNonCanonicalRegistration is returned for a registration whose key bytes are not the canonical compression of the
// point they decode to, or whose Schnorr response is not reduced (Round 23b).
//
// Why: IsRegistrationValid (transaction.go) decodes MinerAddress and signs over the DECODED point's String(), never
// over the 33 raw bytes, and the decoder accepts 254 flag-byte aliases of every x (r22: they all decode to the same
// root) and x >= P (decodes to the identity). Registration then stores the RAW bytes as the balance-tree key
// (transaction_execute.go), so an alias encoding would register a second account for a public key that already has
// one, under a key no wallet ever computes (wallets look accounts up by EncodeCompressed). S is likewise not range
// checked: S + k*Order verifies too. The mainnet tree had 0 alias keys (r22 scan), so this is latent; consensus still
// accepts such a registration inside a block. This node only refuses to put one into its regpool or relay it.
var ErrNonCanonicalRegistration = errors.New("registration key is not a canonical point encoding or its signature is not reduced; not relayed")

var regRejected = metrics.Set.NewCounter("tx_registration_noncanonical_rejected_total")

// registration_canonical reports whether a REGISTRATION tx carries the canonical encoding of its key and S < Order.
// Other tx types pass.
func registration_canonical(tx *transaction.Transaction) bool {
	if tx.TransactionType != transaction.REGISTRATION {
		return true
	}
	var u bn256.G1
	if err := u.DecodeCompressed(tx.MinerAddress[:]); err != nil {
		return false // IsRegistrationValid refuses it as well
	}
	if !bytes.Equal(u.EncodeCompressed(), tx.MinerAddress[:]) {
		return false
	}
	return new(big.Int).SetBytes(tx.S[:]).Cmp(bn256.Order) < 0 && new(big.Int).SetBytes(tx.C[:]).Cmp(bn256.Order) < 0
}

// Check reports whether tx, decoded from raw, may enter the mempool. canonical is true when raw is exactly the
// node's own encoding of tx. A non-canonical encoding is still accepted when its canonical form decodes back to a
// transaction with the same txid and the same canonical bytes (e.g. an undefined point flag byte); otherwise the
// error is ErrNotRoundTrip.
func Check(raw []byte, tx *transaction.Transaction) (canonical bool, err error) {
	if !registration_canonical(tx) {
		regRejected.Inc()
		return false, ErrNonCanonicalRegistration
	}
	canonical, err = roundtrip(raw, tx)
	switch {
	case err != nil:
		rejected.Inc()
	case !canonical:
		nonCanonical.Inc()
	}
	return canonical, err
}

// roundtrip is Check without the mempool counters.
func roundtrip(raw []byte, tx *transaction.Transaction) (canonical bool, err error) {
	ser, err := serialize(tx)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrNotRoundTrip, err)
	}
	if bytes.Equal(raw, ser) {
		return true, nil
	}
	var back transaction.Transaction
	if err = decode(&back, ser); err != nil {
		return false, fmt.Errorf("%w: %v", ErrNotRoundTrip, err)
	}
	ser2, err := serialize(&back)
	if err != nil || back.GetHash() != tx.GetHash() || !bytes.Equal(ser2, ser) {
		return false, ErrNotRoundTrip
	}
	return false, nil
}

var (
	blockNonCanonical = metrics.Set.NewCounter("block_tx_noncanonical_encoding_total") // block tx, re-encodes equivalently
	blockBroken       = metrics.Set.NewCounter("block_tx_roundtrip_broken_total")      // block tx our store cannot serve back
	blockObserved     = metrics.Set.NewCounter("block_tx_roundtrip_observed_total")    // block txs checked
)

// Observe runs the round-trip check on a transaction that arrived inside a BLOCK (Round 23). It never refuses
// anything: blocks are validated by consensus code exactly as before, whoever mined them. It only counts, so an
// operator can alert on block_tx_roundtrip_broken_total > 0: the residual hazard documented above (an accepted block
// whose tx this node stores as bytes no node can decode) would otherwise be silent until a peer failed to sync
// from us. It returns the check's verdict for tests and logging.
func Observe(raw []byte, tx *transaction.Transaction) error {
	blockObserved.Inc()
	canonical, err := roundtrip(raw, tx)
	switch {
	case err != nil:
		blockBroken.Inc()
	case !canonical:
		blockNonCanonical.Inc()
	}
	return err
}

// Admit wraps a mempool admission function with Check.
// r24: then with the node-local admission policy (glue/txpolicy: shared verification of identical bytes, known-invalid
// bytes, pool cap with fee-rate eviction), which is a pass-through until derod calls txpolicy.Attach.
func Admit(raw []byte, tx *transaction.Transaction, add func(*transaction.Transaction) error) error {
	if _, err := Check(raw, tx); err != nil {
		return err
	}
	return txpolicy.Admit(raw, tx, add)
}
