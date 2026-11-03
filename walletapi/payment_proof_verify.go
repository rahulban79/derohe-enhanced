// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package walletapi

// Receiver-side payment-proof verification (Round 23, crypto audit finding C4).
//
// A "deroproof" string carries a blinder B and an amount v. proof.Prove (format code in a guarded package, not
// changed) accepts it when C[k] == v*G + B for some ring member k. Nothing binds B to the transaction, so a third
// party can be shown a restated proof for ANY amount: B' = C[k] - v'*G satisfies the same equation.
//
// The honest blinder is B = r*Y_k, where D = r*G is in the statement and Y_k = sk*G is the receiver's key. So the
// receiver, and only the receiver, can check B == sk*D. With B authenticated, v*G = C[k] - B is fixed and, for
// v < 2^64, so is v. This needs no format change and no consensus change: it is a wallet-local check that a payee
// (merchant, exchange) runs on a proof a payer presents. Third parties (explorers) still cannot authenticate the
// amount; that would need a DLEQ proof in a new proof format.
//
// Burn: the sender's wallet states amount = value + burn and B = C[k] - (value+burn)*G = r*Y_k - burn*G
// (daemon_communication.go, the proof generator). The binding is therefore B + burn*G == sk*D, and the authenticated
// RECEIVED amount is amount - burn (r23 merge: without the burn term an honest proof of a transfer with Burn > 0 was
// refused as restated).
//
// Status: API only. No wallet RPC or CLI command calls VerifyReceivedPaymentProof yet.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/proof"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

var (
	// ErrProofNotForThisWallet: no ring member of the transaction is this wallet, so the receiver check cannot run.
	ErrProofNotForThisWallet = errors.New("payment proof: this wallet is not a ring member of the transaction")
	// ErrProofNotBound: the proof equation holds but its blinder is not the one this transaction created for us,
	// i.e. the proof was restated and its amount is not authenticated.
	ErrProofNotBound = errors.New("payment proof: blinder is not bound to the transaction (restated proof, amount not authenticated)")
	// ErrProofNoMatch: the proof does not open any commitment that belongs to this wallet.
	ErrProofNoMatch = errors.New("payment proof: does not match any commitment to this wallet")
)

// parse_payment_proof extracts (B, v) from a deroproof string.
func parse_payment_proof(proof_str string) (blinder *bn256.G1, amount uint64, err error) {
	addr, err := rpc.NewAddress(strings.TrimSpace(proof_str))
	if err != nil {
		return nil, 0, err
	}
	if !addr.Proof || !addr.IsIntegratedAddress() || !addr.Arguments.Has(rpc.RPC_VALUE_TRANSFER, rpc.DataUint64) {
		return nil, 0, fmt.Errorf("payment proof: not a deroproof with an amount")
	}
	amount = addr.Arguments.Value(rpc.RPC_VALUE_TRANSFER, rpc.DataUint64).(uint64)
	if err = proof.ValidatePayloadProofAmount(amount); err != nil {
		return nil, 0, fmt.Errorf("payment proof: %v", err)
	}
	return addr.PublicKey.G1(), amount, nil
}

// verify_received_proof is the receiver check on parsed inputs. ring[t] lists the ring members of payload t in
// statement order; secret is the receiver's private key. It returns the authenticated received amount (the proof's
// amount minus the payload's burn) and the payload index.
func verify_received_proof(blinder *bn256.G1, amount uint64, tx *transaction.Transaction, ring [][]*bn256.G1, secret *big.Int) (uint64, int, error) {
	mine := new(bn256.G1).ScalarMult(crypto.G, secret).EncodeCompressed()
	expect := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(amount)), blinder).EncodeCompressed()
	member, opened := false, false
	for t := range tx.Payloads {
		if t >= len(ring) {
			break
		}
		st := &tx.Payloads[t].Statement
		for k := range ring[t] {
			if ring[t][k] == nil || k >= len(st.C) || st.C[k] == nil || !bytes.Equal(ring[t][k].EncodeCompressed(), mine) {
				continue
			}
			member = true
			if !bytes.Equal(st.C[k].EncodeCompressed(), expect) {
				continue
			}
			opened = true
			if st.D == nil {
				continue
			}
			// the binding: B + burn*G must be sk*D for the D of this very statement
			burn := tx.Payloads[t].BurnValue
			if burn > amount {
				continue
			}
			bound := blinder
			if burn > 0 {
				bound = new(bn256.G1).Add(blinder, new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(burn)))
			}
			if bytes.Equal(new(bn256.G1).ScalarMult(st.D, secret).EncodeCompressed(), bound.EncodeCompressed()) {
				return amount - burn, t, nil
			}
		}
	}
	switch {
	case !member:
		return 0, -1, ErrProofNotForThisWallet
	case opened:
		return 0, -1, ErrProofNotBound
	default:
		return 0, -1, ErrProofNoMatch
	}
}

// VerifyReceivedPaymentProof authenticates the amount of a payment proof that names this wallet as the receiver.
// tx_hex is the transaction and ring the ring members of each payload (as GetTransaction returns them), the same
// inputs proof.Prove takes. Unlike proof.Prove, a restated proof (same transaction, other amount) is refused.
func (w *Wallet_Memory) VerifyReceivedPaymentProof(proof_str, tx_hex string, ring [][]string) (amount uint64, err error) {
	if w == nil || w.account == nil {
		return 0, fmt.Errorf("payment proof: wallet is not open")
	}
	blinder, amount, err := parse_payment_proof(proof_str)
	if err != nil {
		return 0, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(tx_hex))
	if err != nil {
		return 0, err
	}
	var tx transaction.Transaction
	if err = tx.Deserialize(raw); err != nil {
		return 0, err
	}
	keys := make([][]*bn256.G1, len(ring))
	for t := range ring {
		for _, s := range ring[t] {
			a, err := rpc.NewAddress(s)
			if err != nil {
				return 0, err
			}
			keys[t] = append(keys[t], a.PublicKey.G1())
		}
	}
	amount, _, err = verify_received_proof(blinder, amount, &tx, keys, w.account.Keys.Secret.BigInt())
	return amount, err
}
