// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

// r31 (cryptography area, rft §7 B278 / B283): wallet-side input checks for the curve-point decoders.
//
// The point decoders in cryptography/bn256 are consensus code and are not changed (consensus guard S1): the
// compressed decoder accepts flag bytes other than 0/1 and an x coordinate at or above P (detector-crypto-input
// findings, pinned by cryptography/bn256 TestR31CompressedDecodeClassCensus). Two wallet entry points decode points
// from text that is not a transaction and that no block or transaction check reads, so they can refuse
// non-canonical or inconsistent input locally:
//
//   - the wallet key file: Open_Encrypted_Wallet_Memory decodes _Keys.Public through Point.UnmarshalText (its only
//     JSON caller in the tree) and _Keys.Secret through BNRed.UnmarshalText. check_account_keys refuses a key pair
//     whose public key is not Secret*G (this covers every non-canonical public-key text: whatever it decoded to, it
//     must be the point the secret defines) and a secret that is zero modulo the group order (check_seed_scalar,
//     the rule account creation already applies).
//   - the receiver payment-proof check (VerifyReceivedPaymentProof, API only): the blinder and the ring members
//     arrive as address strings; canonical_address_key refuses one whose 33 key bytes are not the canonical
//     encoding of the point they decode to.
//
// Reach (why this is not consensus-visible): walletapi is imported by no package that decides block or transaction
// acceptance (blockchain/, transaction/, block/, cryptography/, proof/, dvm/, p2p/ import it nowhere; the importers
// are cmd/dero-wallet-cli, cmd/simulator, cmd/webwallet, cmd/rpc_examples/pong_server, walletapi/rpcserver and
// walletapi/xswd; elsewhere only test files: blockchain/r28_sc_flow_test.go, cmd/derod/rpc/*_test.go); the node
// never opens a wallet file or verifies a receiver proof.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

var (
	// ErrWalletKeysMissing: the decrypted account has no secret or no public key.
	ErrWalletKeysMissing = errors.New("wallet keys: secret or public key missing")
	// ErrWalletKeysMismatch: the stored public key is not the point the stored secret defines.
	ErrWalletKeysMismatch = errors.New("wallet keys: public key does not match the secret key")
	// ErrNonCanonicalKey: an address string whose key bytes are not the canonical encoding of the point they decode to.
	ErrNonCanonicalKey = errors.New("address: key is not canonically encoded")
)

// check_account_keys is run on every wallet open, after the account JSON is decoded.
func check_account_keys(k _Keys) error {
	if k.Secret == nil || k.Public == nil {
		return ErrWalletKeysMissing
	}
	if err := check_seed_scalar(k.Secret.BigInt()); err != nil {
		return fmt.Errorf("wallet keys: %v", err)
	}
	want := new(bn256.G1).ScalarMult(crypto.G, k.Secret.BigInt()).EncodeCompressed()
	if !bytes.Equal(want, k.Public.EncodeCompressed()) {
		return ErrWalletKeysMismatch
	}
	return nil
}

// address_key_bytes returns the 33 key bytes an address string carries (bech32 data after the version byte), before
// any point decoding.
func address_key_bytes(s string) ([]byte, error) {
	_, data, err := rpc.Decode(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	acc, bits := 0, uint(0)
	var out []byte
	for _, v := range data {
		if v < 0 || v>>5 != 0 {
			return nil, fmt.Errorf("address: invalid data")
		}
		acc = (acc<<5 | v) & 0xfff
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	if len(out) < 34 || out[0] != 1 {
		return nil, fmt.Errorf("address: invalid length or version")
	}
	return out[1:34], nil
}

// canonical_address_key decodes an address string and refuses it unless its key bytes re-encode exactly.
func canonical_address_key(s string) (*rpc.Address, error) {
	a, err := rpc.NewAddress(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	raw, err := address_key_bytes(s)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, a.PublicKey.EncodeCompressed()) {
		return nil, ErrNonCanonicalKey
	}
	return a, nil
}
