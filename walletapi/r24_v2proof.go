package walletapi

// r24 (cryptoinfl CI24-2, backlog B32 / r23c verifier CI-9): wallet-local mitigation for the receiver-proof key oracle.
//
// For an incoming ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2 transfer the wallet stores a receiver proof whose H argument is
// H = Keccak256(compressed(sk*E)) (crypto.GenerateSharedSecret, cryptography/crypto/userdata.go:48-56), E being the
// first 33 bytes of the payload (daemon_communication.go, synchistory_block, V2 case). The payload key is Keccak256(H, receiver_pub), and E is not
// bound by the transfer's Statement proof (unlike D for v1 payloads). So a later transfer to this wallet that repeats
// the E of an earlier V2 transfer to this wallet makes the wallet store the same H on both entries, and handing out
// the second entry's receiver proof would disclose the key of the first entry's payload. Payload privacy only:
// amounts, balances and keys are not affected, and nothing here is consensus-visible.
//
// Mitigation: the wallet remembers K = Keccak256(tag, H) for every V2 receiver proof it stores (never H itself). When
// two entries with DIFFERENT TXIDs carry the same K, the receiver proof of every entry carrying K is replaced by a
// marker (r24WithheldProofPrefix + hex K) that proof.Prove refuses. Entries of the same TXID (a rescan or a reorg
// re-insert of the same transaction, or two payloads of one transaction built with one ring order by an old wallet)
// are not a repeat. An honest sender derives E from its secret, the tree root and the ring
// (transaction_build.go ephemeral_key/ephemeral_seed), so two honest on-chain transfers with different TXIDs and the
// same E would need the same sender, root hash and ring: a nonce double-spend, of which only one can be on chain.
// The marker persists in the wallet file, so the index rebuilt after a restart still withholds a re-synced entry.

import (
	"encoding/hex"
	"strings"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

const r24WithheldProofPrefix = "withheld-r24-v2-ephemeral-repeat:"

var r24ProofKeyTag = []byte("r24 v2 receiver proof key index")

// r24ProofIndex maps K to the TXID that first carried it; built lazily from the stored entries (all SCIDs: a repeated
// E may sit in a token payload) and kept under the wallet's write lock (InsertReplace).
type r24ProofIndex struct {
	built    bool
	first    map[crypto.Hash]string
	withheld map[crypto.Hash]bool
}

// r24V2ProofKey returns K for an incoming V2 entry whose receiver proof carries H, or ok=false. A withheld marker
// returns its K with withheld=true.
func r24V2ProofKey(e *rpc.Entry) (k crypto.Hash, withheld bool, ok bool) {
	if !e.Incoming || e.Coinbase || e.PayloadType != transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2 || e.Proof == "" {
		return
	}
	if strings.HasPrefix(e.Proof, r24WithheldProofPrefix) {
		b, err := hex.DecodeString(e.Proof[len(r24WithheldProofPrefix):])
		if err != nil || len(b) != len(k) {
			return
		}
		copy(k[:], b)
		return k, true, true
	}
	args, good := r24ProofArguments(e.Proof)
	if !good || !args.Has(rpc.DataHash, rpc.DataHash) {
		return
	}
	h, isHash := args.Value(rpc.DataHash, rpc.DataHash).(crypto.Hash)
	if !isHash {
		return
	}
	return crypto.Keccak256(r24ProofKeyTag, h[:]), false, true
}

// r24ProofArguments reads the arguments of a "deroproof" string the way rpc.Address.UnmarshalText does (bech32,
// checksum, version 1, 33 key bytes, CBOR arguments) but without decompressing the key point: the guard needs only
// H, and the point's square root made rpc.NewAddress cost ~49 us per entry (BenchmarkR24V2ProofGuard).
func r24ProofArguments(s string) (args rpc.Arguments, ok bool) {
	hrp, data, err := rpc.Decode(s)
	if err != nil || hrp != "deroproof" {
		return nil, false
	}
	var out []byte
	acc, bits := 0, 0
	for _, v := range data {
		if v < 0 || v > 31 {
			return nil, false
		}
		acc = acc<<5 | v
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	if bits >= 5 || acc != 0 { // the same padding rule as rpc convertbits(pad=false)
		return nil, false
	}
	if len(out) < 1+33 || out[0] != 1 {
		return nil, false
	}
	if err = args.UnmarshalBinary(out[1+33:]); err != nil {
		return nil, false
	}
	return args, true
}

func r24Withhold(e *rpc.Entry, k crypto.Hash) {
	e.Proof = r24WithheldProofPrefix + hex.EncodeToString(k[:])
}

func (x *r24ProofIndex) note(e *rpc.Entry) {
	k, withheld, ok := r24V2ProofKey(e)
	if !ok {
		return
	}
	if withheld {
		x.withheld[k] = true
		return
	}
	if txid, seen := x.first[k]; !seen {
		x.first[k] = e.TXID
	} else if txid != e.TXID {
		x.withheld[k] = true
	}
}

// r24GuardV2Proof runs inside InsertReplace with w's write lock held, before e is stored.
func (w *Wallet_Memory) r24GuardV2Proof(e *rpc.Entry) {
	k, withheld, ok := r24V2ProofKey(e)
	if !ok || withheld {
		return
	}
	x := &w.r24proofs
	if !x.built {
		x.first, x.withheld = map[crypto.Hash]string{}, map[crypto.Hash]bool{}
		for _, entries := range w.account.EntriesNative {
			for i := range entries {
				x.note(&entries[i])
			}
		}
		x.built = true
		for k := range x.withheld { // repeats already in the file (stored before r24): withhold them now
			w.r24WithholdStored(k)
		}
	}
	if x.withheld[k] {
		r24Withhold(e, k)
		return
	}
	txid, seen := x.first[k]
	if !seen || txid == e.TXID {
		x.first[k] = e.TXID
		return
	}
	// a different TXID holds K, unless a rescan truncated that entry away: then K is free again
	if !w.r24StoredCarries(k, txid) {
		x.first[k] = e.TXID
		return
	}
	x.withheld[k] = true
	w.r24WithholdStored(k)
	r24Withhold(e, k)
}

func (w *Wallet_Memory) r24StoredCarries(k crypto.Hash, txid string) bool {
	for _, entries := range w.account.EntriesNative {
		for i := range entries {
			if entries[i].TXID != txid {
				continue
			}
			if ek, _, ok := r24V2ProofKey(&entries[i]); ok && ek == k {
				return true
			}
		}
	}
	return false
}

func (w *Wallet_Memory) r24WithholdStored(k crypto.Hash) {
	for _, entries := range w.account.EntriesNative {
		for i := range entries {
			if ek, withheld, ok := r24V2ProofKey(&entries[i]); ok && !withheld && ek == k {
				r24Withhold(&entries[i], k)
			}
		}
	}
}
