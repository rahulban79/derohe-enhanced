package walletapi

// r24 (cryptoinfl CI24-2, B32): a V2 receiver proof whose ephemeral key repeats another transaction's is withheld.

import (
	"crypto/rand"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/proof"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

func r24scalar(t *testing.T) *big.Int {
	k, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// r24entry builds the entry synchistory_block stores for an incoming V2 transfer whose payload starts with E: the
// receiver proof carries H = GenerateSharedSecret(sk, E), exactly as daemon_communication.go computes it.
func r24entry(sk *big.Int, E *bn256.G1, txid string, topo int64, typ byte) rpc.Entry {
	h := crypto.GenerateSharedSecret(sk, E)
	blinder := new(bn256.G1).ScalarMult(crypto.G, big.NewInt(int64(topo)+1))
	p := rpc.NewAddressFromKeys((*crypto.Point)(blinder))
	p.Proof = true
	p.Arguments = rpc.Arguments{{Name: "H", DataType: rpc.DataHash, Value: crypto.Hash(h)}, {Name: rpc.RPC_VALUE_TRANSFER, DataType: rpc.DataUint64, Value: uint64(5)}}
	return rpc.Entry{TopoHeight: topo, TransactionPos: 0, TXID: txid, Incoming: true, PayloadType: typ, Proof: p.String(), Amount: 5}
}

func r24wallet() *Wallet_Memory { return &Wallet_Memory{account: &Account{}} }

func r24stored(w *Wallet_Memory, scid crypto.Hash) []rpc.Entry { return w.account.EntriesNative[scid] }

func r24withheld(e rpc.Entry) bool { return strings.HasPrefix(e.Proof, r24WithheldProofPrefix) }

// KAT: copying an earlier transfer's E into a new transfer to the same wallet makes the wallet derive the same H, so
// the second entry's proof would carry the first payload's key. Both proofs are withheld; an unrelated entry is not.
func TestR24V2ReceiverProofRepeatIsWithheld(t *testing.T) {
	sk := r24scalar(t)
	E := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	F := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero crypto.Hash

	victim, copycat, other := r24entry(sk, E, "tx-victim", 10, V2), r24entry(sk, E, "tx-copy", 20, V2), r24entry(sk, F, "tx-other", 15, V2)
	if victim.Proof == copycat.Proof { // different blinders, same H
		t.Fatalf("test setup: identical proof strings")
	}
	k1, _, ok1 := r24V2ProofKey(&victim)
	k2, _, ok2 := r24V2ProofKey(&copycat)
	if !ok1 || !ok2 || k1 != k2 {
		t.Fatalf("repeated E must give the same index key: %v %v %x %x", ok1, ok2, k1, k2)
	}

	w := r24wallet()
	w.InsertReplace(zero, victim)
	w.InsertReplace(zero, other)
	if s := r24stored(w, zero); r24withheld(s[0]) || r24withheld(s[1]) {
		t.Fatalf("distinct ephemeral keys must keep their proofs")
	}
	w.InsertReplace(zero, copycat)
	s := r24stored(w, zero)
	if len(s) != 3 {
		t.Fatalf("stored %d entries", len(s))
	}
	for _, e := range s {
		want := e.TXID != "tx-other"
		if r24withheld(e) != want {
			t.Fatalf("entry %s withheld=%v want %v (proof %q)", e.TXID, r24withheld(e), want, e.Proof)
		}
		if want && strings.Contains(e.Proof, victim.Proof) {
			t.Fatalf("marker leaks the proof")
		}
	}
	// the marker is refused by the proof verifier, so nobody can mistake it for a proof
	if _, _, _, _, err := proof.Prove(s[2].Proof, "00", nil, true); err == nil {
		t.Fatalf("proof.Prove accepted a withheld marker")
	}
	// the honest proof still parses as a proof
	if a, err := rpc.NewAddress(s[1].Proof); err != nil || !a.Proof {
		t.Fatalf("unrelated proof damaged: %v", err)
	}
}

// the same TXID re-inserted (rescan / reorg re-insert) or a second payload of one transaction is not a repeat
func TestR24V2ReceiverProofSameTxidIsNotARepeat(t *testing.T) {
	sk := r24scalar(t)
	E := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero, token crypto.Hash
	token[0] = 1
	w := r24wallet()
	w.InsertReplace(zero, r24entry(sk, E, "tx-a", 10, V2))
	w.InsertReplace(zero, r24entry(sk, E, "tx-a", 10, V2))  // rescan: replaces
	w.InsertReplace(token, r24entry(sk, E, "tx-a", 10, V2)) // second payload of the same tx, other SCID
	for _, scid := range []crypto.Hash{zero, token} {
		for _, e := range r24stored(w, scid) {
			if r24withheld(e) {
				t.Fatalf("same-TXID entry withheld: %+v", e)
			}
		}
	}
	// v1 payloads bind D in the Statement proof: not indexed
	w2 := r24wallet()
	w2.InsertReplace(zero, r24entry(sk, E, "tx-1", 10, transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR))
	w2.InsertReplace(zero, r24entry(sk, E, "tx-2", 11, transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR))
	for _, e := range r24stored(w2, zero) {
		if r24withheld(e) {
			t.Fatalf("v1 entry withheld")
		}
	}
}

// a repeat across SCIDs (E copied into a token payload) is caught, and the marker survives a restart: a fresh index
// built from the stored entries withholds a re-synced copy of the earlier entry.
func TestR24V2ReceiverProofCrossScidAndRestart(t *testing.T) {
	sk := r24scalar(t)
	E := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero, token crypto.Hash
	token[0] = 7
	w := r24wallet()
	w.InsertReplace(zero, r24entry(sk, E, "tx-victim", 10, V2))
	w.InsertReplace(token, r24entry(sk, E, "tx-copy", 20, V2))
	if !r24withheld(r24stored(w, zero)[0]) || !r24withheld(r24stored(w, token)[0]) {
		t.Fatalf("cross-SCID repeat not withheld")
	}
	w.r24proofs = r24ProofIndex{} // restart: the index is not persisted, the markers are
	w.InsertReplace(zero, r24entry(sk, E, "tx-victim", 10, V2))
	if !r24withheld(r24stored(w, zero)[0]) {
		t.Fatalf("re-synced entry got its proof back after a restart")
	}
}

// entries stored before r24 that already repeat (the wallet file predates the guard) are withheld when the index is
// first built; a stale index entry (rescan truncated the holder away) does not withhold a lone survivor.
func TestR24V2ReceiverProofPreexistingAndStale(t *testing.T) {
	sk := r24scalar(t)
	E := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	G2 := new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero crypto.Hash
	w := r24wallet()
	w.account.EntriesNative = map[crypto.Hash][]rpc.Entry{zero: {r24entry(sk, E, "tx-a", 10, V2), r24entry(sk, E, "tx-b", 20, V2)}}
	w.InsertReplace(zero, r24entry(sk, G2, "tx-c", 30, V2)) // builds the index
	s := r24stored(w, zero)
	if !r24withheld(s[0]) || !r24withheld(s[1]) || r24withheld(s[2]) {
		t.Fatalf("pre-existing repeat: %v %v %v", r24withheld(s[0]), r24withheld(s[1]), r24withheld(s[2]))
	}

	w2 := r24wallet()
	w2.InsertReplace(zero, r24entry(sk, E, "tx-old", 10, V2))
	w2.account.EntriesNative[zero] = nil // a rescan dropped it (InsertReplace truncation), the index still names it
	w2.InsertReplace(zero, r24entry(sk, E, "tx-new", 12, V2))
	if r24withheld(r24stored(w2, zero)[0]) {
		t.Fatalf("stale index entry withheld a lone proof")
	}
}

// cost of the guard: one proof parse per incoming V2 entry, and the one-time index build over a wallet's entries
func BenchmarkR24V2ProofGuard(b *testing.B) {
	sk, _ := rand.Int(rand.Reader, bn256.Order)
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero crypto.Hash
	mk := func(n int) []rpc.Entry {
		es := make([]rpc.Entry, n)
		for i := range es {
			s, _ := rand.Int(rand.Reader, bn256.Order)
			es[i] = r24entry(sk, new(bn256.G1).ScalarMult(crypto.G, s), "tx"+string(rune('a'+i%26))+big.NewInt(int64(i)).String(), int64(i), V2)
		}
		return es
	}
	one := mk(1)[0]
	b.Run("key", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r24V2ProofKey(&one)
		}
	})
	stored := mk(2000)
	b.Run("build2000", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			w := r24wallet()
			w.account.EntriesNative = map[crypto.Hash][]rpc.Entry{zero: stored}
			w.r24GuardV2Proof(&one)
		}
	})
	coinbase := rpc.Entry{Coinbase: true, Incoming: true}
	b.Run("non_v2", func(b *testing.B) {
		w := r24wallet()
		for i := 0; i < b.N; i++ {
			w.r24GuardV2Proof(&coinbase)
		}
	})
}

// the fast reader agrees with rpc.NewAddress on every proof the wallet makes, and refuses what NewAddress refuses
func TestR24ProofArgumentsMatchesNewAddress(t *testing.T) {
	sk := r24scalar(t)
	for i := 0; i < 64; i++ {
		e := r24entry(sk, new(bn256.G1).ScalarMult(crypto.G, r24scalar(t)), "tx", int64(i), transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2)
		a, err := rpc.NewAddress(e.Proof)
		args, ok := r24ProofArguments(e.Proof)
		if err != nil || !ok || !reflect.DeepEqual(a.Arguments, args) {
			t.Fatalf("mismatch: %v %v %v %v", err, ok, a.Arguments, args)
		}
		bad := []byte(e.Proof)
		bad[len(bad)-3] ^= 1 // checksum
		if _, ok := r24ProofArguments(string(bad)); ok {
			t.Fatalf("corrupt proof accepted")
		}
	}
	plain := rpc.NewAddressFromKeys((*crypto.Point)(crypto.G))
	if _, ok := r24ProofArguments(plain.String()); ok {
		t.Fatalf("a plain address is not a proof")
	}
	integrated := rpc.NewAddressFromKeys((*crypto.Point)(crypto.G)) // deroi1...: same layout, not a proof
	integrated.Arguments = rpc.Arguments{{Name: "H", DataType: rpc.DataHash, Value: crypto.Hash{1}}}
	if s := integrated.String(); !strings.HasPrefix(s, "deroi1") {
		t.Fatalf("test setup: %s", s)
	} else if _, ok := r24ProofArguments(s); ok {
		t.Fatalf("an integrated address is not a proof")
	}
}

// the guard rewrites stored entries in place: readers (RPC goroutines, RLock) must not race with it (-race)
func TestR24V2ReceiverProofGuardVsReaders(t *testing.T) {
	sk := r24scalar(t)
	V2 := transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	var zero crypto.Hash
	w := r24wallet()
	Es := make([]*bn256.G1, 40)
	for i := range Es {
		Es[i] = new(bn256.G1).ScalarMult(crypto.G, r24scalar(t))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 80; i++ { // each E arrives twice under different TXIDs
			w.InsertReplace(zero, r24entry(sk, Es[i%40], "tx-"+big.NewInt(int64(i)).String(), int64(i), V2))
		}
	}()
	for {
		select {
		case <-done:
			n := 0
			for _, e := range w.Show_Transfers(zero, true, true, true, 0, 0, "", "", 0, 0) {
				if r24withheld(e) {
					n++
				}
			}
			if n != 80 {
				t.Fatalf("%d of 80 withheld", n)
			}
			return
		default:
			_ = w.Show_Transfers(zero, true, true, true, 0, 0, "", "", 0, 0)
			_ = w.GetTXKey("tx-3")
		}
	}
}
