package transaction

// R31 dimension 6 (rft §7 B281, detector fuzz-coverage DF-fuzz-coverage-4a1b9d2dcf, area cryptosupply):
// AssetPayload.UnmarshalProofs had no Go fuzz target. The target is seeded with the proofs of a real mainnet body
// (the HF3 fixture of glue/emission) and with short and garbage inputs; the decoder must never panic. The real body
// pins the proof length the decoder derives from the statement (log2 of the ring size). Consensus code is not changed.
//
// TestR31DeserializeUnknownTypePanics pins today's behaviour of the medium error-paths finding DF-error-paths-
// d4574fb76e (transaction.go:321 panics on an unknown type instead of returning an error). Changing a consensus
// decoder is a disclosure-style item (rft §0.5); the RPC header peek (glue/txprecheck) refuses such a body before
// Deserialize and the emission auditor's DecodeTx recovers it.

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func r31RealBody(t testing.TB) []byte {
	h, err := os.ReadFile("../glue/emission/testdata/hf3_414f79b8.tx.hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func r31Proofs(t testing.TB) (tx Transaction, proofs [][]byte) {
	if err := tx.Deserialize(r31RealBody(t)); err != nil {
		t.Fatalf("real body does not decode: %v", err)
	}
	for _, p := range tx.Payloads {
		b, err := p.MarshalProofs()
		if err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, b)
	}
	return
}

func FuzzR31UnmarshalProofs(f *testing.F) {
	_, proofs := r31Proofs(f)
	for _, p := range proofs {
		f.Add(p, uint8(4), uint8(32)) // the fixture's ring (16 members), 32 bytes per key pointer
		f.Add(p[:len(p)/2], uint8(4), uint8(32))
	}
	f.Add([]byte{}, uint8(1), uint8(1))
	f.Add(bytes.Repeat([]byte{0xff}, 1500), uint8(7), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, ringPow uint8, bpp uint8) {
		var a AssetPayload
		a.Statement.Bytes_per_publickey = 1 + bpp%32
		a.Statement.Publickeylist_pointers = make([]byte, (1<<(1+ringPow%7))*int(a.Statement.Bytes_per_publickey))
		_ = a.UnmarshalProofs(bytes.NewReader(data)) // a panic fails the target
	})
}

// the real body's proofs re-decode with the statement's own ring size, consume exactly their bytes and re-encode
// byte for byte
func TestR31UnmarshalProofsRealBody(t *testing.T) {
	tx, proofs := r31Proofs(t)
	for i, p := range proofs {
		a := AssetPayload{Statement: tx.Payloads[i].Statement}
		r := bytes.NewReader(append(append([]byte{}, p...), 0xAA)) // one trailing byte must stay unread
		if err := a.UnmarshalProofs(r); err != nil {
			t.Fatalf("payload %d: %v", i, err)
		}
		if r.Len() != 1 {
			t.Fatalf("payload %d: %d bytes left, want 1", i, r.Len())
		}
		again, _ := a.MarshalProofs()
		if !bytes.Equal(again, p) {
			t.Fatalf("payload %d: proof does not re-encode", i)
		}
	}
}

func TestR31DeserializeUnknownTypePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("premise changed: an unknown type no longer panics (move DF-error-paths-d4574fb76e to fixed)")
		}
	}()
	var tx Transaction
	_ = tx.Deserialize([]byte{1, 0, 0, 99}) // version 1, networks 0/0, transaction type 99
}
