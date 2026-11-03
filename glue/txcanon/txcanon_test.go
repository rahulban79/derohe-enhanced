// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/transaction"
)

// synth builds the wire bytes of a structurally well-formed NORMAL transaction with one ring-2 payload. Every
// point is a distinct multiple of G and every scalar a small number; the proof does not verify (it is never
// verified here), only the encoding matters. point(i) may be replaced to plant a specific encoding at index i.
type synth struct {
	idx      int
	override map[int][]byte
}

func (s *synth) point(buf *bytes.Buffer) {
	s.idx++
	if o, ok := s.override[s.idx]; ok {
		buf.Write(o)
		return
	}
	buf.Write(new(bn256.G1).ScalarBaseMult(big.NewInt(int64(s.idx))).EncodeCompressed())
}

func scalar(buf *bytes.Buffer, v int64) {
	var b [32]byte
	big.NewInt(v).FillBytes(b[:])
	buf.Write(b[:])
}

func uv(buf *bytes.Buffer, v uint64) {
	var b [binary.MaxVarintLen64]byte
	buf.Write(b[:binary.PutUvarint(b[:], v)])
}

// C[0] of the statement is point index 2 (D is index 1)
const idxC0 = 2

func (s *synth) bytes() []byte {
	var b bytes.Buffer
	uv(&b, 1)                               // version
	uv(&b, 0)                               // source network
	uv(&b, 0)                               // dest network
	uv(&b, uint64(transaction.NORMAL))      // type
	uv(&b, 1000)                            // height
	b.Write(bytes.Repeat([]byte{0x11}, 32)) // BLID
	uv(&b, 1)                               // asset count
	uv(&b, 0)                               // burn
	b.Write(make([]byte, 32))               // SCID
	b.WriteByte(transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2)
	b.Write(bytes.Repeat([]byte{0x22}, transaction.PAYLOAD_LIMIT))
	b.WriteByte(1)                          // ring 2 = 1<<1
	b.WriteByte(4)                          // bytes per public key
	uv(&b, 100)                             // fees
	s.point(&b)                             // D
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // 2 pointers x 4 bytes
	s.point(&b)                             // C[0]
	s.point(&b)                             // C[1]
	b.Write(bytes.Repeat([]byte{0x33}, 32)) // roothash
	for i := 0; i < 4; i++ {                // BA BS A B
		s.point(&b)
	}
	for i := 0; i < 8; i++ { // m=1: CLnG CRnG C_0G DG y_0G gG C_XG y_XG
		s.point(&b)
	}
	s.point(&b) // u
	scalar(&b, 5)
	scalar(&b, 6)                   // f (2m)
	scalar(&b, 7)                   // z_A
	s.point(&b)                     // T_1
	s.point(&b)                     // T_2
	for i := int64(0); i < 7; i++ { // that mu c s_sk s_r s_b s_tau
		scalar(&b, 10+i)
	}
	scalar(&b, 20)
	scalar(&b, 21) // ip a, b
	for i := 0; i < 14; i++ {
		s.point(&b) // ip L/R
	}
	return b.Bytes()
}

func decoded(t *testing.T, raw []byte) *transaction.Transaction {
	t.Helper()
	var tx transaction.Transaction
	if err := decode(&tx, raw); err != nil {
		t.Fatalf("synthetic transaction does not decode: %v", err)
	}
	return &tx
}

func TestCanonicalTxFastPath(t *testing.T) {
	raw := (&synth{}).bytes()
	tx := decoded(t, raw)
	canonical, err := Check(raw, tx)
	if err != nil || !canonical {
		t.Fatalf("canonical tx: canonical=%v err=%v", canonical, err)
	}
	added := 0
	if err := Admit(raw, tx, func(*transaction.Transaction) error { added++; return nil }); err != nil || added != 1 {
		t.Fatalf("canonical tx not admitted: err=%v added=%d", err, added)
	}
}

// an undefined flag byte (0x02..0xff) decodes (to the point or its negation) and its canonical re-encoding decodes to
// the same transaction: accepted, counted as non-canonical
func TestFlagAliasAcceptedNonCanonical(t *testing.T) {
	q := new(bn256.G1).ScalarBaseMult(big.NewInt(idxC0)).EncodeCompressed()
	q[32] = 0x7f
	raw := (&synth{override: map[int][]byte{idxC0: q}}).bytes()
	tx := decoded(t, raw)
	before := nonCanonical.Get()
	canonical, err := Check(raw, tx)
	if err != nil || canonical {
		t.Fatalf("flag alias: canonical=%v err=%v, want accepted non-canonical", canonical, err)
	}
	if nonCanonical.Get() != before+1 {
		t.Fatal("non-canonical counter not incremented")
	}
}

func noncanonicalX(t *testing.T) []byte {
	for k := int64(1); k < 64; k++ {
		enc := new(bn256.G1).ScalarBaseMult(big.NewInt(k)).EncodeCompressed()
		x := new(big.Int).Add(new(big.Int).SetBytes(enc[:32]), bn256.P)
		if x.BitLen() <= 256 {
			out := make([]byte, 33)
			x.FillBytes(out[:32])
			return out
		}
	}
	t.Fatal("no small multiple of G with x+P < 2^256")
	return nil
}

// x >= P decodes (consensus code) to the identity, whose canonical encoding no node can decode: refused
func TestNonCanonicalXRejected(t *testing.T) {
	raw := (&synth{override: map[int][]byte{idxC0: noncanonicalX(t)}}).bytes()
	tx := decoded(t, raw) // the consensus decoder accepts it
	var back transaction.Transaction
	if err := decode(&back, tx.Serialize()); err == nil {
		t.Fatal("premise changed: the re-serialized identity decodes")
	}
	before := rejected.Get()
	_, err := Check(raw, tx)
	if !errors.Is(err, ErrNotRoundTrip) {
		t.Fatalf("non-canonical x: err=%v, want ErrNotRoundTrip", err)
	}
	// the reason must be that the canonical bytes do not decode (the identity's 33 zero bytes)
	if !strings.Contains(err.Error(), "wrong encoded point size") && !strings.Contains(err.Error(), "Cannot decompress") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if rejected.Get() != before+1 {
		t.Fatal("rejection counter not incremented")
	}
	added := 0
	if err := Admit(raw, tx, func(*transaction.Transaction) error { added++; return nil }); err == nil || added != 0 {
		t.Fatalf("non-canonical x admitted: err=%v added=%d", err, added)
	}
}

// a transaction that cannot even be serialized (zero-value) is refused, not a panic
func TestUnserializableRefused(t *testing.T) {
	var tx transaction.Transaction
	tx.Version = 1
	tx.TransactionType = transaction.TransactionType(99)
	if _, err := Check(nil, &tx); !errors.Is(err, ErrNotRoundTrip) {
		t.Fatalf("err=%v, want ErrNotRoundTrip", err)
	}
}

// characterization of a consensus decoder property (cryptography/crypto, not changed): a proof whose final
// inner-product point is cut short still decodes without error (bytes.Reader.Read returns n<33, err=nil and the
// '} else { return err }' branch returns that nil), leaving len(ls) != len(rs), and Serialize then panics (index
// out of range in InnerProduct.Serialize). Pinned so a future decoder change is noticed; the relay policy turns
// the panic into a refusal before Add_TX_To_Pool sees the transaction.
func TestTruncatedTailDecodesThenSerializePanics(t *testing.T) {
	raw := (&synth{}).bytes()
	cut := raw[:len(raw)-20]
	var tx transaction.Transaction
	if err := decode(&tx, cut); err != nil {
		t.Fatalf("premise changed: truncated tail now rejected (%v)", err)
	}
	if _, err := serialize(&tx); err == nil {
		t.Fatal("premise changed: the truncated transaction serializes")
	}
	if _, err := Check(cut, &tx); !errors.Is(err, ErrNotRoundTrip) {
		t.Fatalf("truncated transaction: err=%v, want ErrNotRoundTrip", err)
	}
}

func BenchmarkCheckCanonical(b *testing.B) {
	raw := (&synth{}).bytes()
	var tx transaction.Transaction
	if err := decode(&tx, raw); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Check(raw, &tx)
	}
}

func BenchmarkDeserialize(b *testing.B) {
	raw := (&synth{}).bytes()
	for i := 0; i < b.N; i++ {
		var tx transaction.Transaction
		decode(&tx, raw)
	}
}
