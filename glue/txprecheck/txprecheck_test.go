// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package txprecheck

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/metrics"
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

func fresh(t testing.TB) *transaction.Transaction {
	var tx transaction.Transaction
	if err := tx.Deserialize((&synth{}).bytes()); err != nil {
		t.Fatalf("synthetic transaction does not decode: %v", err)
	}
	return &tx
}

func TestPrecheckPassesWellFormed(t *testing.T) {
	for i := 0; i < 3; i++ {
		if err := Check(fresh(t)); err != nil {
			t.Fatalf("well-formed transfer refused: %v", err)
		}
		tx := fresh(t)
		tx.TransactionType, tx.Value = transaction.BURN_TX, 5
		if err := Check(tx); err != nil {
			t.Fatalf("burn with value refused: %v", err)
		}
		reg := &transaction.Transaction{} // registrations (and anything not a transfer) are not this package's business
		reg.TransactionType = transaction.REGISTRATION
		if err := Check(reg); err != nil {
			t.Fatalf("registration refused: %v", err)
		}
	}
}

func TestPrecheckRefusesWhatConsensusRefuses(t *testing.T) {
	cases := map[string]func(tx *transaction.Transaction){
		"version":    func(tx *transaction.Transaction) { tx.Version = 2 },
		"burn_zero":  func(tx *transaction.Transaction) { tx.TransactionType, tx.Value = transaction.BURN_TX, 0 },
		"no_payload": func(tx *transaction.Transaction) { tx.Payloads = nil },
		"no_base":    func(tx *transaction.Transaction) { tx.Payloads[0].SCID[0] = 1 },
		"roothash": func(tx *transaction.Transaction) {
			p := tx.Payloads[0]
			p.Statement.Roothash[0] ^= 1
			tx.Payloads = append(tx.Payloads, p)
		},
		"bpp_zero":   func(tx *transaction.Transaction) { tx.Payloads[0].Statement.Bytes_per_publickey = 0 },
		"ring_ratio": func(tx *transaction.Transaction) { tx.Payloads[0].Statement.RingSize = 4 },
		"ring_one": func(tx *transaction.Transaction) {
			s := &tx.Payloads[0].Statement
			s.RingSize, s.Publickeylist_pointers = 1, s.Publickeylist_pointers[:4]
		},
		"ring_big": func(tx *transaction.Transaction) {
			s := &tx.Payloads[0].Statement
			s.Bytes_per_publickey, s.RingSize = 1, 256
			s.Publickeylist_pointers = seq(256)
		},
		"ring_not_po2": func(tx *transaction.Transaction) {
			s := &tx.Payloads[0].Statement
			s.Bytes_per_publickey, s.RingSize = 1, 3
			s.Publickeylist_pointers = seq(3)
		},
		"duplicate": func(tx *transaction.Transaction) {
			copy(tx.Payloads[0].Statement.Publickeylist_pointers[4:], tx.Payloads[0].Statement.Publickeylist_pointers[:4])
		},
		"short_C":   func(tx *transaction.Transaction) { tx.Payloads[0].Statement.C = tx.Payloads[0].Statement.C[:1] },
		"nil_D":     func(tx *transaction.Transaction) { tx.Payloads[0].Statement.D = nil },
		"nil_proof": func(tx *transaction.Transaction) { tx.Payloads[0].Proof = nil },
	}
	for i := 0; i < 3; i++ {
		for name, mutate := range cases {
			tx := fresh(t)
			mutate(tx)
			err := Check(tx)
			if !errors.Is(err, ErrStructure) {
				t.Fatalf("%s: not refused (%v)", name, err)
			}
		}
	}
	if !errors.Is(Check(nil), ErrStructure) {
		t.Fatalf("nil tx not refused")
	}
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestPrecheckAdmitGatesTheAdd(t *testing.T) {
	added := 0
	add := func(*transaction.Transaction) error { added++; return nil }
	bad := fresh(t)
	copy(bad.Payloads[0].Statement.Publickeylist_pointers[4:], bad.Payloads[0].Statement.Publickeylist_pointers[:4])
	before := metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="ring_duplicate"}`).Get()
	if err := Admit(bad, add); !errors.Is(err, ErrStructure) || added != 0 {
		t.Fatalf("refused tx reached the pool (err %v, added %d)", err, added)
	}
	if metrics.Set.GetOrCreateCounter(`tx_precheck_refused_total{reason="ring_duplicate"}`).Get() != before+1 {
		t.Fatalf("refusal not counted by reason")
	}
	if err := Admit(fresh(t), add); err != nil || added != 1 {
		t.Fatalf("well-formed tx not passed on (err %v, added %d)", err, added)
	}
}

// r23b forensics: every admission is counted, refused or not, so the precheck's live wiring is visible in /metrics
func TestR23bPrecheckAdmitCountsEveryAdmission(t *testing.T) {
	for i := 0; i < 3; i++ {
		c := metrics.Set.GetOrCreateCounter("tx_precheck_checked_total")
		before := c.Get()
		add := func(*transaction.Transaction) error { return nil }
		bad := fresh(t)
		bad.Version = 2
		Admit(bad, add)
		Admit(fresh(t), add)
		if got := c.Get(); got != before+2 {
			t.Fatalf("tx_precheck_checked_total moved by %d for 2 admissions", got-before)
		}
		// r23b merge: AdmitAt counts once, also when the window refuses (and never twice when it passes on)
		ok, old := fresh(t), fresh(t)
		before = c.Get()
		if err := AdmitAt(ok, ok.GetHash(), int64(ok.Height), add); err != nil {
			t.Fatalf("in-window AdmitAt refused: %v", err)
		}
		if err := AdmitAt(old, old.GetHash(), int64(old.Height)+1000, add); err == nil {
			t.Fatal("a stale tx passed AdmitAt")
		}
		if got := c.Get(); got != before+2 {
			t.Fatalf("tx_precheck_checked_total moved by %d for 2 AdmitAt calls", got-before)
		}
	}
}

func BenchmarkPrecheck(b *testing.B) {
	tx := fresh(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if Check(tx) != nil {
			b.Fatal("refused")
		}
	}
}
