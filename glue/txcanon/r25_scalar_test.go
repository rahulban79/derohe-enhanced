// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

// r25 (secpool, BD5 / disclosure FX-N4): non-reduced proof scalars are refused at admission, counted on blocks.
// Encoding-hygiene tests only: every planted value is an out-of-range ENCODING; nothing here builds or checks a proof.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/transaction"
)

// the 12 scalars synth writes, in proof order: f[0] f[1] z_A that mu c s_sk s_r s_b s_tau ip.a ip.b
var r25_synth_scalars = []int64{5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 20, 21}

func r25_be32(v *big.Int) []byte {
	var b [32]byte
	v.FillBytes(b[:])
	return b[:]
}

// The layout is checked against the bytes, not against itself: every offset proof_scalar_offsets gives for a ring-2
// proof holds exactly the scalar synth wrote there.
func TestR25ProofScalarOffsetsMatchSynth(t *testing.T) {
	raw := (&synth{}).bytes()
	tx := decoded(t, raw)
	var w bytes.Buffer
	tx.Payloads[0].Proof.Serialize(&w)
	pb := w.Bytes()
	if !bytes.HasSuffix(raw, pb) {
		t.Fatal("the proof is not the tail of a one-payload NORMAL tx")
	}
	offs, ok := proof_scalar_offsets(len(pb))
	if !ok || len(offs) != len(r25_synth_scalars) {
		t.Fatalf("ring-2 proof of %d bytes: %d offsets ok=%v", len(pb), len(offs), ok)
	}
	for i, o := range offs {
		if want := r25_be32(big.NewInt(r25_synth_scalars[i])); !bytes.Equal(pb[o:o+32], want) {
			t.Fatalf("offset %d (scalar %d) holds %x, want %x", o, i, pb[o:o+32], want)
		}
	}
	for _, n := range []int{0, 1012, proofFixed, proofFixed + proofPerM - 1, proofFixed + proofPerM + 1} {
		if _, ok := proof_scalar_offsets(n); ok {
			t.Fatalf("size %d accepted by the layout", n)
		}
	}
	// sizes that do not add up are not judged (fail open), never refused
	if reduced, judged := proof_scalars_reduced(raw[:100], tx); !reduced || judged {
		t.Fatalf("a too-short encoding: reduced=%v judged=%v, want true/false", reduced, judged)
	}
}

// Every scalar position, planted with Order, Order+1 and 2^256-1: refused; Order-1 (the largest reduced value): admitted.
func TestR25NonReducedProofScalarRefused(t *testing.T) {
	base := (&synth{}).bytes()
	pstart := len(base) - (proofFixed + proofPerM)
	offs, _ := proof_scalar_offsets(proofFixed + proofPerM)
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	bad := []*big.Int{bn256.Order, new(big.Int).Add(bn256.Order, big.NewInt(1)), max}
	for i, o := range offs {
		for _, v := range bad {
			raw := append([]byte(nil), base...)
			copy(raw[pstart+o:], r25_be32(v))
			tx := decoded(t, raw)
			if _, err := Check(raw, tx); !errors.Is(err, ErrNonReducedProofScalar) {
				t.Fatalf("scalar %d = %x: %v, want ErrNonReducedProofScalar", i, r25_be32(v)[:4], err)
			}
			added := 0
			if err := Admit(raw, tx, func(*transaction.Transaction) error { added++; return nil }); err == nil || added != 0 {
				t.Fatalf("scalar %d non-reduced: admitted", i)
			}
		}
		raw := append([]byte(nil), base...)
		copy(raw[pstart+o:], r25_be32(new(big.Int).Sub(bn256.Order, big.NewInt(1))))
		if _, err := Check(raw, decoded(t, raw)); err != nil {
			t.Fatalf("scalar %d = Order-1 (reduced) refused: %v", i, err)
		}
	}
}

func r25_mainnet(t testing.TB) (raws [][]byte) {
	f, err := os.Open("testdata/r25_mainnet_txs.hex")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		b, err := hex.DecodeString(sc.Text())
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, b)
	}
	return
}

// r25_point_offsets walks the same layout as a second implementation (harness/intel/disclosure_track.py
// parse_tx_proofs): the offset of every point of a proof with ring 2^m.
func r25_point_offsets(m int) (offs []int) {
	o := 0
	for i := 0; i < 4+8*m+1; i++ { // BA BS A B, 8m, u
		offs = append(offs, o)
		o += 33
	}
	o += 32 * (2*m + 1)          // f, z_A
	offs = append(offs, o, o+33) // T_1 T_2
	o += 66 + 32*9               // that .. s_tau, ip.a ip.b
	for i := 0; i < 14; i++ {
		offs = append(offs, o)
		o += 33
	}
	return
}

// Honest traffic: 14 mainnet transactions (one per distinct size among the 61 of the r24 txpool census) are all laid
// out, judged and reduced, and still pass Check. For the one-payload NORMAL ones (rings 2, 16, 32) every point offset of
// the second layout walk decodes and re-encodes to the same 33 bytes, so the scalar offsets between them are aligned.
// A ring-16 tx planted with Order at s_tau is refused.
func TestR25MainnetTxsReducedAndJudged(t *testing.T) {
	raws := r25_mainnet(t)
	if len(raws) < 10 {
		t.Fatalf("fixture has %d txs", len(raws))
	}
	planted := false
	rings := map[int]bool{}
	for i, raw := range raws {
		var tx transaction.Transaction
		if err := decode(&tx, raw); err != nil {
			t.Fatalf("mainnet tx %d: %v", i, err)
		}
		reduced, judged := proof_scalars_reduced(raw, &tx)
		if !reduced || !judged {
			t.Fatalf("mainnet tx %d (%s): reduced=%v judged=%v", i, tx.TransactionType, reduced, judged)
		}
		if _, err := Check(raw, &tx); err != nil {
			t.Fatalf("mainnet tx %d refused: %v", i, err)
		}
		if tx.TransactionType != transaction.NORMAL || len(tx.Payloads) != 1 {
			continue
		}
		p := tx.Payloads[0].Statement
		ring := len(p.Publickeylist_pointers) / int(p.Bytes_per_publickey)
		rings[ring] = true
		var w bytes.Buffer
		tx.Payloads[0].Proof.Serialize(&w)
		n := w.Len()
		if !bytes.HasSuffix(raw, w.Bytes()) {
			continue
		}
		offs, ok := proof_scalar_offsets(n)
		if !ok {
			t.Fatalf("ring %d proof of %d bytes off the layout", ring, n)
		}
		m := len(offs)/2 - 5
		if 1<<m != ring {
			t.Fatalf("ring %d: layout says m=%d", ring, m)
		}
		pb := w.Bytes()
		for _, po := range r25_point_offsets(m) {
			var g bn256.G1
			if err := g.DecodeCompressed(pb[po : po+33]); err != nil || !bytes.Equal(g.EncodeCompressed(), pb[po:po+33]) {
				t.Fatalf("ring %d: point at %d does not decode canonically (%v): layout misaligned", ring, po, err)
			}
		}
		if ring == 16 && !planted {
			bad := append([]byte(nil), raw...)
			copy(bad[len(bad)-n+offs[len(offs)-3]:], r25_be32(bn256.Order)) // s_tau
			var btx transaction.Transaction
			if err := decode(&btx, bad); err != nil {
				t.Fatal(err)
			}
			if _, err := Check(bad, &btx); !errors.Is(err, ErrNonReducedProofScalar) {
				t.Fatalf("ring-16 mainnet tx with s_tau = Order: %v", err)
			}
			planted = true
		}
	}
	t.Logf("SECPOOL scalar-check mainnet txs=%d rings=%v planted_ring16=%v", len(raws), rings, planted)
	if !planted {
		t.Fatal("no ring-16 one-payload NORMAL tx in the fixture: the planted case did not run")
	}
}

// Block txs are counted, never refused.
func TestR25ObserveCountsNonReducedBlockTx(t *testing.T) {
	base := (&synth{}).bytes()
	pstart := len(base) - (proofFixed + proofPerM)
	offs, _ := proof_scalar_offsets(proofFixed + proofPerM)
	raw := append([]byte(nil), base...)
	copy(raw[pstart+offs[0]:], r25_be32(bn256.Order))
	before := blockScalarNonRd.Get()
	if err := Observe(raw, decoded(t, raw)); err != nil {
		t.Fatalf("Observe judged a block tx by its scalars: %v", err)
	}
	if blockScalarNonRd.Get() != before+1 {
		t.Fatal("non-reduced block tx not counted")
	}
}

func BenchmarkR25ProofScalarsReducedRing16(b *testing.B) {
	raws := r25_mainnet(b)
	var tx *transaction.Transaction
	var ser []byte
	for _, raw := range raws {
		var t transaction.Transaction
		if decode(&t, raw) == nil && t.TransactionType == transaction.NORMAL && len(t.Payloads) == 1 &&
			len(t.Payloads[0].Statement.Publickeylist_pointers)/int(t.Payloads[0].Statement.Bytes_per_publickey) == 16 {
			tx, ser = &t, raw
			break
		}
	}
	if tx == nil {
		b.Fatal("no ring-16 tx")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof_scalars_reduced(ser, tx)
	}
}
