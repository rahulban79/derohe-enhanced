// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package bn256

// r31 (cryptography area, rft §7 B278 (1) / B283): the primitives census of the bn256 decoders and constants.
//
// bn256 is consensus code (consensus guard S1: cryptography/ is consensus-visible). These tests change nothing; they
// PIN, per decoder entry point, which input classes it accepts or refuses today, so that any change of a decoder's
// behaviour (a stricter check would make some already-mined encodings invalid: a chain fork) fails here first and
// is routed to the disclosure-style track (rft §0.5) instead of landing silently. Wording is defensive throughout:
// each case names a check that is present or missing, never how to use a missing one.
//
// Entry points and where they are reached from (anchors re-read by harness/intel/crypto_census.py):
//   G1.DecodeCompressed / Decompress   transaction decode (crypto Statement / Proof Deserialize), miner address
//                                      (transaction/transaction.go), balance tree keys: CONSENSUS
//   G1.Unmarshal                       marshal() (the compressed path) and the identity constructor Unmarshal(zeroes)
//                                      used throughout cryptography/crypto/proof_verify.go: CONSENSUS (by design)
//   G1.DecodeUncompressed              changes_more_tests.go only (no node caller)
//   DecompressAmbiguous, G2/GT.Unmarshal  no caller outside this package's tests

import (
	"bytes"
	"math/big"
	"testing"
)

// r31P / r31Order recomputed from the BN parameter u (BN254: p = 36u^4+36u^3+24u^2+6u+1, n = 36u^4+36u^3+18u^2+6u+1),
// independent of constants.go.
func r31BN(u *big.Int, c2 int64) *big.Int {
	u2 := new(big.Int).Mul(u, u)
	u3 := new(big.Int).Mul(u2, u)
	u4 := new(big.Int).Mul(u3, u)
	r := new(big.Int).Mul(big.NewInt(36), u4)
	r.Add(r, new(big.Int).Mul(big.NewInt(36), u3))
	r.Add(r, new(big.Int).Mul(big.NewInt(c2), u2))
	r.Add(r, new(big.Int).Mul(big.NewInt(6), u))
	return r.Add(r, big.NewInt(1))
}

// TestR31Bn256ConstantsKAT: P and Order are the BN254 field modulus and group order, derived from u; both prime;
// P = 3 mod 4 (Decompress takes square roots mod P); the generator has order Order.
func TestR31Bn256ConstantsKAT(t *testing.T) {
	u, _ := new(big.Int).SetString("4965661367192848881", 10)
	if wantP := r31BN(u, 24); P.Cmp(wantP) != 0 {
		t.Fatalf("P is not the BN254 field modulus: %s", P)
	}
	if wantN := r31BN(u, 18); Order.Cmp(wantN) != 0 {
		t.Fatalf("Order is not the BN254 group order: %s", Order)
	}
	if !P.ProbablyPrime(20) || !Order.ProbablyPrime(20) {
		t.Fatalf("P or Order not prime")
	}
	if new(big.Int).Mod(P, big.NewInt(4)).Int64() != 3 {
		t.Fatalf("P mod 4 != 3")
	}
	inf := new(G1).ScalarBaseMult(Order)
	if !inf.p.IsInfinity() {
		t.Fatalf("Order*G is not the identity")
	}
}

// TestR31ScalarOrderReduction: scalar multiplication reduces its scalar modulo Order (k and k+Order give the same
// point). Pinned: scalars are not range-checked by the curve code, so every caller that needs a canonical scalar must
// check it itself (the proof decoders do not: rft §7 B283, disclosure FX-F3).
func TestR31ScalarOrderReduction(t *testing.T) {
	for _, k := range []int64{1, 2, 5, 1 << 40} {
		a := new(G1).ScalarBaseMult(big.NewInt(k)).Marshal()
		kk := new(big.Int).Add(big.NewInt(k), Order)
		b := new(G1).ScalarBaseMult(kk).Marshal()
		c := new(G1).ScalarMult(new(G1).ScalarBaseMult(big.NewInt(1)), kk).Marshal()
		if !bytes.Equal(a, b) || !bytes.Equal(a, c) {
			t.Fatalf("k=%d: k and k+Order give different points", k)
		}
	}
}

// TestR31GfpUnmarshalModulusCheck: the field-element decoder refuses a coordinate equal to or above P and accepts
// P-1. This is the check the uncompressed decoders rely on (and that marshal() drops the error of: rft §7 B283).
func TestR31GfpUnmarshalModulusCheck(t *testing.T) {
	enc := func(v *big.Int) []byte { b := make([]byte, 32); v.FillBytes(b); return b }
	var e gfP
	if err := e.Unmarshal(enc(new(big.Int).Sub(P, big.NewInt(1)))); err != nil {
		t.Fatalf("P-1 refused: %v", err)
	}
	if err := e.Unmarshal(enc(P)); err == nil {
		t.Fatalf("a coordinate equal to P was accepted")
	}
	if err := e.Unmarshal(enc(new(big.Int).Add(P, big.NewInt(1)))); err == nil {
		t.Fatalf("a coordinate above P was accepted")
	}
	all := bytes.Repeat([]byte{0xff}, 32)
	if err := e.Unmarshal(all); err == nil {
		t.Fatalf("2^256-1 accepted as a coordinate")
	}
}

// r31Census is one (entry, class) observation: accepted (no error) and, when accepted, whether the result re-encodes
// to the input bytes.
type r31Census struct {
	accepted, roundtrip, panicked bool
}

func r31Run(f func() (bool, bool)) (c r31Census) {
	defer func() {
		if recover() != nil {
			c = r31Census{panicked: true}
		}
	}()
	c.accepted, c.roundtrip = f()
	return
}

// TestR31Bn256DecodeClassCensus: the entry x class table of the uncompressed G1, G2 and GT decoders and of
// DecompressAmbiguous. Every case is either a canonical encoding (accepted, round-trips) or one the decoder refuses
// today; the identity row is the documented low finding (identity accepted by the uncompressed decoders) which the
// proof code relies on (proof_verify.go builds its zero accumulators with Unmarshal(zeroes)): not-a-defect, pinned.
func TestR31Bn256DecodeClassCensus(t *testing.T) {
	g1 := func(m []byte) func() (bool, bool) {
		return func() (bool, bool) {
			var e G1
			if _, err := e.Unmarshal(m); err != nil {
				return false, false
			}
			return true, bytes.Equal(e.Marshal(), m[:64])
		}
	}
	g1u := func(m []byte) func() (bool, bool) {
		return func() (bool, bool) {
			var e G1
			if err := e.DecodeUncompressed(m); err != nil {
				return false, false
			}
			return true, bytes.Equal(e.EncodeUncompressed(), m[:64])
		}
	}
	g2 := func(m []byte) func() (bool, bool) {
		return func() (bool, bool) {
			var e G2
			if _, err := e.Unmarshal(m); err != nil {
				return false, false
			}
			return true, bytes.Equal(e.Marshal(), m[:128])
		}
	}
	gt := func(m []byte) func() (bool, bool) {
		return func() (bool, bool) {
			var e GT
			if _, err := e.Unmarshal(m); err != nil {
				return false, false
			}
			return true, bytes.Equal(e.Marshal(), m[:384])
		}
	}
	amb := func(m []byte) func() (bool, bool) {
		return func() (bool, bool) {
			a, b, err := DecompressAmbiguous(m)
			if err != nil {
				return false, false
			}
			q, _ := Decompress(m)
			sum := new(G1).Add(a, b)
			// both roots: {q, -q}, and q is one of them
			return true, sum.p.IsInfinity() || bytes.Equal(a.Marshal(), q.Marshal()) || bytes.Equal(b.Marshal(), q.Marshal())
		}
	}
	p1 := new(G1).ScalarBaseMult(big.NewInt(7)).Marshal()
	offCurve := append(append([]byte{}, p1[:32]...), p1[32:]...)
	offCurve[63] ^= 1
	xAbove := make([]byte, 64)
	new(big.Int).Add(P, big.NewInt(1)).FillBytes(xAbove[:32])
	big.NewInt(2).FillBytes(xAbove[32:]) // (1, 2) is on y^2 = x^3 + 3; x written at or above P must be refused
	q2 := new(G2).ScalarBaseMult(big.NewInt(9)).Marshal()
	q2bad := append([]byte{}, q2...)
	q2bad[127] ^= 1
	gtv := Pair(new(G1).ScalarBaseMult(big.NewInt(3)), new(G2).ScalarBaseMult(big.NewInt(5))).Marshal()
	gtbad := append([]byte{}, gtv...)
	copy(gtbad[:32], bytes.Repeat([]byte{0xff}, 32))
	c1 := new(G1).ScalarBaseMult(big.NewInt(11)).EncodeCompressed()
	x0 := make([]byte, 33) // x = 0: 3 is a non-residue mod P, no point

	cases := []struct {
		entry, class string
		run          func() (bool, bool)
		want         r31Census
	}{
		{"G1.Unmarshal", "canonical", g1(p1), r31Census{accepted: true, roundtrip: true}},
		{"G1.Unmarshal", "identity (all zero)", g1(make([]byte, 64)), r31Census{accepted: true, roundtrip: true}},
		{"G1.Unmarshal", "off curve", g1(offCurve), r31Census{}},
		{"G1.Unmarshal", "coordinate >= P", g1(xAbove), r31Census{}},
		{"G1.Unmarshal", "short", g1(p1[:63]), r31Census{}},
		{"G1.DecodeUncompressed", "canonical", g1u(p1), r31Census{accepted: true, roundtrip: true}},
		{"G1.DecodeUncompressed", "identity (all zero)", g1u(make([]byte, 64)), r31Census{accepted: true, roundtrip: true}},
		{"G1.DecodeUncompressed", "coordinate >= P", g1u(xAbove), r31Census{}},
		{"G2.Unmarshal", "canonical", g2(q2), r31Census{accepted: true, roundtrip: true}},
		{"G2.Unmarshal", "identity (all zero)", g2(make([]byte, 128)), r31Census{accepted: true, roundtrip: true}},
		{"G2.Unmarshal", "off curve", g2(q2bad), r31Census{}},
		{"G2.Unmarshal", "short", g2(q2[:127]), r31Census{}},
		{"GT.Unmarshal", "canonical", gt(gtv), r31Census{accepted: true, roundtrip: true}},
		{"GT.Unmarshal", "coordinate >= P", gt(gtbad), r31Census{}},
		{"GT.Unmarshal", "short", gt(gtv[:383]), r31Census{}},
		{"DecompressAmbiguous", "canonical", amb(c1), r31Census{accepted: true, roundtrip: true}},
		{"DecompressAmbiguous", "x not on curve", amb(x0), r31Census{}},
		{"DecompressAmbiguous", "wrong length", amb(c1[:32]), r31Census{}},
	}
	for _, c := range cases {
		if got := r31Run(c.run); got != c.want {
			t.Errorf("%s / %s: got %+v, pinned %+v (a decoder behaviour change: consensus-visible for the G1 entries, "+
				"route it through rft §0.5, never land it locally)", c.entry, c.class, got, c.want)
		}
	}
}

// TestR31CompressedDecodeClassCensus: the compressed G1 entry (consensus) per class. Canonical encodings round-trip;
// an encoding of the wrong length or whose x is not on the curve is refused; the two non-canonical classes the R22
// audit documented (flag byte outside {0,1}; x at or above P, whose Unmarshal error marshal() drops at
// changes.go:59) are ACCEPTED and never re-encode to their input. Pinned (rft §7 B283; disclosure-style: a fix needs
// a coordinated fork). The class inputs come from the R22 helpers (r22_decode_audit_test.go).
func TestR31CompressedDecodeClassCensus(t *testing.T) {
	type obs struct{ accepted, canonical bool }
	dec := func(b []byte) obs {
		var e G1
		if err := e.DecodeCompressed(b); err != nil {
			return obs{}
		}
		return obs{true, bytes.Equal(e.EncodeCompressed(), b)}
	}
	q := r22_point(5)
	enc := q.EncodeCompressed()
	flag := append([]byte{}, enc...)
	flag[32] = 0x02
	var high []byte
	for k := int64(1); k < 64 && high == nil; k++ {
		high = r22_noncanonical(r22_point(k))
	}
	if high == nil {
		t.Fatalf("no sample for the x >= P class")
	}
	cases := []struct {
		class string
		in    []byte
		want  obs
	}{
		{"canonical", enc, obs{true, true}},
		{"wrong length", enc[:32], obs{}},
		{"x not on curve", make([]byte, 33), obs{}},
		{"flag byte outside {0,1}", flag, obs{true, false}},
		{"x >= P", high, obs{true, false}},
	}
	for _, c := range cases {
		if got := dec(c.in); got != c.want {
			t.Errorf("G1.DecodeCompressed / %s: got %+v, pinned %+v (consensus-visible: rft §0.5 track, never a local change)",
				c.class, got, c.want)
		}
	}
	// what the x >= P class decodes to is pinned too: the identity (marshal() drops the Unmarshal error and returns
	// the zero point), not some other point
	var e G1
	if err := e.DecodeCompressed(high); err != nil || e.p == nil || !e.p.IsInfinity() {
		t.Errorf("G1.DecodeCompressed / x >= P: pinned to decode to the identity without error (err %v)", err)
	}
}

// FuzzR31Bn256Decoders: the uncompressed G1 / G2 / GT decoders and DecompressAmbiguous never panic, and every input
// they accept re-encodes to itself (the uncompressed encodings have exactly one accepted form per element, identity
// included). Seeds run as a unit test; never fuzzed for long in the pipeline.
func FuzzR31Bn256Decoders(f *testing.F) {
	p1 := new(G1).ScalarBaseMult(big.NewInt(7)).Marshal()
	q2 := new(G2).ScalarBaseMult(big.NewInt(9)).Marshal()
	gtv := Pair(new(G1).ScalarBaseMult(big.NewInt(3)), new(G2).ScalarBaseMult(big.NewInt(5))).Marshal()
	f.Add(p1)
	f.Add(make([]byte, 64))
	f.Add(q2)
	f.Add(make([]byte, 128))
	f.Add(gtv)
	f.Add(new(G1).ScalarBaseMult(big.NewInt(11)).EncodeCompressed())
	f.Add(bytes.Repeat([]byte{0xff}, 384))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, m []byte) {
		if len(m) >= 64 {
			var e G1
			if _, err := e.Unmarshal(m); err == nil && !bytes.Equal(e.Marshal(), m[:64]) {
				t.Fatalf("G1.Unmarshal accepted a non-canonical encoding %x", m[:64])
			}
		}
		var u G1
		if err := u.DecodeUncompressed(m); err == nil && !bytes.Equal(u.EncodeUncompressed(), m[:64]) {
			t.Fatalf("G1.DecodeUncompressed accepted a non-canonical encoding")
		}
		if len(m) >= 128 {
			var e G2
			if _, err := e.Unmarshal(m); err == nil && !bytes.Equal(e.Marshal(), m[:128]) {
				t.Fatalf("G2.Unmarshal accepted a non-canonical encoding")
			}
		}
		if len(m) >= 384 {
			var e GT
			if _, err := e.Unmarshal(m); err == nil && !bytes.Equal(e.Marshal(), m[:384]) {
				t.Fatalf("GT.Unmarshal accepted a non-canonical encoding")
			}
		}
		var e GT
		e.Unmarshal(m) // any length: an error, never a panic
		if len(m) == 33 {
			a, b, err := DecompressAmbiguous(m)
			if err == nil && (a == nil || b == nil) {
				t.Fatalf("DecompressAmbiguous: nil point without error")
			}
		} else if _, _, err := DecompressAmbiguous(m); err == nil {
			t.Fatalf("DecompressAmbiguous accepted length %d", len(m))
		}
	})
}
