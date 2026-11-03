// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package bn256

// r22 crypto audit: characterization tests that PIN the current (consensus) behaviour of the compressed G1
// decoder. bn256 is consensus code; these tests do not ask for a change, they make any future change visible,
// because changing what DecodeCompressed accepts changes which transactions are valid (a chain fork).

import (
	"bytes"
	"math/big"
	"testing"
)

func r22_point(k int64) *G1 { return new(G1).ScalarBaseMult(big.NewInt(k)) }

// the identity compresses to 33 zero bytes, and 33 zero bytes do not decode: 3 is a quadratic non-residue mod P,
// so x=0 is not on y^2 = x^3 + 3. The identity therefore has no canonical compressed encoding.
func TestR22IdentityHasNoCanonicalEncoding(t *testing.T) {
	inf := new(G1).ScalarBaseMult(big.NewInt(0))
	enc := inf.EncodeCompressed()
	if !bytes.Equal(enc, make([]byte, 33)) {
		t.Fatalf("identity compressed to %x, want 33 zero bytes", enc)
	}
	if new(big.Int).Exp(big.NewInt(3), new(big.Int).Rsh(new(big.Int).Sub(P, big.NewInt(1)), 1), P).Cmp(big.NewInt(1)) == 0 {
		t.Fatal("3 is a quadratic residue mod P; the premise of this test changed")
	}
	var back G1
	if err := back.DecodeCompressed(enc); err == nil {
		t.Fatal("33 zero bytes decoded; the identity round-trip behaviour changed")
	}
}

// r22_noncanonical returns the encoding of q with x replaced by x+P (still < 2^256), or nil if it overflows.
func r22_noncanonical(q *G1) []byte {
	enc := q.EncodeCompressed()
	x := new(big.Int).SetBytes(enc[:32])
	x.Add(x, P)
	if x.BitLen() > 256 {
		return nil
	}
	out := make([]byte, 33)
	x.FillBytes(out[:32])
	out[32] = enc[32]
	return out
}

// an x coordinate >= P whose reduction is on the curve decodes WITHOUT error to the point at infinity: marshal()
// ignores the Unmarshal error ("coordinate exceeds modulus") and returns the zero curvePoint (z = 0 = infinity).
func TestR22NonCanonicalXDecodesToIdentity(t *testing.T) {
	found := 0
	for k := int64(1); k < 64 && found < 8; k++ {
		enc := r22_noncanonical(r22_point(k))
		if enc == nil {
			continue
		}
		found++
		var d G1
		if err := d.DecodeCompressed(enc); err != nil {
			t.Fatalf("k=%d: non-canonical x rejected (%v); decoder behaviour changed", k, err)
		}
		if !d.p.IsInfinity() {
			t.Fatalf("k=%d: non-canonical x decoded to a finite point; decoder behaviour changed", k)
		}
		if bytes.Equal(d.EncodeCompressed(), enc) {
			t.Fatalf("k=%d: re-encoding reproduced the non-canonical bytes", k)
		}
	}
	if found == 0 {
		t.Fatal("no small multiple of G had x+P < 2^256")
	}
}

// the flag byte is only defined for 0x00 and 0x01; 0x02..0xff decode too, to the root ModSqrt returned first, which
// is either the point itself or its negation (deterministic per x). So one x has many accepted encodings, and an
// "alias" may even name the negated point. Re-encoding always yields 0x00/0x01.
func TestR22FlagByteMalleability(t *testing.T) {
	same, negated := 0, 0
	for k := int64(1); k <= 64; k++ {
		q := r22_point(k)
		enc := q.EncodeCompressed()
		neg := new(G1).Neg(q).EncodeCompressed()
		for f := 2; f < 256; f += 51 {
			alt := append([]byte(nil), enc...)
			alt[32] = byte(f)
			var d G1
			if err := d.DecodeCompressed(alt); err != nil {
				t.Fatalf("k=%d flag %#x rejected (%v); decoder behaviour changed", k, f, err)
			}
			switch got := d.EncodeCompressed(); {
			case bytes.Equal(got, enc):
				same++
			case bytes.Equal(got, neg):
				negated++
			default:
				t.Fatalf("k=%d flag %#x decoded to an unrelated point", k, f)
			}
		}
	}
	if same == 0 || negated == 0 {
		t.Fatalf("aliases: %d same point, %d negated; expected both kinds", same, negated)
	}
}

// canonical encodings of finite points round-trip exactly
func TestR22CanonicalRoundTrip(t *testing.T) {
	for k := int64(1); k < 200; k++ {
		q := r22_point(k)
		enc := q.EncodeCompressed()
		var d G1
		if err := d.DecodeCompressed(enc); err != nil {
			t.Fatalf("k=%d: %v", k, err)
		}
		if !bytes.Equal(d.Marshal(), q.Marshal()) || !bytes.Equal(d.EncodeCompressed(), enc) {
			t.Fatalf("k=%d: round trip mismatch", k)
		}
	}
}

// FuzzDecodeCompressed: the decoder never panics, and every accepted input that does not re-encode to itself
// belongs to one of the two known non-canonical classes (undefined flag byte, or x >= P). Anything else would be a
// new decoder bug.
func FuzzDecodeCompressed(f *testing.F) {
	f.Add(r22_point(1).EncodeCompressed())
	f.Add(make([]byte, 33))
	f.Add(bytes.Repeat([]byte{0xff}, 33))
	if nc := r22_noncanonical(r22_point(3)); nc != nil {
		f.Add(nc)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var d G1
		if err := d.DecodeCompressed(in); err != nil {
			return
		}
		if len(in) != 33 {
			t.Fatalf("accepted a %d-byte encoding", len(in))
		}
		if bytes.Equal(d.EncodeCompressed(), in) {
			return
		}
		x := new(big.Int).SetBytes(in[:32])
		if in[32] > 1 || x.Cmp(P) >= 0 {
			return
		}
		t.Fatalf("canonical-looking input %x decoded to a point that re-encodes differently (%x)", in, d.EncodeCompressed())
	})
}
