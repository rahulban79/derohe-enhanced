package crypto

// r28 (glue-global, L24-25): the verify-path guards of Proof.Verify that no test pinned, each with a go_mutate
// mutation (gm-r28-glue-global-crypto-*) that removes it. Tests only (consensus guard S1: cryptography/ verify code
// is unchanged). Every input is an HONEST proof (r25HonestProof) or that proof with one statement or proof value
// changed; each test asserts the honest code REFUSES it and names the check that does. Nothing here builds a proof the
// unmodified verifier accepts (rft §9 NO-GO for the range-proof/IPA defect); the open-value overflow case is the
// fee/burn uint64 guard, not that defect.

import (
	"math"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
)

// verify_no_panic runs Verify and reports (accepted, panicked).
func verify_no_panic(p *Proof, s *Statement, txid Hash, extra uint64) (ok bool, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			ok, panicked = false, true
		}
	}()
	var scid Hash
	return p.Verify(scid, 0, s, txid, extra), false
}

// a statement whose commitment list is shorter than its ring: refused up front, never an index panic.
func TestR28VerifyRefusesMismatchedStatement(t *testing.T) {
	h := r25HonestProof(t, 4, 0, 1)
	if ok, pn := verify_no_panic(h.proof, &h.s, h.txid, 0); !ok || pn {
		t.Fatalf("honest proof: accepted %v panicked %v", ok, pn)
	}
	s := h.s
	s.C = s.C[:len(s.C)-1]
	if ok, pn := verify_no_panic(h.decode(t, h.bytesOf(h.proof)), &s, h.txid, 0); ok || pn {
		t.Fatalf("len(C) %d != len(ring) %d: accepted %v panicked %v (want a plain refusal)", len(s.C), len(s.Publickeylist), ok, pn)
	}
}

// Fees + extra_value is a uint64: a pair that wraps to the honest total must be refused by the overflow guard (the
// proof itself only sees the wrapped sum).
func TestR28VerifyRefusesWrappedOpenValue(t *testing.T) {
	h := r25HonestProof(t, 4, 0, 1)
	s := h.s
	s.Fees = h.s.Fees + 1 // 4 + (2^64 - 1) wraps to 3, the honest fee
	ok, pn := verify_no_panic(h.decode(t, h.bytesOf(h.proof)), &s, h.txid, math.MaxUint64)
	if ok || pn {
		t.Fatalf("fees %d + extra %d (wraps to %d): accepted %v panicked %v", s.Fees, uint64(math.MaxUint64), s.Fees+math.MaxUint64, ok, pn)
	}
	if ok, _ := verify_no_panic(h.decode(t, h.bytesOf(h.proof)), &h.s, h.txid, 0); !ok {
		t.Fatalf("honest proof refused")
	}
}

// the parity condition (w equals f[0] or f[m]) refuses a change of the matching f entry by itself, before the
// B^w*A recovery: pinned as the refusal stage of at least one of the two one-entry changes.
func TestR28VerifyParityStagePinned(t *testing.T) {
	for _, rc := range r25Rings {
		h := r25HonestProof(t, rc[0], rc[1], rc[2])
		honest := h.bytesOf(h.proof)
		m := h.proof.f.Length() / 2
		stages := map[int]string{}
		for _, k := range []int{0, m} {
			p := h.decode(t, honest)
			p.f.vector[k] = new(big.Int).Mod(new(big.Int).Add(p.f.vector[k], big.NewInt(1)), bn256.Order)
			stages[k] = r26RefusalStage(h, p)
		}
		t.Logf("R28 ring %d: f[0] refused-by %q, f[%d] refused-by %q", rc[0], stages[0], m, stages[m])
		if stages[0] == "accepted" || stages[m] == "accepted" {
			t.Fatalf("ring %d: a one-entry f change was accepted", rc[0])
		}
		if stages[0] != "Parity check failed" && stages[m] != "Parity check failed" {
			t.Fatalf("ring %d: no f change refused by the parity check (%v)", rc[0], stages)
		}
	}
}

// the inner-product argument's L/R vectors must have the same length: refused by the length guard (a plain false),
// never by the final-equation panic.
func TestR28InnerProductLengthGuard(t *testing.T) {
	h := r25HonestProof(t, 4, 0, 1)
	p := h.decode(t, h.bytesOf(h.proof))
	p.ip.ls = p.ip.ls[:len(p.ip.ls)-1]
	if ok, pn := verify_no_panic(p, &h.s, h.txid, 0); ok || pn {
		t.Fatalf("len(ip.ls) %d != len(ip.rs) %d: accepted %v panicked %v (want a plain refusal)", len(p.ip.ls), len(p.ip.rs), ok, pn)
	}
}
