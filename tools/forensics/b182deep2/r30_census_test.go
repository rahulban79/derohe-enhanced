package main

// R30 B208 KATs for the b182deep2 chain-census decoder (go_mutations.json gm-r30-gen-*). Synthetic wire bytes only:
// no chain data, no address, no network.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/transaction"
)

func uv(b []byte, v uint64) []byte {
	var t [10]byte
	return append(b, t[:binary.PutUvarint(t[:], v)]...)
}

// pt: the compressed point (x = 1, flag 0): 1 + 3 = 4 is a square, so it is on the curve.
func pt() []byte { p := make([]byte, 33); p[31] = 1; return p }

// synthTx: a NORMAL tx with one payload per burn value, ring 2 (power 1), canonical points, zero scalars.
func synthTx(burns []uint64, scalar []byte) []byte {
	b := uv(nil, 1)
	b = uv(b, 0)
	b = uv(b, 0)
	b = uv(b, uint64(transaction.NORMAL))
	b = uv(b, 7)
	b = append(b, make([]byte, 32)...)
	b = uv(b, uint64(len(burns)))
	for k, bv := range burns {
		b = uv(b, bv)
		b = append(b, make([]byte, 32)...)
		b = append(b, 0)
		b = append(b, make([]byte, 145)...)
		b = append(b, 1, 1) // power 1 (ring 2), bpp 1
		b = uv(b, uint64(10+k))
		b = append(b, pt()...)
		b = append(b, 0, 1)
		b = append(b, pt()...)
		b = append(b, pt()...)
		b = append(b, make([]byte, 32)...)
	}
	for range burns {
		for _, r := range proofLayout(1) {
			for j := 0; j < r.count; j++ {
				if r.kind == 'P' {
					b = append(b, pt()...)
				} else if scalar != nil {
					b = append(b, scalar...)
					scalar = nil
				} else {
					b = append(b, make([]byte, 32)...)
				}
			}
		}
	}
	return b
}

func be32(x *big.Int) []byte { s := make([]byte, 32); x.FillBytes(s); return s }

func TestR30CanonScalarOrderCounted(t *testing.T) {
	for _, c := range []struct {
		name string
		v    *big.Int
		want int
	}{{"Order-1", new(big.Int).Sub(bn256.Order, big.NewInt(1)), 0}, {"Order", bn256.Order, 1},
		{"Order+1", new(big.Int).Add(bn256.Order, big.NewInt(1)), 1}} {
		_, cs, cf, err := canon(synthTx([]uint64{0}, be32(c.v)), transaction.NORMAL)
		if err != nil || cs == 0 {
			t.Fatalf("%s: walk %v cs %d", c.name, err, cs)
		}
		if got := cf["proof-scalar-not-reduced"]; got != c.want {
			t.Fatalf("%s: scalar-not-reduced %d, want %d", c.name, got, c.want)
		}
	}
}

func TestR30CanonPointChecks(t *testing.T) {
	if q := pointProblem(pt()); q != "" {
		t.Fatalf("canonical point flagged %q", q)
	}
	p := pt()
	p[32] = 2
	if pointProblem(p) != "point-flag-not-0-or-1" {
		t.Fatal("flag 2 not flagged")
	}
	if pointProblem(append(be32(bn256.P), 0)) != "point-x-not-reduced" {
		t.Fatal("x = P not flagged")
	}
	var nr []byte
	for x := int64(2); x < 50; x++ { // first x with x^3+3 a non-residue
		q := append(be32(big.NewInt(x)), 0)
		if pointProblem(q) == "point-not-on-curve" {
			nr = q
			break
		}
	}
	if nr == nil {
		t.Fatal("no off-curve x found below 50: the on-curve check never fires")
	}
	cp, cs, cf, err := canon(synthTx([]uint64{0, 0}, nil), transaction.NORMAL)
	if err != nil || len(cf) != 0 {
		t.Fatalf("clean tx: %v %v", err, cf)
	}
	// per payload: D + 2 C = 3 statement points; proof (L=1): 4+8+1+2+14 = 29 points, 2+1+2+5+2 = 12 scalars
	if cp != 2*(3+29) || cs != 2*12 {
		t.Fatalf("counts cp %d cs %d", cp, cs)
	}
}

func TestR30BurnSumAllPayloads(t *testing.T) {
	o := decode("t", synthTx([]uint64{5, 7}, nil))
	if !o.OK {
		t.Skipf("node decoder refuses the synthetic tx (%s): burn sum covered by the Python KAT", o.E)
	}
	if o.Burn != 12 || o.NP != 2 || o.Fee != 21 {
		t.Fatalf("burn %d np %d fee %d, want 12 2 21", o.Burn, o.NP, o.Fee)
	}
	if o.CP == 0 || o.CS == 0 {
		t.Fatal("canonicality not counted")
	}
}

func TestR30GenesisBlockCensus(t *testing.T) {
	gb := blockchain.Generate_Genesis_Block()
	o := decode("b", gb.Serialize())
	if !o.OK || !o.RS {
		t.Fatalf("genesis does not decode/re-serialize: %v", o.E)
	}
	if o.MT != transaction.PREMINE.String() || o.MV != config.PREMINE || o.MJ != 1 || o.H != 0 {
		t.Fatalf("genesis census mt %s mv %d mj %d h %d", o.MT, o.MV, o.MJ, o.H)
	}
	if o.RW != blockchain.CalcBlockReward(0) {
		t.Fatalf("rw %d", o.RW)
	}
	var bl block.Block
	bl.Major_Version, bl.Minor_Version, bl.Height = 2, 0, 6999999 // the last block of epoch 0: reward(h+1) differs
	bl.Miner_TX.Version, bl.Miner_TX.TransactionType = 1, transaction.COINBASE
	bl.Miner_TX.MinerAddress = gb.Miner_TX.MinerAddress
	o = decode("b", bl.Serialize())
	if !o.OK || o.MJ != 2 || o.MT != "COINBASE" || o.MV != 0 || o.RW != blockchain.CalcBlockReward(6999999) {
		t.Fatalf("coinbase census %+v", o)
	}
}

// eulerOnCurve: the affine check the Jacobi form replaced (9782272d): x^3+3 == 0 or (x^3+3)^((P-1)/2) == 1 mod P.
func eulerOnCurve(x *big.Int) bool {
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x).Add(rhs, big.NewInt(3)).Mod(rhs, bn256.P)
	half := new(big.Int).Rsh(new(big.Int).Sub(bn256.P, big.NewInt(1)), 1)
	return rhs.Sign() == 0 || new(big.Int).Exp(rhs, half, bn256.P).Cmp(big.NewInt(1)) == 0
}

// TestR30OnCurveJacobiEqualsEuler (r30 verifier, item 9): the Jacobi on-curve verdict equals the Euler criterion it
// replaced AND the node's own Decompress (bn256/changes.go:215, ModSqrt) on every x of the corpus: x = 0 (the identity's
// compressed encoding, 33 zero bytes, which the node itself refuses: 3 is a non-residue mod P), 1..2047, P-2048..P-1,
// 512 hash-derived x, and the compressed G1 generator; both flags. Off-curve and on-curve x both occur (asserted).
func TestR30OnCurveJacobiEqualsEuler(t *testing.T) {
	var xs []*big.Int
	for i := int64(0); i < 2048; i++ {
		xs = append(xs, big.NewInt(i), new(big.Int).Sub(bn256.P, big.NewInt(i+1)))
	}
	h := sha256.Sum256([]byte("r30 jacobi corpus"))
	for i := 0; i < 512; i++ {
		h = sha256.Sum256(h[:])
		xs = append(xs, new(big.Int).Mod(new(big.Int).SetBytes(h[:]), bn256.P))
	}
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1)).Compress()
	xs = append(xs, new(big.Int).SetBytes(g[:32]))
	on, off := 0, 0
	for _, x := range xs {
		for _, flag := range []byte{0, 1} {
			enc := append(be32(x), flag)
			jac := pointProblem(enc) == ""
			if jac != eulerOnCurve(x) {
				t.Fatalf("x %s flag %d: Jacobi %v != Euler %v", x, flag, jac, !jac)
			}
			if _, err := bn256.Decompress(enc); (err == nil) != jac {
				t.Fatalf("x %s flag %d: Jacobi %v != node Decompress ok %v", x, flag, jac, err == nil)
			}
			if jac {
				on++
			} else {
				off++
			}
		}
	}
	if pointProblem(make([]byte, 33)) != "point-not-on-curve" {
		t.Fatal("the identity encoding (33 zero bytes) is not reported apart as the node refuses it")
	}
	if on == 0 || off == 0 {
		t.Fatalf("corpus has on %d / off %d: both verdicts must occur", on, off)
	}
	if pointProblem(g) != "" {
		t.Fatal("the compressed generator is flagged")
	}
}
