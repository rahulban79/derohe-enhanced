package crypto

// r25 (cryptodisc, backlog BD9 / disclosure fact NF24-5): does a proof scalar written as value + bn256.Order (a
// non-reduced 32-byte encoding of the same residue) verify like its reduced value?
//
// The test builds an HONEST transfer statement and witness (ring of 4, the wallet's commitment layout of
// walletapi/transaction_build.go), proves it with GenerateProof, and checks the honest proof verifies before and after a
// serialize/deserialize round trip. Then, one field at a time, it re-encodes that field as value + Order (the residue is
// unchanged), serializes, deserializes and runs Verify. Nothing here constructs a proof of a false statement: the
// statement and the residues are the honest ones; only the byte encoding of one field changes. The result is a
// decode-hygiene fact (C3 / FX-F3 / FX-N4) and it is pinned below, so a change of the verifier's treatment of any
// field flips this test.

import (
	"bytes"
	"math/big"
	"strconv"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
)

type r25Honest struct {
	s     Statement
	proof *Proof
	txid  Hash
	m     int
}

func r25HonestProof(t *testing.T, ringsize, sender, receiver int) r25Honest {
	t.Helper()
	const balance, value, fees = uint64(1000), uint64(7), uint64(3)
	if sender%2 == receiver%2 {
		t.Fatalf("sender and receiver need different parity (pick_ring_order)")
	}
	var secrets []*big.Int
	var keys []*bn256.G1
	for i := 0; i < ringsize; i++ {
		sk := RandomScalar()
		secrets = append(secrets, sk)
		keys = append(keys, new(bn256.G1).ScalarMult(G, sk))
	}
	r := RandomScalar()
	var C, CLn, CRn []*bn256.G1
	D := new(bn256.G1).ScalarMult(G, r)
	for i := range keys {
		var amount *big.Int
		switch i {
		case sender:
			amount = new(big.Int).SetInt64(0 - int64(value) - int64(fees))
		case receiver:
			amount = new(big.Int).SetInt64(int64(value))
		default:
			amount = new(big.Int)
		}
		x := new(bn256.G1).ScalarMult(G, amount)
		x.Add(new(bn256.G1).Set(x), new(bn256.G1).ScalarMult(keys[i], r))
		C = append(C, x)
		bal := uint64(0)
		if i == sender {
			bal = balance
		}
		k := RandomScalar() // the account's current encrypted balance: (G^bal * pk^k, G^k)
		left := new(bn256.G1).Add(new(bn256.G1).ScalarMult(G, new(big.Int).SetUint64(bal)), new(bn256.G1).ScalarMult(keys[i], k))
		right := new(bn256.G1).ScalarMult(G, k)
		CLn = append(CLn, new(bn256.G1).Add(left, x))
		CRn = append(CRn, new(bn256.G1).Add(right, D))
	}
	var h r25Honest
	h.s = Statement{CLn: CLn, CRn: CRn, Publickeylist: keys, C: C, D: D, Fees: fees}
	copy(h.s.Roothash[:], []byte("r25 honest statement root hash.."))
	h.txid = Keccak256([]byte("r25 honest statement txid"))
	w := Witness{SecretKey: secrets[sender], R: r, TransferAmount: value, Balance: balance - value - fees, Index: []int{sender, receiver}}
	var scid Hash
	uinput := append([]byte(PROTOCOL_CONSTANT), h.s.Roothash[:]...)
	uinput = append(uinput, scid[:]...)
	uinput = append(uinput, strconv.Itoa(0)...)
	u := new(bn256.G1).ScalarMult(HashToPoint(HashtoNumber(uinput)), secrets[sender])
	h.proof = GenerateProof(scid, 0, &h.s, &w, u, h.txid, 0)
	h.m = GetPowerof2(ringsize)
	return h
}

func (h r25Honest) bytesOf(p *Proof) []byte {
	var b bytes.Buffer
	p.Serialize(&b)
	return b.Bytes()
}

func (h r25Honest) decode(t *testing.T, b []byte) *Proof {
	t.Helper()
	var p Proof
	if err := p.Deserialize(bytes.NewReader(b), h.m); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	return &p
}

func (h r25Honest) verify(p *Proof) bool {
	var scid Hash
	return p.Verify(scid, 0, &h.s, h.txid, 0)
}

// r25ScalarFields names every scalar of the proof encoding and returns a pointer to it in p.
func r25ScalarFields(p *Proof) []struct {
	name string
	v    **big.Int
} {
	var out []struct {
		name string
		v    **big.Int
	}
	add := func(n string, v **big.Int) {
		out = append(out, struct {
			name string
			v    **big.Int
		}{n, v})
	}
	for i := range p.f.vector {
		add("f["+strconv.Itoa(i)+"]", &p.f.vector[i])
	}
	add("z_A", &p.z_A)
	add("that", &p.that)
	add("mu", &p.mu)
	add("c", &p.c)
	add("s_sk", &p.s_sk)
	add("s_r", &p.s_r)
	add("s_b", &p.s_b)
	add("s_tau", &p.s_tau)
	add("ip.a", &p.ip.a)
	add("ip.b", &p.ip.b)
	return out
}

// r25ReencodeTable re-encodes each field as value+Order and reports whether Verify still accepts.
func r25ReencodeTable(t *testing.T, h r25Honest) map[string]bool {
	t.Helper()
	honest := h.bytesOf(h.proof)
	res := map[string]bool{}
	names := r25ScalarFields(h.decode(t, honest))
	for idx := range names {
		p := h.decode(t, honest)
		f := r25ScalarFields(p)[idx]
		v := new(big.Int).Add(*f.v, bn256.Order)
		if v.BitLen() > 256 {
			t.Fatalf("%s: value+Order does not fit 32 bytes", f.name)
		}
		*f.v = v
		b := h.bytesOf(p)
		if bytes.Equal(b, honest) {
			t.Fatalf("%s: the re-encoding did not change the bytes", f.name)
		}
		q := h.decode(t, b)
		if got := new(big.Int).SetBytes(ConvertBigIntToByte(*r25ScalarFields(q)[idx].v)); got.Cmp(bn256.Order) < 0 {
			t.Fatalf("%s: decode reduced the value (%s); NF24-5 says SetBytes keeps it", f.name, got)
		}
		res[f.name] = h.verify(q)
	}
	return res
}

// r25ReencodeExpected pins the measured result (2026-11-03, r25): true = the non-reduced encoding is accepted exactly
// like the reduced one (an encoding malleability of the proof bytes, which are outside the TXID, NF24-2); false = Verify
// refuses it. Measured on rings of 2, 4 and 8 with both sender parities (r25Rings): only c (Verify compares its hex text
// with the recomputed challenge, proof_verify.go:422) and the f element that Verify's parity check compares with w as a
// number (proof_verify.go:136) refuse the non-reduced encoding; every other scalar is used only modulo Order.
var r25ReencodeExpected = map[string]bool{
	"f[parity-w]": false, "c": false,
	"f[parity-0]": true, "f[other]": true, "z_A": true, "that": true, "mu": true,
	"s_sk": true, "s_r": true, "s_b": true, "s_tau": true, "ip.a": true, "ip.b": true,
}

func TestR25HonestProofVerifies(t *testing.T) {
	for _, c := range r25Rings {
		n := c[0]
		h := r25HonestProof(t, n, c[1], c[2])
		if !h.verify(h.proof) {
			t.Fatalf("ring %d: the honest proof does not verify", n)
		}
		b := h.bytesOf(h.proof)
		q := h.decode(t, b)
		if !h.verify(q) {
			t.Fatalf("ring %d: the honest proof does not verify after a round trip", n)
		}
		if !bytes.Equal(h.bytesOf(q), b) {
			t.Fatalf("ring %d: round trip changed the bytes", n)
		}
		for _, f := range r25ScalarFields(q) {
			if (*f.v).Cmp(bn256.Order) >= 0 {
				t.Fatalf("ring %d: honest prover wrote %s >= Order", n, f.name)
			}
		}
		// negative control: the honest proof does not verify a different statement (another txid)
		var scid Hash
		if q.Verify(scid, 0, &h.s, Keccak256([]byte("r25 other txid")), 0) {
			t.Fatalf("ring %d: the honest proof verified against another txid", n)
		}
	}
}

func TestR25ScalarReencodeVerifies(t *testing.T) {
	for _, c := range r25Rings {
		n := c[0]
		h := r25HonestProof(t, n, c[1], c[2])
		got := r25ReencodeTable(t, h)
		for _, f := range r25ScalarFields(h.proof) {
			t.Logf("R25-BD9 ring %d sender %d receiver %d field %s class %s value+Order accepted=%v", n, c[1], c[2], f.name, r25FieldClass(f.name, *f.v, h.m), got[f.name])
		}
		classes := map[string]string{}
		for _, f := range r25ScalarFields(h.proof) {
			classes[f.name] = r25FieldClass(f.name, *f.v, h.m)
		}
		for name, acc := range got {
			want, ok := r25ReencodeExpected[classes[name]]
			if !ok {
				t.Fatalf("ring %d: field %s has no pinned result", n, name)
			}
			if acc != want {
				t.Errorf("ring %d: field %s value+Order accepted=%v, pinned %v", n, name, acc, want)
			}
		}
	}
}

// r25Rings: {ring size, sender index, receiver index}; both parities of the sender, rings of 2, 4 and 8.
var r25Rings = [][3]int{{2, 0, 1}, {2, 1, 0}, {4, 0, 1}, {4, 3, 2}, {4, 1, 2}, {8, 6, 3}}

// r25FieldClass classes the f elements by their role in Verify's parity check (proof_verify.go: w is compared, as a
// number, with f[0] and with f[m]; an honest proof has one of the two equal to 0 and the other equal to w):
// "f[parity-w]" is the one of f[0], f[m] that is non-zero, "f[parity-0]" the zero one, "f[other]" every other index.
// Other names map to themselves.
func r25FieldClass(name string, honest *big.Int, m int) string {
	if len(name) > 2 && name[:2] == "f[" {
		if name != "f[0]" && name != "f["+strconv.Itoa(m)+"]" {
			return "f[other]"
		}
		if honest.Sign() == 0 {
			return "f[parity-0]"
		}
		return "f[parity-w]"
	}
	return name
}
