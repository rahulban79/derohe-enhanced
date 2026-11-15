// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package crypto

// r31 (cryptography area, rft §7 B278 / B283): the primitives census of cryptography/crypto: hash and hash-to-point
// labels (B278 (3)), the randomness sources of key and blinding paths (B278 (2)), and the decoders' input classes
// (detector-crypto-input, detector-error-paths, detector-fuzz-coverage findings). cryptography/ is consensus code
// (consensus guard S1): nothing here changes it; each test PINS today's behaviour so a change shows up as a failing
// test and goes through the disclosure-style track (rft §0.5) instead of landing. Wording is defensive: a case names
// a check that is present or missing, never how to use a missing one.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"golang.org/x/crypto/sha3"
)

// TestR31HashLabelsKAT: Keccak-256 (legacy padding) known answers; HashtoNumber is that hash; the generators are
// hash-to-point images of the labels PROTOCOL_CONSTANT+"G" / +"H" (and +label+32-byte index for the vectors), pinned
// by value, distinct from each other. A change of a label, of the hash or of the hash-to-point map changes every
// commitment and proof (consensus): it must fail here.
func TestR31HashLabelsKAT(t *testing.T) {
	kat := map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	}
	for in, want := range kat {
		h := Keccak256([]byte(in))
		if hex.EncodeToString(h[:]) != want {
			t.Fatalf("Keccak256(%q) = %x", in, h[:])
		}
		ref := sha3.NewLegacyKeccak256()
		ref.Write([]byte(in))
		if HashtoNumber([]byte(in)).Cmp(new(big.Int).SetBytes(ref.Sum(nil))) != 0 {
			t.Fatalf("HashtoNumber(%q) is not legacy Keccak-256", in)
		}
	}
	if PROTOCOL_CONSTANT != "DERO" {
		t.Fatalf("PROTOCOL_CONSTANT = %q", PROTOCOL_CONSTANT)
	}
	gp := NewGeneratorParams(2)
	pinned := []struct {
		name string
		p    *bn256.G1
		hex  string
	}{
		{"G", G, "02eacfbf92b94015c9b0b3d901dae37ec68f74dea7e4484c76d505aade4ad7c001"},
		{"GP.G", gp.G, "02eacfbf92b94015c9b0b3d901dae37ec68f74dea7e4484c76d505aade4ad7c001"},
		{"H", gp.H, "268a955ce9d9444dbacc12db3dd1d51cca17ab9d6469c10899cd89c8665d25aa00"},
		{"Gs[0]", gp.Gs.vector[0], "08ed9cf63e34481c0c24351e71c0f119e1e182781fb14ead9756713b926be41200"},
		{"Hs[1]", gp.Hs.vector[1], "20f85793860c2a003e14eaab500da92a4f7e0e89bd378a639b00092f5dbbaf9101"},
	}
	seen := map[string]string{}
	for _, c := range pinned {
		got := hex.EncodeToString(c.p.EncodeCompressed())
		if got != c.hex {
			t.Fatalf("generator %s = %s, pinned %s (a label / hash / hash-to-point change is consensus-visible)", c.name, got, c.hex)
		}
		if prev, ok := seen[got]; ok && !(c.name == "GP.G" && prev == "G") {
			t.Fatalf("generators %s and %s coincide", prev, c.name)
		}
		seen[got] = c.name
	}
	if r := ReducedHash([]byte("r31")); r.Sign() < 0 || r.Cmp(bn256.Order) >= 0 {
		t.Fatalf("ReducedHash not reduced")
	}
}

// TestR31PointTextDecodeCensus: Point.UnmarshalText (finding DF-crypto-input-5325afeed7) is the hex front of
// Point.DecodeCompressed. Its only JSON caller is the wallet key file (walletapi/wallet.go _Keys.Public); the
// wallet now checks the decoded key against its secret on open (walletapi/r31_wallet_keys.go). Pinned here: a
// hex error is refused (also hex followed by garbage), and for every byte string the text decoder accepts exactly
// what DecodeCompressed accepts (no extra check, none missing).
func TestR31PointTextDecodeCensus(t *testing.T) {
	q := new(bn256.G1).ScalarMult(G, big.NewInt(12345))
	canon := hex.EncodeToString(q.EncodeCompressed())
	var p Point
	if err := p.UnmarshalText([]byte(canon)); err != nil || !bytes.Equal(p.EncodeCompressed(), q.EncodeCompressed()) {
		t.Fatalf("canonical text refused or changed: %v", err)
	}
	for _, bad := range []string{canon + "zz", canon[:65], "zz" + canon[2:], ""} {
		if err := new(Point).UnmarshalText([]byte(bad)); err == nil {
			t.Fatalf("text %q accepted", bad)
		}
	}
	enc := q.EncodeCompressed()
	for f := 0; f < 256; f += 51 {
		b := append([]byte{}, enc...)
		b[32] = byte(f)
		e1 := new(Point).UnmarshalText([]byte(hex.EncodeToString(b)))
		e2 := new(bn256.G1).DecodeCompressed(b)
		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("flag %#x: text decoder %v, compressed decoder %v", f, e1, e2)
		}
	}
}

// TestR31StatementTruncationPinned: Statement.Deserialize (finding DF-crypto-input-0a69e3be30) carries no scalar
// (ring size, key width, fee varint, points D and C[i], root hash: protocol_structures.go:94-200), so the scalar
// part of that finding does not apply; its points go through G1.DecodeCompressed (pinned in bn256). Pinned here: a
// statement cut inside C[] returns NO error (the shadowed err of `if n, err := r.Read(...)` is nil on a short read;
// disclosure claim C7, decoder short reads). The transaction decoder then fails on the proof that follows, so no
// truncated transaction decodes; consensus code, documented, not changed.
func TestR31StatementTruncationPinned(t *testing.T) {
	var b bytes.Buffer
	b.WriteByte(1) // ring of 2
	b.WriteByte(0) // no pointer bytes
	var v [binary.MaxVarintLen64]byte
	b.Write(v[:binary.PutUvarint(v[:], 7)])
	b.Write(new(bn256.G1).ScalarMult(G, big.NewInt(3)).EncodeCompressed())
	b.Write(new(bn256.G1).ScalarMult(G, big.NewInt(4)).EncodeCompressed()[:10]) // C[0] cut short
	var s Statement
	err := s.Deserialize(bytes.NewReader(b.Bytes()))
	if err != nil || len(s.C) != 0 || s.RingSize != 2 {
		t.Fatalf("pinned: a short read inside C[] returns nil with C empty; got err=%v len(C)=%d ring=%d", err, len(s.C), s.RingSize)
	}
	// at a clean EOF the reader reports io.EOF: refused
	var s2 Statement
	if err := s2.Deserialize(bytes.NewReader(b.Bytes()[:3])); err == nil {
		t.Fatalf("a statement that ends before D was accepted")
	}
}

// r31Panic runs f and returns the recovered value (nil when f returned).
func r31Panic(f func()) (r interface{}) {
	defer func() { r = recover() }()
	f()
	return nil
}

// TestR31PanicDecodersPinned: the four decoders that panic instead of returning an error (detector-error-paths
// panic-in-decoder): NonceBalance.Unmarshal / UnmarshalNonce, ElGamal.Deserialize, HexToKey. Each panics with the
// pinned message on the pinned class and round-trips honest input. Callers: UnmarshalNonce from
// blockchain/transaction_verify.go (bytes from the node's own balance tree), NonceBalance.Deserialize from
// glue/emission and tools/forensics (own store, under recover), ElGamal.Deserialize from the same plus walletapi
// (own values); HexToKey and HexToHash have no caller in the tree. Consensus package: pinned, not changed.
func TestR31PanicDecodersPinned(t *testing.T) {
	eg := ConstructElGamal(new(bn256.G1).ScalarMult(G, big.NewInt(5)), new(bn256.G1).ScalarMult(G, big.NewInt(6)))
	nb := &NonceBalance{NonceHeight: 300, Balance: eg}
	ser := nb.Serialize()
	back := new(NonceBalance).Deserialize(ser)
	if back.NonceHeight != 300 || !bytes.Equal(back.Balance.Serialize(), eg.Serialize()) {
		t.Fatalf("NonceBalance round trip")
	}
	var n NonceBalance
	n.UnmarshalNonce(ser)
	if n.NonceHeight != 300 {
		t.Fatalf("UnmarshalNonce = %d", n.NonceHeight)
	}
	cases := []struct {
		name string
		f    func()
		want string
	}{
		{"NonceBalance.Unmarshal(empty)", func() { new(NonceBalance).Unmarshal(nil) }, "buf too small or value larger than 64 bits"},
		{"NonceBalance.UnmarshalNonce(empty)", func() { new(NonceBalance).UnmarshalNonce(nil) }, "buf too small or value larger than 64 bits"},
		{"NonceBalance.Unmarshal(varint > 64 bits)", func() { new(NonceBalance).Unmarshal(bytes.Repeat([]byte{0xff}, 11)) }, "buf too small or value larger than 64 bits"},
		{"ElGamal.Deserialize(65 bytes)", func() { new(ElGamal).Deserialize(eg.Serialize()[:65]) }, "insufficient buffer size"},
		{"ElGamal.Deserialize(67 bytes)", func() { new(ElGamal).Deserialize(append(eg.Serialize(), 0)) }, "insufficient buffer size"},
		{"HexToKey(short)", func() { HexToKey("abcd") }, "Incorrect key size"},
		{"HexToHash(short)", func() { HexToHash("abcd") }, "Incorrect key size"},
	}
	for _, c := range cases {
		r := r31Panic(c.f)
		if s, ok := r.(string); !ok || s != c.want {
			t.Errorf("%s: recovered %v, pinned panic %q", c.name, r, c.want)
		}
	}
	bad := eg.Serialize()
	copy(bad[:33], make([]byte, 33)) // left point x = 0: not on the curve
	if r := r31Panic(func() { new(ElGamal).Deserialize(bad) }); r == nil {
		t.Errorf("ElGamal.Deserialize accepted an undecodable point")
	} else if _, isErr := r.(error); !isErr {
		t.Errorf("ElGamal.Deserialize panicked with %T, pinned: the decoder's error value", r)
	}
}

// TestR31TextDecodersDiscardHexErrorPinned: the discarded hex errors (detector-error-paths discarded-error) of
// HexToKey, HexToHash and Key.UnmarshalText: 64 hex digits followed by non-hex text decode to the 32-byte prefix
// (the R22 audit pinned Hash/Key.UnmarshalText; TestR22HashUnmarshalTextAcceptsTrailingGarbage). HashHexToHash, the
// helper the RPC handlers use, checks the error and returns the zero hash. BNRed.UnmarshalText (the wallet key file's
// secret) stops at the first space. All pinned; the wallet's open check compares the secret with its public key.
func TestR31TextDecodersDiscardHexErrorPinned(t *testing.T) {
	h := Keccak256([]byte("r31 text decoders"))
	hx := hex.EncodeToString(h[:])
	if k := HexToKey(hx + "zz"); !bytes.Equal(k[:], h[:]) {
		t.Fatalf("HexToKey(hex+garbage) pinned to decode the prefix")
	}
	if k := HexToHash(hx + "zz"); !bytes.Equal(k[:], h[:]) {
		t.Fatalf("HexToHash(hex+garbage) pinned to decode the prefix")
	}
	var k Key
	if err := k.UnmarshalText([]byte(hx + "zz")); err != nil || !bytes.Equal(k[:], h[:]) {
		t.Fatalf("Key.UnmarshalText(hex+garbage) pinned to decode the prefix: %v", err)
	}
	if z := HashHexToHash(hx + "zz"); !z.IsZero() {
		t.Fatalf("HashHexToHash checks the hex error: zero hash expected")
	}
	if z := HashHexToHash(hx); z != h {
		t.Fatalf("HashHexToHash canonical")
	}
	var x BNRed
	if err := x.UnmarshalText([]byte("abc def")); err != nil || x.BigInt().Int64() != 0xabc {
		t.Fatalf("BNRed.UnmarshalText pinned to stop at the first space: %v %v", err, x.BigInt())
	}
	if err := new(BNRed).UnmarshalText([]byte("xyz")); err == nil {
		t.Fatalf("BNRed.UnmarshalText accepted non-hex")
	}
}

// FuzzR31CryptoTextDecoders: the text and fixed-size decoders (HexToKey, HexToHash, Key/Hash/BNRed/Point
// UnmarshalText, Key.FromBytes) never panic except with the pinned message, and an accepted Key/Hash is the decoded
// hex prefix. Seeds run as a unit test.
func FuzzR31CryptoTextDecoders(f *testing.F) {
	h := Keccak256([]byte("seed"))
	f.Add(hex.EncodeToString(h[:]))
	f.Add(hex.EncodeToString(h[:]) + "zz")
	f.Add(hex.EncodeToString(new(bn256.G1).ScalarMult(G, big.NewInt(9)).EncodeCompressed()))
	f.Add("abc def")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		for _, fn := range []func(string){func(s string) { HexToKey(s) }, func(s string) { HexToHash(s) }} {
			if r := r31Panic(func() { fn(s) }); r != nil && r != "Incorrect key size" {
				t.Fatalf("unpinned panic %v", r)
			}
		}
		var k Key
		if k.UnmarshalText([]byte(s)) == nil {
			pre, _ := hex.DecodeString(s)
			if len(pre) != 32 || !bytes.Equal(k[:], pre) {
				t.Fatalf("Key.UnmarshalText accepted %q as %x", s, k[:])
			}
			var k2 Key
			k2.FromBytes(k.ToBytes())
			if k2 != k {
				t.Fatalf("Key.FromBytes round trip")
			}
		}
		var hh Hash
		if hh.UnmarshalText([]byte(s)) == nil {
			pre, _ := hex.DecodeString(s)
			if !bytes.Equal(hh[:], pre) {
				t.Fatalf("Hash.UnmarshalText accepted %q as %x", s, hh[:])
			}
		}
		var x BNRed
		x.UnmarshalText([]byte(s))
		var p Point
		if p.UnmarshalText([]byte(s)) == nil {
			raw, err := hex.DecodeString(s)
			if err != nil || new(bn256.G1).DecodeCompressed(raw) != nil {
				t.Fatalf("Point.UnmarshalText accepted %q that DecodeCompressed refuses", s)
			}
		}
	})
}

// FuzzR31NonceBalanceDecoders: NonceBalance.Unmarshal / Deserialize / UnmarshalNonce and ElGamal.Deserialize panic
// only with their pinned messages or the point decoder's error value, never with a runtime error (index out of
// range, nil dereference). Seeds run as a unit test.
func FuzzR31NonceBalanceDecoders(f *testing.F) {
	eg := ConstructElGamal(new(bn256.G1).ScalarMult(G, big.NewInt(5)), new(bn256.G1).ScalarMult(G, big.NewInt(6)))
	f.Add((&NonceBalance{NonceHeight: 1, Balance: eg}).Serialize())
	f.Add(eg.Serialize())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 70))
	pinned := map[string]bool{"buf too small or value larger than 64 bits": true, "insufficient buffer size": true}
	check := func(t *testing.T, name string, fn func()) {
		r := r31Panic(fn)
		if r == nil {
			return
		}
		if _, rt := r.(runtime.Error); rt {
			t.Fatalf("%s: runtime panic %v", name, r)
		}
		if s, ok := r.(string); ok && !pinned[s] {
			t.Fatalf("%s: unpinned panic %q", name, s)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		check(t, "Unmarshal", func() { var nb NonceBalance; nb.Unmarshal(b) })
		check(t, "Deserialize", func() { var nb NonceBalance; nb.Deserialize(b) })
		check(t, "UnmarshalNonce", func() { var nb NonceBalance; nb.UnmarshalNonce(b) })
		check(t, "ElGamal.Deserialize", func() { var eg ElGamal; eg.Deserialize(b) })
	})
}

// r31Root is the repository root (this file is cryptography/crypto/...).
func r31Root(t *testing.T) string {
	_, me, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("no caller")
	}
	return filepath.Join(filepath.Dir(me), "..", "..")
}

// TestR31RandomnessSourceCensus (B278 (2), B15 re-verified): key and blinding randomness comes from crypto/rand.
//   - no file of cryptography/ imports math/rand;
//   - globals/random.go's CryptoRandSource reads only crypto/rand (B15: its discarded error is moot since go1.24,
//     crypto/rand.Read never returns one; rft §7 B15 REFUTED);
//   - every math/rand generator in walletapi (ring order, decoy picks) is built on globals.NewCryptoRandSource(),
//     never on a seeded math/rand source.
func TestR31RandomnessSourceCensus(t *testing.T) {
	root := r31Root(t)
	fset := token.NewFileSet()
	parse := func(rel string) *ast.File {
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		return f
	}
	importName := func(f *ast.File, path string) string {
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == path {
				if im.Name != nil {
					return im.Name.Name
				}
				return filepath.Base(p)
			}
		}
		return ""
	}
	list := func(dir string) []string {
		m, _ := filepath.Glob(filepath.Join(root, dir, "*.go"))
		var out []string
		for _, x := range m {
			if !strings.HasSuffix(x, "_test.go") {
				r, _ := filepath.Rel(root, x)
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			t.Fatalf("no sources in %s", dir)
		}
		return out
	}
	for _, rel := range append(list("cryptography/crypto"), list("cryptography/bn256")...) {
		if importName(parse(rel), "math/rand") != "" {
			t.Errorf("%s imports math/rand", rel)
		}
	}
	// globals/random.go: every X.Read / X.Int call in CryptoRandSource methods is on the crypto/rand import
	g := parse("globals/random.go")
	crand, mrand := importName(g, "crypto/rand"), importName(g, "math/rand")
	reads := 0
	ast.Inspect(g, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
			return true
		}
		if id, ok := fd.Recv.List[0].Type.(*ast.Ident); !ok || id.Name != "CryptoRandSource" {
			return false
		}
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && (x.Name == crand || x.Name == mrand) {
					if x.Name != crand {
						t.Errorf("globals/random.go %s: CryptoRandSource uses %s.%s", fset.Position(sel.Pos()), x.Name, sel.Sel.Name)
					} else {
						reads++
					}
				}
			}
			return true
		})
		return false
	})
	if reads == 0 {
		t.Errorf("globals/random.go: CryptoRandSource does not read crypto/rand")
	}
	// walletapi: math/rand generators are built on the crypto source only
	for _, rel := range list("walletapi") {
		f := parse(rel)
		mr := importName(f, "math/rand")
		if mr == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == mr {
				switch sel.Sel.Name {
				case "New":
					arg := ""
					if len(call.Args) == 1 {
						if c, ok := call.Args[0].(*ast.CallExpr); ok {
							if s, ok := c.Fun.(*ast.SelectorExpr); ok {
								if p, ok := s.X.(*ast.Ident); ok {
									arg = p.Name + "." + s.Sel.Name
								}
							}
						}
					}
					if arg != "globals.NewCryptoRandSource" {
						t.Errorf("%s %s: math/rand generator not built on globals.NewCryptoRandSource (%s)", rel, fset.Position(call.Pos()), arg)
					}
				default:
					t.Errorf("%s %s: package-level math/rand.%s (the shared, non-crypto source)", rel, fset.Position(call.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
}
