package main

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// hashOf encodes v (< 2^256) as the little-endian hash CheckPowHashBig reads.
func hashOf(v *big.Int) (h crypto.Hash) {
	var b [32]byte
	v.FillBytes(b[:])
	for i := 0; i < 32; i++ {
		h[i] = b[31-i]
	}
	return
}

// TestPowTargetMatchesCheckPowHashBig: random hashes, and hashes at and around the target, for difficulties from 1 to
// beyond 2^64 (including the live ~21.6M and values whose target has equal top words), give CheckPowHashBig's verdict.
func TestPowTargetMatchesCheckPowHashBig(t *testing.T) {
	r := rand.New(rand.NewSource(22))
	diffs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(255), big.NewInt(21600000), big.NewInt(21633979),
		new(big.Int).Lsh(big.NewInt(1), 64), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 200), new(big.Int).Lsh(big.NewInt(1), 255), new(big.Int).Lsh(big.NewInt(1), 256)}
	for i := 0; i < 40; i++ {
		diffs = append(diffs, new(big.Int).SetUint64(r.Uint64()>>uint(r.Intn(63))+1))
	}
	one := big.NewInt(1)
	max := new(big.Int).Sub(oneLsh256, one)
	n := 0
	for _, d := range diffs {
		tg := newPowTarget(d)
		q := new(big.Int).Div(oneLsh256, d)
		var probes []*big.Int
		for _, delta := range []int64{-2, -1, 0, 1, 2} {
			v := new(big.Int).Add(q, big.NewInt(delta))
			if v.Sign() >= 0 && v.Cmp(max) <= 0 {
				probes = append(probes, v)
			}
		}
		// same top word as the target, lower words random (exercises the word-by-word tie break)
		if q.BitLen() <= 256 {
			for k := 0; k < 8; k++ {
				var b [32]byte
				q.FillBytes(b[:])
				r.Read(b[8+r.Intn(24):])
				probes = append(probes, new(big.Int).SetBytes(b[:]))
			}
		}
		probes = append(probes, big.NewInt(0), max)
		for k := 0; k < 200; k++ {
			var b [32]byte
			r.Read(b[:])
			b[0] >>= uint(r.Intn(9)) // spread magnitudes
			probes = append(probes, new(big.Int).SetBytes(b[:]))
		}
		for _, v := range probes {
			h := hashOf(v)
			want := CheckPowHashBig(h, d)
			if got := tg.meets(h); got != want {
				t.Fatalf("difficulty %s hash %x: powTarget %v, CheckPowHashBig %v", d, v, got, want)
			}
			n++
		}
	}
	if n < 10000 {
		t.Fatalf("only %d probes", n)
	}
}

// TestPowTargetNegative: a non-positive difficulty takes CheckPowHashBig's path (zero still panics, as before).
func TestPowTargetNegative(t *testing.T) {
	tg := newPowTarget(big.NewInt(-5))
	var h crypto.Hash
	if tg.meets(h) != CheckPowHashBig(h, big.NewInt(-5)) {
		t.Fatal("negative difficulty verdict differs")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("zero difficulty must panic as CheckPowHashBig does")
		}
	}()
	z := newPowTarget(big.NewInt(0))
	z.meets(h)
}

var benchSink bool

func benchHashes() []crypto.Hash {
	r := rand.New(rand.NewSource(1))
	hs := make([]crypto.Hash, 4096)
	for i := range hs {
		r.Read(hs[i][:])
		binary.LittleEndian.PutUint64(hs[i][24:], r.Uint64()>>uint(r.Intn(40)))
	}
	return hs
}

func BenchmarkCheckPowHashBig(b *testing.B) {
	d := big.NewInt(21600000)
	hs := benchHashes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = CheckPowHashBig(hs[i&4095], d)
	}
}

func BenchmarkPowTargetMeets(b *testing.B) {
	tg := newPowTarget(big.NewInt(21600000))
	hs := benchHashes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = tg.meets(hs[i&4095])
	}
}

// r22: split_next precomputes the job's target (split_found then checks without big.Int) and refuses a zero
// difficulty (CheckPowHashBig would panic on the reply goroutine for every hash of the batch).
func TestSplitNextPrecomputesTarget(t *testing.T) {
	blob := make([]byte, 48)
	blob[0] = 0x41
	setJob(t, 10, blob, "21600000")
	var rb [12]byte
	w, ok := split_next(&rb)
	if !ok {
		t.Fatal("split_next refused a valid job")
	}
	sj := w.Tag.(*splitJob)
	if !sj.tgt.set {
		t.Fatal("split_next did not precompute the target")
	}
	q := new(big.Int).Div(oneLsh256, big.NewInt(21600000))
	for _, d := range []int64{-1, 0, 1} {
		h := hashOf(new(big.Int).Add(q, big.NewInt(d)))
		if sj.meets(h) != CheckPowHashBig(h, big.NewInt(21600000)) {
			t.Fatalf("target%+d: verdict differs from CheckPowHashBig", d)
		}
	}
	setJob(t, 10, blob, "0")
	if _, ok := split_next(&rb); ok {
		t.Fatal("split_next accepted a zero difficulty")
	}
}
