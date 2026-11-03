package dsa

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

// workInput is a fixed vector recipe: byte 0 = 1, bytes 8..42 = k*7+11, bytes 43..45 = i
// little-endian. The corpus is regenerated here with OUR consensus code; no third-party generator runs.
func workInput(i int) []byte {
	var b [48]byte
	b[0] = 1
	for k := 8; k <= 42; k++ {
		b[k] = byte(k*7 + 11)
	}
	b[43], b[44], b[45] = byte(i), byte(i>>8), byte(i>>16)
	return b[:]
}

func inputs() [][]byte {
	var in [][]byte
	for i := 0; i < 512; i++ {
		in = append(in, workInput(i))
	}
	for _, nonce := range []uint32{0, 1, 2, 3, 255, 256, 65535, 0x5f3759df, 0xfffffffe, 0xffffffff} {
		var b [48]byte
		binary.BigEndian.PutUint32(b[39:43], nonce)
		in = append(in, b[:])
	}
	r := rand.New(rand.NewSource(20261022))
	for i := 0; i < 128; i++ {
		b := make([]byte, 1+r.Intn(255))
		r.Read(b)
		in = append(in, b)
	}
	in = append(in, bytes.Repeat([]byte{0}, 48), bytes.Repeat([]byte{0xff}, 48))
	return in
}

// The whole hash must be identical with the fast sort installed. A suffix array is unique, so any difference is a bug.
func TestHashEquivalence(t *testing.T) {
	var used, declined int64
	before := atomic.LoadUint64(&astrobwtv3.RecoveredPanics)
	for i, in := range inputs() {
		astrobwtv3.SuffixSort = nil
		ref := astrobwtv3.AstroBWTv3(in)
		astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
			ok := SuffixArray(text, sa)
			if ok {
				atomic.AddInt64(&used, 1)
			} else {
				atomic.AddInt64(&declined, 1)
			}
			return ok
		}
		got := astrobwtv3.AstroBWTv3(in)
		astrobwtv3.SuffixSort = nil
		if got != ref {
			t.Fatalf("input %d (%x): hash %x with the descriptor sort, %x with SA-IS", i, in, got, ref)
		}
	}
	if after := atomic.LoadUint64(&astrobwtv3.RecoveredPanics); after != before {
		t.Fatalf("%d recovered panic(s) during the run", after-before)
	}
	if used == 0 {
		t.Fatal("the descriptor sort never ran (every text declined): the test proves nothing")
	}
	t.Logf("%d hashes identical; descriptor sort used %d, declined %d", used+declined, used, declined)
}

func naiveSA(t []byte) []int32 {
	sa := make([]int32, len(t))
	for i := range sa {
		sa[i] = int32(i)
	}
	sort.Slice(sa, func(a, b int) bool { return bytes.Compare(t[sa[a]:], t[sa[b]:]) < 0 })
	return sa
}

// Texts the hash never produces: random, all-equal, short, near-copy runs with edits, lengths around block edges.
func TestAgainstNaive(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	var texts [][]byte
	for _, n := range []int{1, 2, 3, 255, 256, 257, 511, 512, 513, 768, 1000, 4096, 8191, 8192, 8193} {
		b := make([]byte, n)
		r.Read(b)
		texts = append(texts, b, bytes.Repeat([]byte{0}, n), bytes.Repeat([]byte{0xab}, n))
	}
	for k := 0; k < 40; k++ { // near-copy 256-byte blocks, like stage 1
		blocks := 1 + r.Intn(40)
		state := make([]byte, 256)
		r.Read(state)
		var b []byte
		for i := 0; i < blocks; i++ {
			if r.Intn(4) == 0 {
				r.Read(state)
			} else {
				p := r.Intn(256)
				for q := p; q < p+r.Intn(32) && q < 256; q++ {
					state[q] = byte(r.Intn(4)) // small alphabet: many equal keys, deep merges
				}
			}
			b = append(b, state...)
		}
		b = append(b, state[:r.Intn(256)]...)
		texts = append(texts, b)
	}
	for i, txt := range texts {
		sa := make([]int32, len(txt))
		if !SuffixArray(txt, sa) {
			continue // declining is allowed: the caller falls back
		}
		want := naiveSA(txt)
		for j := range want {
			if sa[j] != want[j] {
				t.Fatalf("text %d (len %d): sa[%d] = %d, want %d", i, len(txt), j, sa[j], want[j])
			}
		}
	}
}

// Per-hash cost with and without the fast sort, on the same 64 corpus inputs, one goroutine.
func benchHash(b *testing.B, fast bool) {
	in := inputs()[:64]
	if fast {
		astrobwtv3.SuffixSort = SuffixArray
	}
	defer func() { astrobwtv3.SuffixSort = nil }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		astrobwtv3.AstroBWTv3(in[i%len(in)])
	}
}

func BenchmarkHashSAIS(b *testing.B)       { benchHash(b, false) }
func BenchmarkHashDescriptor(b *testing.B) { benchHash(b, true) }

func TestVerifyRejectsWrongArrays(t *testing.T) {
	txt := []byte("abracadabra-abracadabra")
	sa := naiveSA(txt)
	if !Verify(txt, sa) {
		t.Fatal("the true suffix array was rejected")
	}
	bad := append([]int32(nil), sa...)
	bad[3], bad[4] = bad[4], bad[3]
	if Verify(txt, bad) {
		t.Fatal("a swapped pair was accepted")
	}
	dup := append([]int32(nil), sa...)
	dup[5] = dup[6]
	if Verify(txt, dup) {
		t.Fatal("a duplicate index was accepted")
	}
	for _, v := range []int32{-1, int32(len(txt))} {
		out := append([]int32(nil), sa...)
		out[len(out)-1] = v
		if Verify(txt, out) {
			t.Fatalf("an out-of-range index %d was accepted", v)
		}
	}
}

// TestFreshScratchTail: every call gets a freshly sized scratch (as when sync.Pool has dropped its objects), and the
// texts are random, so most blocks are unique and the tail must still fit (or grow) without indexing past s.desc.
func TestFreshScratchTail(t *testing.T) {
	r := rand.New(rand.NewSource(764))
	for _, n := range []int{257, 300, 511, 700, 1000, 1023, 1500, 2047, 3000} {
		txt := make([]byte, n)
		r.Read(txt)
		pool = sync.Pool{}
		sa := make([]int32, n)
		if !SuffixArray(txt, sa) {
			continue // a decline is allowed: the caller falls back
		}
		want := naiveSA(txt)
		for i := range want {
			if want[i] != sa[i] {
				t.Fatalf("n=%d: differs from naive at %d", n, i)
			}
		}
	}
}
