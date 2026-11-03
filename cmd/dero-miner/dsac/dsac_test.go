//go:build darwin && arm64 && cgo

package dsac

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
)

// inputs is cmd/dero-miner/dsa/dsa_test.go's 652-input recipe, unchanged.
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

// stage1Texts captures the exact text astrobwtv3 hands its suffix sort for each input (declining, so SA-IS runs).
func stage1Texts(t testing.TB) [][]byte {
	var texts [][]byte
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		texts = append(texts, append([]byte(nil), text...))
		return false
	}
	defer func() { astrobwtv3.SuffixSort = nil }()
	for _, in := range inputs() {
		astrobwtv3.AstroBWTv3(in)
	}
	if len(texts) != len(inputs()) {
		t.Fatalf("captured %d texts for %d inputs", len(texts), len(inputs()))
	}
	return texts
}

// C vs Go dsa vs dsa.Verify, on all 652 real stage-1 texts. A decline by C is counted, not failed, but must be rare.
func TestBitExactVsGoDSA(t *testing.T) {
	texts := stage1Texts(t)
	var declined, same int
	minN, maxN := 1<<30, 0
	for i, txt := range texts {
		n := len(txt)
		if n < minN {
			minN = n
		}
		if n > maxN {
			maxN = n
		}
		c := make([]int32, n+64)
		for j := range c {
			c[j] = -12345 // sentinel: proves nothing past n is written
		}
		g := make([]int32, n)
		if !dsa.SuffixArray(txt, g) {
			t.Fatalf("text %d: Go dsa declined", i)
		}
		if !SuffixArray(txt, c) {
			declined++
			continue
		}
		for j := n; j < len(c); j++ {
			if c[j] != -12345 {
				t.Fatalf("text %d (n=%d): C wrote past n at %d", i, n, j)
			}
		}
		if !dsa.Verify(txt, c[:n]) {
			t.Fatalf("text %d (n=%d): C array fails dsa.Verify", i, n)
		}
		for j := 0; j < n; j++ {
			if c[j] != g[j] {
				t.Fatalf("text %d (n=%d): C sa[%d]=%d, Go %d", i, n, j, c[j], g[j])
			}
		}
		same++
	}
	if same == 0 || declined*100 > len(texts) {
		t.Fatalf("identical %d, declined %d of %d", same, declined, len(texts))
	}
	t.Logf("%d stage-1 texts (n %d..%d): %d bit-identical to Go dsa and Verify-clean, %d declined", len(texts), minN, maxN, same, declined)
}

func naiveSA(t []byte) []int32 {
	sa := make([]int32, len(t))
	for i := range sa {
		sa[i] = int32(i)
	}
	sort.Slice(sa, func(a, b int) bool { return bytes.Compare(t[sa[a]:], t[sa[b]:]) < 0 })
	return sa
}

// Texts the hash never produces (dsa_test.go TestAgainstNaive's recipe, larger): random, constant, block-edge
// lengths, near-copy 256-byte blocks with a small alphabet, plus mutated real texts.
func synthTexts(seed int64) [][]byte {
	r := rand.New(rand.NewSource(seed))
	var texts [][]byte
	for _, n := range []int{1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 511, 512, 513, 768, 1000, 4096, 8191, 8192, 8193, 70000, 98303} {
		b := make([]byte, n)
		r.Read(b)
		texts = append(texts, b, bytes.Repeat([]byte{0}, n), bytes.Repeat([]byte{0xab}, n))
		ab := make([]byte, n)
		for i := range ab {
			ab[i] = "ab"[r.Intn(2)]
		}
		texts = append(texts, ab)
	}
	for k := 0; k < 300; k++ {
		blocks := 1 + r.Intn(300)
		state := make([]byte, 256)
		r.Read(state)
		var b []byte
		for i := 0; i < blocks; i++ {
			switch r.Intn(6) {
			case 0:
				r.Read(state)
			case 1: // identical block: whole run constant
			default:
				p := r.Intn(256)
				for q := p; q < p+r.Intn(48) && q < 256; q++ {
					state[q] = byte(r.Intn(3))
				}
			}
			b = append(b, state...)
		}
		b = append(b, state[:r.Intn(256)]...)
		texts = append(texts, b)
	}
	return texts
}

func TestSynthetic(t *testing.T) {
	var declined, same, naive int
	check := func(i int, txt []byte) {
		n := len(txt)
		c := make([]int32, n+64)
		for j := range c {
			c[j] = -12345
		}
		if !SuffixArray(txt, c) {
			declined++
			return
		}
		for j := n; j < len(c); j++ {
			if c[j] != -12345 {
				t.Fatalf("synthetic %d (n=%d): wrote past n", i, n)
			}
		}
		if !dsa.Verify(txt, c[:n]) {
			t.Fatalf("synthetic %d (n=%d): fails Verify", i, n)
		}
		g := make([]int32, n)
		if dsa.SuffixArray(txt, g) {
			for j := 0; j < n; j++ {
				if c[j] != g[j] {
					t.Fatalf("synthetic %d (n=%d): differs from Go dsa at %d", i, n, j)
				}
			}
		}
		if n <= 20000 {
			w := naiveSA(txt)
			for j := range w {
				if w[j] != c[j] {
					t.Fatalf("synthetic %d (n=%d): differs from naive at %d", i, n, j)
				}
			}
			naive++
		}
		same++
	}
	all := synthTexts(16)
	// mutated real texts: flip bytes in captured stage-1 texts
	r := rand.New(rand.NewSource(99))
	for _, txt := range stage1Texts(t)[:64] {
		m := append([]byte(nil), txt...)
		for k := 0; k < 1+r.Intn(64); k++ {
			m[r.Intn(len(m))] = byte(r.Intn(256))
		}
		all = append(all, m, m[:len(m)-1-r.Intn(255)])
	}
	for i, txt := range all {
		check(i, txt)
	}
	t.Logf("%d synthetic texts: %d correct (%d also vs naive), %d declined", len(all), same, naive, declined)
}

// Whole-hash equality with C installed via the astrobwtv3.SuffixSort hook.
func TestHashEquivalence(t *testing.T) {
	var used, declined int64
	before := atomic.LoadUint64(&astrobwtv3.RecoveredPanics)
	for i, in := range inputs() {
		astrobwtv3.SuffixSort = nil
		ref := astrobwtv3.AstroBWTv3(in)
		astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
			ok := SuffixArray(text, sa)
			if ok {
				used++
			} else {
				declined++
			}
			return ok
		}
		got := astrobwtv3.AstroBWTv3(in)
		astrobwtv3.SuffixSort = nil
		if got != ref {
			t.Fatalf("input %d: hash %x with C, %x with SA-IS", i, got, ref)
		}
	}
	if atomic.LoadUint64(&astrobwtv3.RecoveredPanics) != before {
		t.Fatal("recovered panic during the run")
	}
	if used == 0 {
		t.Fatal("C never ran")
	}
	t.Logf("%d hashes identical; C used %d, declined %d", used+declined, used, declined)
}

// Round 19 (NEON vmask/uniform-span/scatter): 2048 fresh miniblock-shaped inputs, none of them in the corpus, hashed
// with the C sort and with the consensus SA-IS (astrobwtv3.SuffixSort = nil). Every hash must agree and the C sort
// must actually have run on (almost) all of them.
func TestBitExactFresh2048(t *testing.T) {
	const N = 2048
	r := rand.New(rand.NewSource(19102026))
	in := make([][48]byte, N)
	for i := range in {
		r.Read(in[i][:])
		in[i][0] = in[i][0]&0xf0 | 1 // version 1, as mining requires
		binary.BigEndian.PutUint32(in[i][43:47], uint32(i))
		in[i][47] = 0xfe // the split-mode marker byte
	}
	hashAll := func() [][32]byte {
		out := make([][32]byte, N)
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := w; i < N; i += 4 {
					out[i] = astrobwtv3.AstroBWTv3(in[i][:])
				}
			}(w)
		}
		wg.Wait()
		return out
	}
	before := atomic.LoadUint64(&astrobwtv3.RecoveredPanics)
	astrobwtv3.SuffixSort = nil
	ref := hashAll()
	var used, declined int64
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		ok := SuffixArray(text, sa)
		if ok {
			atomic.AddInt64(&used, 1)
		} else {
			atomic.AddInt64(&declined, 1)
		}
		return ok
	}
	got := hashAll()
	astrobwtv3.SuffixSort = nil
	for i := range ref {
		if got[i] != ref[i] {
			t.Fatalf("fresh input %d: hash %x with C, %x with SA-IS", i, got[i], ref[i])
		}
	}
	if atomic.LoadUint64(&astrobwtv3.RecoveredPanics) != before {
		t.Fatal("recovered panic during the run")
	}
	if used < N-N/64 {
		t.Fatalf("C sort ran on only %d of %d texts (declined %d)", used, N, declined)
	}
	t.Logf("%d fresh hashes identical; C used %d, declined %d", N, used, declined)
}

// Concurrent use from many goroutines (each cgo call runs on one OS thread with its own __thread scratch).
func TestConcurrent(t *testing.T) {
	texts := stage1Texts(t)
	want := make([][32]byte, len(texts))
	_ = want
	var wg sync.WaitGroup
	var bad int32
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				txt := texts[(w*37+k)%len(texts)]
				c := make([]int32, len(txt))
				g := make([]int32, len(txt))
				if SuffixArray(txt, c) && dsa.SuffixArray(txt, g) {
					for j := range c {
						if c[j] != g[j] {
							atomic.StoreInt32(&bad, 1)
							return
						}
					}
				}
			}
		}(w)
	}
	wg.Wait()
	if bad != 0 {
		t.Fatal("concurrent C result differed from Go dsa")
	}
}

// Dumps the 652 stage-1 texts for the ASan/UBSan C harness: DSAC_DUMP=<file>.
func TestDumpCorpus(t *testing.T) {
	p := os.Getenv("DSAC_DUMP")
	if p == "" {
		t.Skip("set DSAC_DUMP")
	}
	var buf bytes.Buffer
	for _, txt := range append(stage1Texts(t), synthTexts(16)...) {
		binary.Write(&buf, binary.LittleEndian, uint32(len(txt)))
		buf.Write(txt)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Per-hash cost via the hook: Go dsa vs C, same 64 inputs, one goroutine.
func benchHash(b *testing.B, sorter func([]byte, []int32) bool) {
	in := inputs()[:64]
	astrobwtv3.SuffixSort = sorter
	defer func() { astrobwtv3.SuffixSort = nil }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		astrobwtv3.AstroBWTv3(in[i%len(in)])
	}
}

func BenchmarkHashGoDSA(b *testing.B) { benchHash(b, dsa.SuffixArray) }
func BenchmarkHashC(b *testing.B)     { benchHash(b, SuffixArray) }

// Sort-only cost on captured texts.
func benchSort(b *testing.B, sorter func([]byte, []int32) bool) {
	texts := stage1Texts(b)[:64]
	sa := make([]int32, 256*384)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sorter(texts[i%len(texts)], sa)
	}
}

func BenchmarkSortGoDSA(b *testing.B) { benchSort(b, dsa.SuffixArray) }
func BenchmarkSortC(b *testing.B)     { benchSort(b, SuffixArray) }

// zeroRunTexts (Round 21) builds texts whose suffixes starting with three zero bytes form big colliding groups (the
// zkey64 path): blocks of random bytes, mostly rekeyed so every column is its own list, each with a zero run of 3 to
// 1,100 bytes (across DSA_ZRUN_CAP = 1,024) followed by the same four bytes and then a random one, so equal run
// lengths tie on the zkey and are decided exactly one byte past what DSA_TIE_FROM skips. Some texts end in a zero run
// (the end-of-text keys), some have no other zeros at all.
func zeroRunTexts(seed int64) [][]byte {
	r := rand.New(rand.NewSource(seed))
	var texts [][]byte
	for k := 0; k < 120; k++ {
		blocks := 2 + r.Intn(60)
		b := make([]byte, 0, blocks*256+2048)
		state := make([]byte, 256)
		long := false // at most one run past the cap a text: a group over DSA_GROUP_CAP positions is declined by design
		for i := 0; i < blocks; i++ {
			if r.Intn(4) != 0 {
				r.Read(state)
				for q := range state {
					if state[q] == 0 {
						state[q] = 1 + byte(r.Intn(255))
					}
				}
			}
			b = append(b, state...)
			if r.Intn(3) == 0 {
				z := 3 + r.Intn(40)
				switch r.Intn(8) {
				case 0:
					if !long {
						z, long = 1000+r.Intn(100), true // straddles the cap
					}
				case 1:
					z = 3 + r.Intn(4)
				}
				b = append(b, make([]byte, z)...)
				b = append(b, 0x5a, 0x01, 0x02, 0x03, byte(r.Intn(256)))
			}
		}
		if k%3 == 0 {
			b = append(b, make([]byte, 1+r.Intn(300))...) // ends in a zero run
		}
		if len(b) > 256*384-1 {
			b = b[:256*384-1]
		}
		texts = append(texts, b)
	}
	return texts
}

// TestZeroRuns checks the zero-run tie-break keys against the naive suffix array and the Go dsa on texts made to
// exercise every branch of zkey64 (run lengths, the cap, end-of-text runs, ties settled just past the skipped prefix).
func TestZeroRuns(t *testing.T) {
	var declined, checked int
	for i, txt := range zeroRunTexts(21) {
		n := len(txt)
		c := make([]int32, n+64)
		for j := range c {
			c[j] = -12345
		}
		if !SuffixArray(txt, c) {
			declined++
			continue
		}
		for j := n; j < len(c); j++ {
			if c[j] != -12345 {
				t.Fatalf("zero-run text %d (n=%d): wrote past n", i, n)
			}
		}
		var w []int32
		if n <= 24000 {
			w = naiveSA(txt)
		} else {
			w = make([]int32, n)
			if !dsa.SuffixArray(txt, w) {
				if !dsa.Verify(txt, c[:n]) {
					t.Fatalf("zero-run text %d (n=%d): fails Verify", i, n)
				}
				checked++
				continue
			}
		}
		for j := range w {
			if w[j] != c[j] {
				t.Fatalf("zero-run text %d (n=%d): differs from the reference at %d", i, n, j)
			}
		}
		checked++
	}
	if declined > 0 {
		t.Fatalf("%d of the zero-run texts were declined", declined)
	}
	t.Logf("zero-run texts: %d checked, %d declined", checked, declined)
}
