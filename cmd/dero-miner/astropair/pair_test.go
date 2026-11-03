package astropair

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
)

// corpus returns >= 600 inputs: sequential miner nonces, random blobs, and edge inputs.
func corpus() [][]byte {
	var in [][]byte
	r := rand.New(rand.NewSource(16))
	var work [48]byte // shaped like a miniblock work blob: version 1, random middle, nonce at 43..46, tid at 47
	work[0] = 1
	r.Read(work[1:43])
	for i := uint32(0); i < 260; i++ {
		w := work
		binary.BigEndian.PutUint32(w[43:], i)
		w[47] = byte(i % 20)
		in = append(in, w[:])
	}
	for i := 0; i < 320; i++ {
		b := make([]byte, 48)
		r.Read(b)
		in = append(in, b)
	}
	for _, v := range []byte{0x00, 0xff, 0x55, 0xaa, 0x01, 0x80} {
		in = append(in, bytes.Repeat([]byte{v}, 48))
	}
	for _, n := range []int{0, 1, 2, 31, 32, 33, 47, 49, 55, 56, 63, 64, 65, 100, 128, 255, 256, 1000} {
		b := make([]byte, n)
		r.Read(b)
		in = append(in, b)
	}
	in = append(in, []byte(nil))
	return in
}

func reference(t testing.TB, in [][]byte) [][32]byte {
	if astrobwtv3.SuffixSort != nil {
		t.Fatal("astrobwtv3.SuffixSort must be nil for the reference")
	}
	ref := make([][32]byte, len(in))
	for i := range in {
		ref[i] = astrobwtv3.AstroBWTv3(in[i])
	}
	return ref
}

// stageLen returns data_len for an input (via the generated stage).
func stageLen(in []byte, s *Scratch) uint32 { return stage1(in, &s.a) }

func TestBitExact(t *testing.T) {
	in := corpus()
	if len(in) < 600 {
		t.Fatalf("corpus has %d inputs", len(in))
	}
	ref := reference(t, in)
	s := NewScratch()
	lens := make([]uint32, len(in))
	for i := range in {
		lens[i] = stageLen(in[i], s)
	}
	defer func(f func([]byte, []int32) bool) { SuffixSort = f }(SuffixSort)

	var declines uint64
	sorters := map[string]func([]byte, []int32) bool{
		"dsa": dsa.SuffixArray,
		"nil": nil,
		// declines every other call, so pairs hit all four (sorted A?, sorted B?) combinations
		"alternate": func(text []byte, sa []int32) bool {
			if atomic.AddUint64(&declines, 1)%3 == 0 {
				return false
			}
			return dsa.SuffixArray(text, sa)
		},
	}
	for name, f := range sorters {
		SuffixSort = f
		var pairs, diffLen, aLonger, bLonger, twoBlockTail, equalLen int
		check := func(i, j int) {
			ha, hb, ok := Hash2(in[i], in[j], s)
			if !ok || ha != ref[i] || hb != ref[j] {
				t.Fatalf("%s: pair (%d,%d) lens (%d,%d): ok=%v\n got %x %x\nwant %x %x", name, i, j, lens[i], lens[j], ok, ha, hb, ref[i], ref[j])
			}
			pairs++
			switch {
			case lens[i] > lens[j]:
				aLonger++
				diffLen++
			case lens[i] < lens[j]:
				bLonger++
				diffLen++
			default:
				equalLen++
			}
			if (lens[i]*4)%64 >= 56 || (lens[j]*4)%64 >= 56 {
				twoBlockTail++
			}
		}
		for i := 0; i+1 < len(in); i++ { // neighbours: sequential nonces pair with their successor
			check(i, i+1)
		}
		r := rand.New(rand.NewSource(7))
		for k := 0; k < 300; k++ { // random partners
			check(r.Intn(len(in)), r.Intn(len(in)))
		}
		for i := range in { // a nonce paired with itself (equal lengths, both lanes identical)
			if i%10 == 0 {
				check(i, i)
			}
		}
		// extreme partners: shortest with longest text, both orders
		lo, hi := 0, 0
		for i := range lens {
			if lens[i] < lens[lo] {
				lo = i
			}
			if lens[i] > lens[hi] {
				hi = i
			}
		}
		check(lo, hi)
		check(hi, lo)
		for i := range in {
			h, ok := Hash1(in[i], s)
			if !ok || h != ref[i] {
				t.Fatalf("%s: Hash1(%d) = %x want %x", name, i, h, ref[i])
			}
		}
		t.Logf("%s: %d inputs, %d pairs bit-exact (A longer %d, B longer %d, equal %d; a lane with a two-block tail %d); data_len %d..%d",
			name, len(in), pairs, aLonger, bLonger, equalLen, twoBlockTail, lens[lo], lens[hi])
		if diffLen == 0 || aLonger == 0 || bLonger == 0 || twoBlockTail == 0 {
			t.Fatalf("%s: coverage hole", name)
		}
	}
}

// TestSHA checks the paired and single SHA-256 against crypto/sha256 on every tail length and unequal lengths.
func TestSHA(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	big := make([]byte, 300000)
	r.Read(big)
	lengths := []int{}
	for n := 0; n <= 200; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths, 4095, 4096, 4097, 263172, 283644, 299999, 300000)
	for _, la := range lengths {
		a := big[:la]
		if got := sum1(a); got != sha256.Sum256(a) {
			t.Fatalf("sum1 len %d", la)
		}
		for _, lb := range []int{0, 1, 55, 56, 63, 64, 119, 120, 128, la, la + 1, 4096, 283644} {
			if lb > len(big) {
				lb = len(big)
			}
			b := big[len(big)-lb:]
			var ha, hb [32]byte
			sum2(a, b, &ha, &hb)
			if ha != sha256.Sum256(a) || hb != sha256.Sum256(b) {
				t.Fatalf("sum2 lens (%d,%d)", la, lb)
			}
		}
	}
}

// TestPanicProducesNoHash: a panic in either lane (stage, sort) returns ok=false and FailHash for BOTH nonces,
// counts once, and leaves the scratch usable.
func TestPanicProducesNoHash(t *testing.T) {
	in := corpus()[:4]
	ref := reference(t, in)
	s := NewScratch()
	defer func(f func([]byte, []int32) bool) { SuffixSort = f; testHook = nil }(SuffixSort)
	SuffixSort = dsa.SuffixArray

	cases := []struct {
		name string
		hook func(int)
		sort func([]byte, []int32) bool
	}{
		{"lane A after stage", func(l int) {
			if l == 0 {
				panic("injected A")
			}
		}, dsa.SuffixArray},
		{"lane B after stage", func(l int) {
			if l == 1 {
				panic("injected B")
			}
		}, dsa.SuffixArray},
		{"sorter on the second call", nil, func() func([]byte, []int32) bool {
			n := 0
			return func(text []byte, sa []int32) bool {
				if n++; n == 2 {
					var z []int32
					_ = z[len(text)] // index out of range
				}
				return dsa.SuffixArray(text, sa)
			}
		}()},
	}
	for _, c := range cases {
		testHook, SuffixSort = c.hook, c.sort
		before := atomic.LoadUint64(&RecoveredPanics)
		ha, hb, ok := Hash2(in[0], in[1], s)
		if ok || ha != FailHash || hb != FailHash {
			t.Fatalf("%s: ok=%v ha=%x hb=%x", c.name, ok, ha, hb)
		}
		if ha == ref[0] || hb == ref[1] {
			t.Fatalf("%s: a real hash escaped", c.name)
		}
		if got := atomic.LoadUint64(&RecoveredPanics) - before; got != 1 {
			t.Fatalf("%s: RecoveredPanics +%d", c.name, got)
		}
		testHook, SuffixSort = nil, dsa.SuffixArray
		ha, hb, ok = Hash2(in[2], in[3], s)
		if !ok || ha != ref[2] || hb != ref[3] {
			t.Fatalf("%s: the next pair after the panic is wrong", c.name)
		}
	}
}

// TestStageIsCurrent: stage_gen.go is exactly what the generator writes from this tree's pow.go.
func TestStageIsCurrent(t *testing.T) {
	pow, err := os.ReadFile("../../../astrobwt/astrobwtv3/pow.go")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(string(pow))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile("stage_gen.go")
	if string(got) != want {
		t.Fatal("stage_gen.go is stale: run go generate in cmd/dero-miner/astropair")
	}
	// gen_stage.go carries a copy of Generate; it must match stagegen_lib.go
	lib, _ := os.ReadFile("stagegen_lib.go")
	gen, _ := os.ReadFile("gen_stage.go")
	body := string(lib)[strings.Index(string(lib), "const ("):]
	if !strings.Contains(string(gen), body) {
		t.Fatal("gen_stage.go's copy of the generator differs from stagegen_lib.go")
	}
}

// TestAsmIsCurrent: sha_arm64.s is exactly what gen_sha.go writes from this toolchain's GOROOT file.
func TestAsmIsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go tool")
	}
	out := filepath.Join(t.TempDir(), "sha.s")
	cmd := exec.Command("go", "run", "gen_sha.go")
	cmd.Env = append(os.Environ(), "GEN_SHA_OUT="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	want, _ := os.ReadFile(out)
	got, _ := os.ReadFile("sha_arm64.s")
	if !bytes.Equal(got, want) {
		t.Fatal("sha_arm64.s differs from gen_sha.go output (toolchain file changed?)")
	}
}
