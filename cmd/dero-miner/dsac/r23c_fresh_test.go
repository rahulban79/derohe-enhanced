//go:build darwin && arm64 && cgo

package dsac

// derohe r23c (sortfuse): large-sample bit-exactness for descriptor.c changes. freshInputs is the
// TestBitExactFresh2048 recipe (miniblock-shaped 48-byte inputs, split-mode marker byte) with a caller seed, so the
// texts are real AstroBWTv3 stage-1 texts produced by the tree's own code and none of them is in the 652 corpus.

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
)

func freshInput(r *rand.Rand, i int) []byte {
	var b [48]byte
	r.Read(b[:])
	b[0] = b[0]&0xf0 | 1
	binary.BigEndian.PutUint32(b[43:47], uint32(i))
	b[47] = 0xfe
	return b[:]
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

// DSAC_DUMP_FRESH=<file> [DSAC_DUMP_N=2048] [DSAC_SEED=23112026]: writes N fresh stage-1 texts (u32 length + bytes)
// for the standalone C bench harness.
func TestDumpFresh(t *testing.T) {
	p := os.Getenv("DSAC_DUMP_FRESH")
	if p == "" {
		t.Skip("set DSAC_DUMP_FRESH")
	}
	N := envInt("DSAC_DUMP_N", 2048)
	r := rand.New(rand.NewSource(int64(envInt("DSAC_SEED", 23112026))))
	var buf bytes.Buffer
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		binary.Write(&buf, binary.LittleEndian, uint32(len(text)))
		buf.Write(text)
		return SuffixArray(text, sa)
	}
	defer func() { astrobwtv3.SuffixSort = nil }()
	for i := 0; i < N; i++ {
		astrobwtv3.AstroBWTv3(freshInput(r, i))
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// DSAC_VERIFY_N=<count> [DSAC_SEED]: every fresh stage-1 text is sorted by the C sort and by the Go twin (dsa, the
// pre-r23c algorithm, itself proven against SA-IS) and the two suffix arrays must be identical word for word; every
// 64th one is also checked by dsa.Verify. Runs GOMAXPROCS/2 workers.
func TestBitExactFreshN(t *testing.T) {
	N := envInt("DSAC_VERIFY_N", 0)
	if N == 0 {
		t.Skip("set DSAC_VERIFY_N")
	}
	seed := int64(envInt("DSAC_SEED", 23112026))
	workers := envInt("DSAC_WORKERS", runtime.GOMAXPROCS(0)/2)
	var next, used, declined, verified int64
	var bad int64 = -1
	var mu sync.Mutex
	var wg sync.WaitGroup
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		ok := SuffixArray(text, sa)
		if !ok {
			atomic.AddInt64(&declined, 1)
			return false
		}
		ref := make([]int32, len(text))
		if !dsa.SuffixArray(text, ref) {
			// The Go twin declined: fall back to the independent checker.
			if !dsa.Verify(text, sa[:len(text)]) {
				atomic.StoreInt64(&bad, int64(len(text)))
			}
			atomic.AddInt64(&verified, 1)
		} else {
			for j := range ref {
				if ref[j] != sa[j] {
					atomic.StoreInt64(&bad, int64(j))
					break
				}
			}
		}
		u := atomic.AddInt64(&used, 1)
		if u%64 == 0 {
			if !dsa.Verify(text, sa[:len(text)]) {
				atomic.StoreInt64(&bad, int64(len(text)))
			}
			atomic.AddInt64(&verified, 1)
		}
		return true
	}
	defer func() { astrobwtv3.SuffixSort = nil }()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&next, 1) - 1
				if i >= int64(N) || atomic.LoadInt64(&bad) >= 0 {
					return
				}
				// Per-index seed so the texts do not depend on worker scheduling.
				r := rand.New(rand.NewSource(seed*1000003 + i))
				astrobwtv3.AstroBWTv3(freshInput(r, int(i)))
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if bad >= 0 {
		t.Fatalf("suffix array mismatch (index/len %d)", bad)
	}
	if used < int64(N)-int64(N)/64 {
		t.Fatalf("C sort ran on only %d of %d (declined %d)", used, N, declined)
	}
	t.Logf("%d fresh texts: C used %d, declined %d, identical to Go dsa; %d also dsa.Verify'd", N, used, declined, verified)
}

// derohe r23c: the paired singleton write (two groups per iteration, sixteen lanes each, the second starting at
// out + la) must never write past sa[n) and must agree with the Go twin wherever the pair/single split falls near
// the end of the text. Real stage-1 texts truncated by 0..47 bytes move the last groups across the
// `out + la + 16 <= n` boundary; a sentinel tail catches any overhang.
func TestR23cPairTailBoundary(t *testing.T) {
	texts := stage1Texts(t)[:24]
	checked := 0
	for i, full := range texts {
		for cut := 0; cut < 48; cut++ {
			txt := full[:len(full)-cut]
			n := len(txt)
			c := make([]int32, n+64)
			for j := range c {
				c[j] = -777
			}
			if !SuffixArray(txt, c) {
				continue
			}
			for j := n; j < len(c); j++ {
				if c[j] != -777 {
					t.Fatalf("text %d cut %d: wrote sa[%d] past n=%d", i, cut, j, n)
				}
			}
			g := make([]int32, n)
			if !dsa.SuffixArray(txt, g) {
				if !dsa.Verify(txt, c[:n]) {
					t.Fatalf("text %d cut %d: fails Verify", i, cut)
				}
				continue
			}
			for j := 0; j < n; j++ {
				if c[j] != g[j] {
					t.Fatalf("text %d cut %d: differs from Go dsa at %d", i, cut, j)
				}
			}
			checked++
		}
	}
	if checked < 24*48*9/10 {
		t.Fatalf("only %d truncated texts checked", checked)
	}
	t.Logf("%d truncated stage-1 texts identical to Go dsa, no write past n", checked)
}
