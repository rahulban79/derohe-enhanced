//go:build darwin && arm64 && cgo

package dsac

import (
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"github.com/deroproject/derohe/cmd/dero-miner/dsa"
)

// Round 30 (rft §8 L-C2, §7 B237): the branch-free two-list merge (dsa_merge_variant 1) is bit-exact against the r29
// merge (variant 0) and against the Go twin, on every existing input set (the 652 real stage-1 texts, the synthetic
// and zero-run texts) and on a randomized differential set: fresh stage-1 texts of random block inputs plus raw random
// texts over small alphabets (2-8 symbols: many four-byte key collisions, i.e. the two-list path the variant changes).
// DSAC_R30_N sets the fresh count (default 1,500; the quiet-window runner uses 20,000). A suffix array is unique, so
// any difference is a bug in the variant.
func TestR30MergeVariantBitExact(t *testing.T) {
	defer SetMergeVariant(MergeVariant())
	if SetMergeVariant(1); MergeVariant() != 1 {
		t.Fatal("SetMergeVariant(1) did not take")
	}
	SetMergeVariant(0)
	texts := stage1Texts(t)
	for _, s := range []int64{1, 2, 3} {
		texts = append(texts, synthTexts(s)...)
		texts = append(texts, zeroRunTexts(s)...)
	}
	n := 1500
	if v, err := strconv.Atoi(os.Getenv("DSAC_R30_N")); err == nil && v > 0 {
		n = v
	}
	r := rand.New(rand.NewSource(30112026))
	var fresh [][]byte
	astrobwtv3.SuffixSort = func(text []byte, sa []int32) bool {
		fresh = append(fresh, append([]byte(nil), text...))
		return false
	}
	for i := 0; i < n; i++ {
		astrobwtv3.AstroBWTv3(freshInput(r, i))
	}
	astrobwtv3.SuffixSort = nil
	texts = append(texts, fresh...)
	for i := 0; i < 400; i++ { // raw small-alphabet texts, lengths across the packing's range
		L := 1 + r.Intn(70000)
		k := 2 + r.Intn(7)
		b := make([]byte, L)
		for j := range b {
			b[j] = byte(r.Intn(k))
		}
		texts = append(texts, b)
	}
	sa0, sa1 := make([]int32, maxLen), make([]int32, maxLen)
	ref := make([]int32, maxLen)
	var both, declined, twin int
	for i, txt := range texts {
		SetMergeVariant(0)
		ok0 := SuffixArray(txt, sa0)
		SetMergeVariant(1)
		ok1 := SuffixArray(txt, sa1)
		SetMergeVariant(0)
		if ok0 != ok1 {
			t.Fatalf("text %d (len %d): variant 0 ok=%v, variant 1 ok=%v", i, len(txt), ok0, ok1)
		}
		if !ok0 {
			declined++
			continue
		}
		both++
		for j := range txt {
			if sa0[j] != sa1[j] {
				t.Fatalf("text %d (len %d): the variants differ at %d (%d vs %d)", i, len(txt), j, sa0[j], sa1[j])
			}
		}
		if dsa.SuffixArray(txt, ref[:len(txt)]) {
			twin++
			for j := range txt {
				if ref[j] != sa1[j] {
					t.Fatalf("text %d (len %d): variant 1 differs from the Go twin at %d", i, len(txt), j)
				}
			}
		} else if !dsa.Verify(txt, sa1[:len(txt)]) {
			t.Fatalf("text %d (len %d): variant 1 fails dsa.Verify", i, len(txt))
		}
	}
	if both < len(texts)*9/10 {
		t.Fatalf("only %d of %d texts sorted (declined %d): the differential is vacuous", both, len(texts), declined)
	}
	t.Logf("%d texts bit-exact across the merge variants (%d declined by both, %d also checked against the Go twin)", both, declined, twin)
}
