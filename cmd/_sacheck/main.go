package main

// Prove the SA-uniqueness approach: run a simple prefix-doubling suffix array on the GPU's
// pre-SAIS data (gpu_loop_<i>.bin, validated bit-exact in stage 3b), take sha256(sa as int32 LE),
// and compare to astrobwtv3.AstroBWTv3(input). If equal for all KA vectors, prefix-doubling
// produces the byte-identical SA that the recursive SAIS does — so we can port THIS to the GPU
// instead of the intricate recursive induced-sorting SAIS.
import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

// prefix-doubling suffix array of text[0:n], sentinel convention (suffix that ends first sorts first).
func suffixArray(text []byte) []int32 {
	n := len(text)
	sa := make([]int32, n)
	rank := make([]int32, n)
	tmp := make([]int32, n)
	for i := 0; i < n; i++ {
		sa[i] = int32(i)
		rank[i] = int32(text[i])
	}
	key2 := func(a int32, k int) int32 {
		if int(a)+k < n {
			return rank[int(a)+k]
		}
		return -1 // sentinel: shorter suffix sorts first
	}
	rounds := 0
	for k := 1; ; k *= 2 {
		rounds++
		less := func(a, b int32) bool {
			if rank[a] != rank[b] {
				return rank[a] < rank[b]
			}
			return key2(a, k) < key2(b, k)
		}
		sort.Slice(sa, func(i, j int) bool { return less(sa[i], sa[j]) })
		tmp[sa[0]] = 0
		for i := 1; i < n; i++ {
			tmp[sa[i]] = tmp[sa[i-1]]
			if less(sa[i-1], sa[i]) {
				tmp[sa[i]]++
			}
		}
		copy(rank, tmp)
		if int(rank[sa[n-1]]) == n-1 || k > n {
			break
		}
	}
	lastRounds = rounds
	return sa
}

var lastRounds int

func main() {
	inputs := []struct {
		label string
		in    []byte
	}{
		{"a", []byte("a")}, {"ab", []byte("ab")}, {"abc", []byte("abc")}, {"abcd", []byte("abcd")},
		{"abcde", []byte("abcde")}, {"abcdef", []byte("abcdef")}, {"abcdefg", []byte("abcdefg")},
		{"abcdefgh", []byte("abcdefgh")}, {"abcdefghi", []byte("abcdefghi")}, {"abcdefghij", []byte("abcdefghij")},
		{"48x00", make([]byte, 48)},
	}
	all := true
	fmt.Printf("%-12s %-8s %-18s %-18s %s\n", "input", "data_len", "AstroBWTv3", "prefixdbl_SA+sha", "match")
	for i, tc := range inputs {
		raw, err := os.ReadFile(fmt.Sprintf("gpu-miner-poc/gpu_loop_%d.bin", i))
		if err != nil {
			fmt.Println(err)
			all = false
			continue
		}
		dlen := binary.LittleEndian.Uint32(raw[:4])
		data := raw[4 : 4+int(dlen)]
		sa := suffixArray(data)
		sb := make([]byte, int(dlen)*4)
		for j, v := range sa {
			binary.LittleEndian.PutUint32(sb[j*4:], uint32(v))
		}
		mine := sha256.Sum256(sb)
		want := astrobwtv3.AstroBWTv3(tc.in)
		ok := mine == want
		if !ok {
			all = false
		}
		fmt.Printf("%-12s dlen=%-6d rounds=%-3d %v\n", tc.label, dlen, lastRounds, map[bool]string{true:"MATCH",false:"MISMATCH"}[ok])
	}
	fmt.Printf("\n=== SA-UNIQUENESS PROOF: %s ===\n", map[bool]string{true: "prefix-doubling == SAIS (port THIS to GPU)", false: "MISMATCH — convention differs"}[all])
	if !all {
		os.Exit(1)
	}
}
