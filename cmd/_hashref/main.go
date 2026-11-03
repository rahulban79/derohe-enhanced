package main

// Ground-truth for GPU stage-3a: the 3 conditional loop hashes (pow.go:2407-2419)
// computed with the EXACT libraries pow.go uses. Test inputs exercise every length
// boundary (the >=32 block path + the 8/4/1-byte tails). Prints len,fnv1a,xxhash,siphash.
import (
	"fmt"

	"github.com/cespare/xxhash"
	"github.com/dchest/siphash"
	"github.com/segmentio/fasthash/fnv1a"
)

func testdata(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte((i*131 + n*17) & 0xff)
	}
	return b
}

func main() {
	const k0 = uint64(0x0123456789abcdef)
	const k1 = uint64(0xfedcba9876543210)
	lens := []int{0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 33, 64, 100, 200, 255}
	fmt.Printf("k0=%016x k1=%016x\n", k0, k1)
	fmt.Printf("%-5s %-18s %-18s %-18s\n", "len", "fnv1a64", "xxhash64", "siphash24")
	for _, n := range lens {
		d := testdata(n)
		fmt.Printf("%-5d %016x %016x %016x\n", n, fnv1a.HashBytes64(d), xxhash.Sum64(d), siphash.Hash(k0, k1, d))
	}
}
