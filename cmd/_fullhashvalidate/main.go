package main

// Stage-3c validation: compare the GPU's COMPLETE 32-byte hash (gpu_hash_<i>.bin) to
// astrobwtv3.AstroBWTv3(input). All match => the whole AstroBWTv3 hash runs bit-exact on GPU.
import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

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
	fmt.Printf("%-12s %-20s %-20s %s\n", "input", "cpu AstroBWTv3", "gpu full_hash", "match")
	for i, tc := range inputs {
		raw, err := os.ReadFile(fmt.Sprintf("gpu-miner-poc/gpu_hash_%d.bin", i))
		if err != nil || len(raw) != 32 {
			fmt.Printf("%-12s  MISSING/short %v\n", tc.label, err)
			all = false
			continue
		}
		want := astrobwtv3.AstroBWTv3(tc.in)
		ok := hex.EncodeToString(want[:]) == hex.EncodeToString(raw)
		if !ok {
			all = false
		}
		fmt.Printf("%-12s %x %x %v\n", tc.label, want[:10], raw[:10], map[bool]string{true: "MATCH", false: "MISMATCH"}[ok])
	}
	fmt.Printf("\n=== STAGE-3c RESULT: %s ===\n", map[bool]string{true: "COMPLETE AstroBWTv3 HASH RUNS BIT-EXACT ON GPU", false: "MISMATCH"}[all])
	if !all {
		os.Exit(1)
	}
}
