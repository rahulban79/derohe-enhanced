package main

// Validate the GPU linear SA-IS: gpu_sais_<i>.bin (GPU SA-IS -> final SHA) vs AstroBWTv3(input).
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
	for i, tc := range inputs {
		raw, err := os.ReadFile(fmt.Sprintf("gpu-miner-poc/gpu_sais_%d.bin", i))
		if err != nil || len(raw) != 32 {
			fmt.Printf("%-12s MISSING\n", tc.label)
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
	fmt.Printf("\n=== GPU LINEAR SA-IS: %s ===\n", map[bool]string{true: "BIT-EXACT — full AstroBWTv3 on GPU via fast SA-IS", false: "MISMATCH (debug next)"}[all])
	if !all {
		os.Exit(1)
	}
}
