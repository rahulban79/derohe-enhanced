package main

// Prove: sais_32 on int32-promoted bytes (textMax=256) == sais_8_32 on bytes, so the GPU port
// only needs the int32 SA-IS variant. Compare Sais32Hash(GPU 3b data) to AstroBWTv3(input).
import (
	"encoding/binary"
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
		raw, err := os.ReadFile(fmt.Sprintf("gpu-miner-poc/gpu_loop_%d.bin", i))
		if err != nil {
			fmt.Println(err)
			all = false
			continue
		}
		dlen := binary.LittleEndian.Uint32(raw[:4])
		data := raw[4 : 4+int(dlen)]
		want := astrobwtv3.AstroBWTv3(tc.in)
		got := astrobwtv3.Sais32Hash(data, dlen)
		ok := want == got
		if !ok {
			all = false
		}
		fmt.Printf("%-12s %x %x %v\n", tc.label, want[:8], got[:8], map[bool]string{true: "MATCH", false: "MISMATCH"}[ok])
	}
	fmt.Printf("\n=== sais_32-on-promoted-bytes == sais_8_32 : %s ===\n", map[bool]string{true: "YES — port ONLY the int32 SA-IS variant", false: "NO"}[all])
	if !all {
		os.Exit(1)
	}
}
