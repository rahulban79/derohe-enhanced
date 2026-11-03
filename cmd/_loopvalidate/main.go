package main

// Stage-3b validation: read the GPU's (data_len, data) from gpu_loop_<i>.bin, finish the hash
// on the CPU via astrobwtv3.FinishHashFromData (real SAIS + final SHA256), and compare to
// astrobwtv3.AstroBWTv3(input). Equal for all inputs => the GPU 256-op loop is byte-correct.
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
	dir := "gpu-miner-poc"
	all := true
	fmt.Printf("%-12s %-8s %-20s %-20s %s\n", "input", "data_len", "cpu_hash(AstroBWTv3)", "gpu_loop->cpu_finish", "match")
	for i, tc := range inputs {
		raw, err := os.ReadFile(fmt.Sprintf("%s/gpu_loop_%d.bin", dir, i))
		if err != nil {
			fmt.Printf("%-12s  MISSING %s\n", tc.label, err)
			all = false
			continue
		}
		dlen := binary.LittleEndian.Uint32(raw[:4])
		data := raw[4:]
		if uint32(len(data)) != dlen {
			fmt.Printf("%-12s  bad file len %d != data_len %d\n", tc.label, len(data), dlen)
			all = false
			continue
		}
		cpu := astrobwtv3.AstroBWTv3(tc.in)                    // ground truth (matches pow_test.go)
		gpu := astrobwtv3.FinishHashFromData(data, dlen)       // GPU loop output -> real SAIS+SHA
		ok := cpu == gpu
		if !ok {
			all = false
		}
		fmt.Printf("%-12s %-8d %x %x %v\n", tc.label, dlen, cpu[:8], gpu[:8], map[bool]string{true: "MATCH", false: "MISMATCH"}[ok])
	}
	fmt.Printf("\n=== STAGE-3b RESULT: %s ===\n", map[bool]string{true: "ALL MATCH — GPU 256-op loop is byte-exact (full pre-SAIS on GPU)", false: "MISMATCH"}[all])
	if !all {
		os.Exit(1)
	}
}
