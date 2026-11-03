package main

// Ground-truth reference for GPU Milestone-1 stage 2: computes step_3[256] after
// the EXACT AstroBWTv3 pre-loop sequence (sha256 -> salsa20 -> rc4) using the SAME
// libraries pow.go uses (pow.go:52-63). Prints a sha256 fingerprint of step_3 +
// first 8 bytes, per KA input, for byte-exact comparison against the GPU kernel.
import (
	"crypto/sha256"
	"fmt"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
	"golang.org/x/crypto/salsa20/salsa"
)

func step3(input []byte) [256]byte {
	var step_3 [256]byte
	var counter [16]byte
	key := sha256.Sum256(input) // [32]byte  (pow.go:52)
	salsa.XORKeyStream(step_3[:], step_3[:], &counter, &key)
	rc4s := astrobwtv3.NewCipher(step_3[:]) // key = salsa keystream (pow.go:62)
	rc4s.XORKeyStream(step_3[:], step_3[:])
	return step_3
}

func main() {
	type tc struct {
		label string
		in    []byte
	}
	cases := []tc{
		{"a", []byte("a")}, {"ab", []byte("ab")}, {"abc", []byte("abc")},
		{"abcd", []byte("abcd")}, {"abcde", []byte("abcde")}, {"hello", []byte("hello")},
		{"48x00", make([]byte, 48)},
	}
	fmt.Println("input          fp=sha256(step_3)                                                first8")
	for _, c := range cases {
		s := step3(c.in)
		fp := sha256.Sum256(s[:])
		fmt.Printf("%-14s %x  %x\n", c.label, fp, s[:8])
	}
}
