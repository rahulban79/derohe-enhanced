// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package dvm

import (
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Round 23 measurement: the DVM hash builtins charge a flat 25000 compute gas whatever the input length (strings
// reach 1 MiB, dvm.go string ADD), and one call has 10,000,000 compute gas (sc.go). These give the per-MiB cost.
var mib = make([]byte, 1<<20)

func BenchmarkR23Sha256MiB(b *testing.B) {
	b.SetBytes(1 << 20)
	for i := 0; i < b.N; i++ {
		sha256.Sum256(mib)
	}
}
func BenchmarkR23Sha3MiB(b *testing.B) {
	b.SetBytes(1 << 20)
	for i := 0; i < b.N; i++ {
		sha3.Sum256(mib)
	}
}
func BenchmarkR23KeccakMiB(b *testing.B) {
	b.SetBytes(1 << 20)
	for i := 0; i < b.N; i++ {
		h := sha3.NewLegacyKeccak256()
		h.Write(mib)
		h.Sum(nil)
	}
}
