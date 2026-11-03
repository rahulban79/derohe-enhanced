// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"bytes"
	"testing"
)

// EncryptWithKey must not write into the caller's plaintext, even when the slice has spare capacity (r22)
func TestEncryptWithKeyLeavesPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	backing := make([]byte, 32, 128) // spare capacity: Seal(Data[:0], ...) would reuse it
	for i := range backing {
		backing[i] = byte(i)
	}
	want := append([]byte(nil), backing...)
	out, err := EncryptWithKey(key, backing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backing, want) {
		t.Fatal("EncryptWithKey overwrote the plaintext buffer")
	}
	if len(out) != 32+16+12 {
		t.Fatalf("ciphertext length %d, want %d", len(out), 32+16+12)
	}
	back, err := DecryptWithKey(key, out)
	if err != nil || !bytes.Equal(back, want) {
		t.Fatalf("round trip failed: %v", err)
	}
	out2, _ := EncryptWithKey(key, want)
	if bytes.Equal(out, out2) {
		t.Fatal("two encryptions produced the same ciphertext (nonce reuse)")
	}
}
