// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package crypto

import (
	"bytes"
	"testing"
)

// FuzzStatementProofDecode records which proof/statement decoder inputs panic (r22 crypto audit). The decoders are
// consensus code and are not changed; every node caller wraps them in a recover (p2p deserialize_tx, RPC
// handlers). The target fails only on a panic, which is then a documented decoder robustness defect.
func FuzzStatementProofDecode(f *testing.F) {
	f.Add([]byte{1, 4, 0}, uint8(1))
	f.Add(bytes.Repeat([]byte{0}, 400), uint8(2))
	f.Add(bytes.Repeat([]byte{0xff}, 400), uint8(7))
	f.Fuzz(func(t *testing.T, data []byte, length uint8) {
		var s Statement
		s.Deserialize(bytes.NewReader(data))
		var p Proof
		p.Deserialize(bytes.NewReader(data), int(length%8))
		var e ElGamal
		if len(data) == 66 {
			func() {
				defer func() { recover() }() // ElGamal.Deserialize panics by design on undecodable points
				e.Deserialize(data)
			}()
		}
	})
}

// Characterization: Hash/Key UnmarshalText ignore the hex decoder's error and only check the decoded length, so 64
// hex digits followed by ANY garbage are accepted (hex.DecodeString returns the 32 bytes it decoded before the bad
// byte). JSON-RPC parameters typed crypto.Hash (txids, block hashes, SCIDs) therefore accept malformed strings.
// Consensus code: pinned, not changed.
func TestR22HashUnmarshalTextAcceptsTrailingGarbage(t *testing.T) {
	good := bytes.Repeat([]byte("ab"), 32)
	for _, junk := range []string{"z", "zz", "0", "!not-hex-at-all"} {
		var h Hash
		if err := h.UnmarshalText(append(append([]byte{}, good...), junk...)); err != nil {
			t.Fatalf("premise changed: %q suffix now rejected (%v)", junk, err)
		}
		if h.String() != string(good) {
			t.Fatalf("decoded %s", h)
		}
	}
}
