// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package mnemonics

import (
	"math/big"
	"testing"
)

// FuzzWordsToKey (Round 23): seed parsing must never panic, and an accepted seed must map back to itself.
func FuzzWordsToKey(f *testing.F) {
	f.Add(Key_To_Words(big.NewInt(1), "English"))
	f.Add(Key_To_Words(new(big.Int).Lsh(big.NewInt(1), 255), "Japanese"))
	f.Add(Key_To_Words(big.NewInt(0x1234567), "Russian"))
	f.Add("abbey abbey")
	f.Fuzz(func(t *testing.T, words string) {
		lang, key, err := Words_To_Key(words)
		if err != nil {
			return
		}
		if key == nil || key.BitLen() > 256 {
			t.Fatalf("accepted seed gives an out-of-range key %v", key)
		}
		_, key2, err := Words_To_Key(Key_To_Words(key, lang))
		if err != nil || key2.Cmp(key) != 0 {
			t.Fatalf("accepted seed does not round-trip: %v", err)
		}
	})
}
