// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/transaction"
)

// FuzzCheck (Round 23): for any bytes that decode, Check must not panic, and whatever it admits must be a tx whose
// canonical bytes decode back to the same txid and re-serialize identically (the property relayed bytes need).
func FuzzCheck(f *testing.F) {
	s := synth{}
	f.Add(s.bytes())
	q := new(bn256.G1).ScalarBaseMult(big.NewInt(idxC0)).EncodeCompressed()
	q[32] = 0x7f // undefined flag byte (alias)
	f.Add((&synth{override: map[int][]byte{idxC0: q}}).bytes())
	f.Add((&synth{override: map[int][]byte{idxC0: noncanonicalX(&testing.T{})}}).bytes())
	f.Fuzz(func(t *testing.T, raw []byte) { checkAdmitProperty(t, raw) })
}

// checkAdmitProperty: no panic, and whatever Check admits round-trips (shared by FuzzCheck and the sweep below).
func checkAdmitProperty(t *testing.T, raw []byte) {
	var tx transaction.Transaction
	if decode(&tx, raw) != nil {
		return
	}
	canonical, err := Check(raw, &tx)
	if err != nil {
		return
	}
	ser, err := serialize(&tx)
	if err != nil {
		t.Fatalf("admitted a tx that cannot be serialized: %v", err)
	}
	if canonical && !bytes.Equal(ser, raw) {
		t.Fatal("canonical=true but raw != Serialize")
	}
	var back transaction.Transaction
	if err := decode(&back, ser); err != nil {
		t.Fatalf("admitted a tx whose canonical bytes do not decode: %v", err)
	}
	if back.GetHash() != tx.GetHash() {
		t.Fatal("admitted a tx whose canonical bytes decode to another txid")
	}
	if ser2, err := serialize(&back); err != nil || !bytes.Equal(ser2, ser) {
		t.Fatal("admitted a tx whose canonical bytes do not re-serialize identically")
	}
}

// TestR23SingleByteSweep runs the admission property on every single-byte mutation of the synthetic tx (1701 bytes
// x 7 values). Deterministic complement to FuzzCheck, whose engine throughput on this package was ~0.3 exec/s on
// the loaded box (the exec itself was never the slow part: a watchdog on each exec never fired).
func TestR23SingleByteSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("sweep")
	}
	base := (&synth{}).bytes()
	step := 1
	if raceEnabled {
		step = 7 // keep -race runs short
	}
	n := 0
	for pos := 0; pos < len(base); pos += step {
		for _, v := range []byte{0x00, 0xff, 0x7f, 0x80, 0x40, 0x08, 0x10} {
			b := append([]byte{}, base...)
			b[pos] = v
			checkAdmitProperty(t, b)
			n++
		}
	}
	t.Logf("%d mutated inputs checked", n)
}
