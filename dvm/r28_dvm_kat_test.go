// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package dvm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// Round 28 (dvm-blockchain): known-answer tests for the dvm/ pieces the in-package tests left at 0 % (R28 sweep:
// SC_META_DATA's pre-HF2 codec, GetBalanceKey / SC_Asset_Key / the balance branch of DataKey.MarshalBinaryPanic,
// TX_Storage.RawLoad) or partly covered (RANDOM / RND.Random_MAX, checkargscount). dvm/ is consensus code: nothing
// here changes it; footguns are pinned as they are.

// SC_META_DATA has two codecs. The chain writes the pre-HF2 one (MarshalBinary) below HF2_HEIGHT and at every SC
// install (blockchain/transaction_execute.go process_transaction_sc), and the "Good" one at the block commit from
// HF2 on (blockchain/blockchain.go). The pre-HF2 MarshalBinary copies DataHash into buf[33:], an empty slice: the
// data-tree hash is NEVER serialised (bytes 1..32 are always zero), and UnmarshalBinary reads it back from buf[33:]
// as well. So before HF2 the meta tree did not commit to any SC's data tree, whatever its comment says. Pinned.
func TestR28SCMetaCodecsKAT(t *testing.T) {
	var h crypto.Hash
	for i := range h {
		h[i] = byte(i + 1)
	}
	meta := SC_META_DATA{Type: 1, DataHash: h}

	old := meta.MarshalBinary()
	if len(old) != 33 || old[0] != 1 || !bytes.Equal(old[1:], make([]byte, 32)) {
		t.Fatalf("pre-HF2 codec: %x, want 01 followed by 32 zero bytes (DataHash never serialised; premise changed)", old)
	}
	var back SC_META_DATA
	if err := back.UnmarshalBinary(old); err != nil || back.Type != 1 || !back.DataHash.IsZero() {
		t.Fatalf("pre-HF2 decode: %+v %v, want type 1 and a zero DataHash", back, err)
	}
	// even a buffer that carries a hash decodes to zero with the pre-HF2 codec
	good := meta.MarshalBinaryGood()
	if len(good) != 33 || good[0] != 1 || !bytes.Equal(good[1:], h[:]) {
		t.Fatalf("Good codec: %x, want 01 || DataHash", good)
	}
	if err := back.UnmarshalBinary(good); err != nil || !back.DataHash.IsZero() {
		t.Fatalf("pre-HF2 decode of a Good buffer: %+v %v, want a zero DataHash", back, err)
	}
	var g SC_META_DATA
	if err := g.UnmarshalBinaryGood(good); err != nil || g != meta {
		t.Fatalf("Good round trip: %+v %v, want %+v", g, err, meta)
	}
	for _, n := range []int{0, 32, 34} {
		if back.UnmarshalBinary(make([]byte, n)) == nil || g.UnmarshalBinaryGood(make([]byte, n)) == nil {
			t.Fatalf("a %d-byte meta buffer was accepted", n)
		}
	}
}

// A balance key is the raw 32 asset bytes: GetBalanceKey(scid, asset).MarshalBinaryPanic() == SC_Asset_Key(asset)
// == asset[:], the key LoadSCAssetValue reads and SanityCheckExternalTransfers writes; the SCID is not part of it
// (each SC has its own data tree). A non-string balance key panics.
func TestR28BalanceKeyKAT(t *testing.T) {
	var scid, asset crypto.Hash
	scid[0], asset[31] = 0xaa, 0x55
	k := GetBalanceKey(scid, asset)
	if !k.Balance || k.SCID != scid {
		t.Fatalf("GetBalanceKey: %+v", k)
	}
	if got := k.MarshalBinaryPanic(); !bytes.Equal(got, asset[:]) || !bytes.Equal(SC_Asset_Key(asset), asset[:]) {
		t.Fatalf("balance key %x / asset key %x, want the raw asset %x", got, SC_Asset_Key(asset), asset[:])
	}
	if ser, err := k.MarshalBinary(); err != nil || bytes.Equal(ser, asset[:]) {
		t.Fatalf("DataKey.MarshalBinary ignores Balance and encodes the Variable (%x, %v)", ser, err)
	}
	func() {
		defer func() {
			if r := recover(); r == nil || !strings.Contains(r.(string), "balance keys can only be string") {
				t.Fatalf("a Uint64 balance key: recover %v", r)
			}
		}()
		DataKey{Balance: true, Key: Variable{Type: Uint64, ValueUint64: 1}}.MarshalBinaryPanic()
	}()
	// a plain key is the Variable's encoding
	plain := DataKey{Key: Variable{Type: String, ValueString: "C"}}.MarshalBinaryPanic()
	if !bytes.Equal(plain, SC_Code_Key(scid)) {
		t.Fatalf("SC_Code_Key %x is not the String key \"C\" %x", SC_Code_Key(scid), plain)
	}
}

// RawLoad reads the tx-local raw keys first, then the disk loader; with no disk loader a miss is a miss.
func TestR28RawLoadKAT(t *testing.T) {
	s := Initialize_TX_store()
	if v, found := s.RawLoad([]byte("k")); found || v != nil {
		t.Fatalf("empty store, no loader: %x %v", v, found)
	}
	disk := map[string][]byte{"k": []byte("disk"), "d": []byte("onlydisk")}
	calls := 0
	s.DiskLoaderRaw = func(key []byte) ([]byte, bool) { calls++; v, ok := disk[string(key)]; return v, ok }
	s.RawKeys["k"] = []byte("tx")
	if v, found := s.RawLoad([]byte("k")); !found || string(v) != "tx" || calls != 0 {
		t.Fatalf("tx-local key: %q %v (disk calls %d), want the tx value without a disk read", v, found, calls)
	}
	if v, found := s.RawLoad([]byte("d")); !found || string(v) != "onlydisk" || calls != 1 {
		t.Fatalf("disk key: %q %v (disk calls %d)", v, found, calls)
	}
	if _, found := s.RawLoad([]byte("none")); found {
		t.Fatal("a key in neither place was found")
	}
}

const r28_random_sc = `
Function Initialize() Uint64
10 RETURN 0
End Function

Function Rand() Uint64
10 STORE("r1", RANDOM())
20 STORE("r2", RANDOM())
30 STORE("m1", RANDOM(1))
40 STORE("m10", RANDOM(10))
50 RETURN 0
End Function

Function RandBad(which Uint64) Uint64
10 IF which == 1 THEN GOTO 100
20 IF which == 2 THEN GOTO 200
30 IF which == 3 THEN GOTO 300
40 RETURN 0
100 STORE("z", RANDOM(0))
110 RETURN 0
200 STORE("z", RANDOM(1, 2))
210 RETURN 0
300 STORE("z", RANDOM("x"))
310 RETURN 0
End Function

Function Args() Uint64
10 STORE("z", SCID(1))
20 RETURN 0
End Function
`

// RANDOM() / RANDOM(n): one HSalsa20 stream per invocation keyed by Keccak256(SCID, BLID, TXID), position from 1;
// RANDOM(n) is the next stream value mod n. RANDOM(0), two arguments or a String argument fail the call (and with
// it every STORE of the invocation). A builtin called with the wrong argument count fails via checkargscount.
func TestR28RandomKAT(t *testing.T) {
	// the generator itself: same seed, same stream; Random_MAX(n) = next Random() % n; 0 panics
	var a, b, c crypto.Hash
	a[0], b[0], c[0] = 1, 2, 3
	r1, r2 := Initialize_RND(a, b, c), Initialize_RND(a, b, c)
	if r1.Pos != 1 {
		t.Fatalf("stream starts at %d, want 1", r1.Pos)
	}
	x, y := r1.Random(), r1.Random()
	if x == y || r2.Random() != x || r2.Random_MAX(1000) != y%1000 || r2.Pos != 3 {
		t.Fatal("RND: the stream is not a deterministic function of the seed and position")
	}
	if Initialize_RND(c, b, a).Random() == x {
		t.Fatal("RND: swapping SCID and TXID gave the same first value")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Random_MAX(0) did not panic")
			}
		}()
		r1.Random_MAX(0)
	}()

	r := r27_new_sim(t, r28_random_sc)
	r.must("Rand", nil)
	v1, v2 := r.read("r1"), r.read("r2")
	if v1 == nil || v2 == nil || v1 == v2 {
		t.Fatalf("RANDOM(): r1 %v r2 %v, want two different stored values", v1, v2)
	}
	if r.read("m1") != uint64(0) {
		t.Fatalf("RANDOM(1) = %v, want 0", r.read("m1"))
	}
	if m, ok := r.read("m10").(uint64); !ok || m >= 10 {
		t.Fatalf("RANDOM(10) = %v, want < 10", r.read("m10"))
	}
	for which := uint64(1); which <= 3; which++ {
		if err := r.call("RandBad", nil, rpc.Argument{Name: "which", DataType: rpc.DataUint64, Value: which}); err == nil {
			t.Fatalf("RandBad(%d) succeeded", which)
		}
		if r.read("z") != nil {
			t.Fatalf("RandBad(%d) stored z", which)
		}
	}
	if err := r.call("Args", nil); err == nil || r.read("z") != nil {
		t.Fatalf("SCID(1): err %v, want the call to fail (checkargscount)", err)
	}
}

// The Go generator against vectors built by an independent pure-Python implementation (pure Keccak-256 from
// harness/forensics/keccak.py, HSalsa20 from the spec, checked there against the NaCl vector):
// harness/kat/test_dvm_rnd_crossimpl_r28.py writes and checks dvm/testdata/r28_rnd_vectors.json.
func TestR28RNDCrossImpl(t *testing.T) {
	raw, err := os.ReadFile("testdata/r28_rnd_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Cases []struct {
			SCID, BLID, TXID string
			Values           []string
			Max              []struct{ N, Want string }
		}
	}
	if err := json.Unmarshal(raw, &vec); err != nil || len(vec.Cases) == 0 {
		t.Fatalf("vectors: %v (%d cases)", err, len(vec.Cases))
	}
	hash := func(s string) (h crypto.Hash) {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad hash %q", s)
		}
		copy(h[:], b)
		return
	}
	u64 := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for i, c := range vec.Cases {
		r := Initialize_RND(hash(c.SCID), hash(c.BLID), hash(c.TXID))
		for j, w := range c.Values {
			if got := r.Random(); got != u64(w) {
				t.Fatalf("case %d value %d: Go %d, independent implementation %s", i, j, got, w)
			}
		}
		for j, m := range c.Max {
			if got := r.Random_MAX(u64(m.N)); got != u64(m.Want) {
				t.Fatalf("case %d Random_MAX(%s) #%d: Go %d, independent implementation %s", i, m.N, j, got, m.Want)
			}
		}
	}
}
