package dvm

// R31 (dero-rft §7 B289, detector fuzz-coverage findings for ParseSmartContract, Variable.UnmarshalBinary,
// SC_META_DATA.UnmarshalBinary / UnmarshalBinaryGood; B281 class): Go fuzz targets with seed corpora (f.Add). Under
// plain `go test` each runs its seeds as a KAT; `go test -fuzz=FuzzR31... ./dvm/` explores. Tests only: no DVM change.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

var r31_parse_seeds = []string{
	r31_sc, r27_builtins_sc, "",
	"Function Initialize() Uint64\n10 RETURN 0\nEnd Function\n",
	"Function Initialize( Uint64\n10 RETURN 0\n",
	"Function Initialize() Uint64\n10 DIM x as Uint64\n20 LET x = 1 + 2 * 3\n30 RETURN x\nEnd Function\n",
	"Function A() Uint64\n10 RETURN 0\nEnd Function\nFunction A() Uint64\n10 RETURN 0\nEnd Function\n",
	"Function Initialize() Uint64\n20 RETURN 0\n10 RETURN 1\nEnd Function\n",
	"Function Initialize() String\n10 RETURN \"x\"\nEnd Function\n",
}

// the parser on adversarial source (an SC install carries arbitrary code): it returns or errors, never panics, and a
// contract it accepts parses the same way twice (the chain re-parses stored code on every call, ReadSC)
func FuzzR31ParseSmartContract(f *testing.F) {
	for _, s := range r31_parse_seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		sc, _, err := r31_parse(t, src)
		if err != nil {
			return
		}
		sc2, _, err2 := r31_parse(t, src)
		if err2 != nil || len(sc2.Functions) != len(sc.Functions) {
			t.Fatalf("re-parse differs: %v, %d vs %d functions", err2, len(sc2.Functions), len(sc.Functions))
		}
	})
}

func r31_parse(t *testing.T, src string) (sc SmartContract, pos string, err error) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseSmartContract panicked on %.120q: %v", src, r)
		}
	}()
	return ParseSmartContract(src)
}

// Variable is the store codec of every SC value (dvm_store.go). Encode→decode is the identity; decoding arbitrary
// bytes returns, errors, or panics with one of its two documented messages ("corruption in DB", "unknown variable
// type not implemented3"; upstream, reached only from bytes the node wrote itself: LoadSCValue / ReadSC), never
// another panic
func FuzzR31VariableUnmarshalBinary(f *testing.F) {
	for _, v := range []Variable{{Type: Uint64, ValueUint64: 0}, {Type: Uint64, ValueUint64: 1<<64 - 1},
		{Type: String, ValueString: ""}, {Type: String, ValueString: "dero"}} {
		f.Add(v.MarshalBinaryPanic())
	}
	f.Add([]byte{})
	f.Add([]byte{byte(Uint64)})
	f.Add([]byte{0xff, byte(Uint64)})
	f.Add([]byte{0x01, 0x7f})
	f.Fuzz(func(t *testing.T, buf []byte) {
		var v Variable
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					if m, _ := r.(string); m != "corruption in DB" && m != "unknown variable type not implemented3" {
						t.Fatalf("UnmarshalBinary(%x) panicked: %v", buf, r)
					}
					err = errFuzzPanic
				}
			}()
			err = v.UnmarshalBinary(buf)
		}()
		if err != nil {
			return
		}
		// a decoded value re-encodes to bytes that decode to the same value
		var w Variable
		if err := w.UnmarshalBinary(v.MarshalBinaryPanic()); err != nil || w != v {
			t.Fatalf("round trip of %x: %+v -> %+v (%v)", buf, v, w, err)
		}
		if v.Type == String && !bytes.Equal(v.MarshalBinaryPanic(), buf) {
			t.Fatalf("a String re-encodes to other bytes: %x -> %x", buf, v.MarshalBinaryPanic())
		}
	})
}

type fuzzPanic struct{}

func (fuzzPanic) Error() string { return "documented panic" }

var errFuzzPanic error = fuzzPanic{}

// SC_META_DATA: both codecs refuse any length but 33 and never panic; the Good codec round-trips exactly; the legacy
// codec (the one the chain writes) keeps only the type byte: its copy starts at offset 33, so DataHash is never
// stored or read (upstream quirk, pinned, consensus-visible through the SC meta tree hash)
func FuzzR31SCMetaUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add(SC_META_DATA{Type: 1}.MarshalBinary())
	f.Add(SC_META_DATA{Type: 1, DataHash: crypto.Hash{1, 2, 3}}.MarshalBinaryGood())
	f.Add(bytes.Repeat([]byte{0xff}, 34))
	f.Fuzz(func(t *testing.T, buf []byte) {
		var a, b SC_META_DATA
		ea, eb := a.UnmarshalBinary(buf), b.UnmarshalBinaryGood(buf)
		if (ea == nil) != (len(buf) == 33) || (eb == nil) != (len(buf) == 33) {
			t.Fatalf("len %d: errors %v / %v", len(buf), ea, eb)
		}
		if len(buf) != 33 {
			return
		}
		if a.Type != buf[0] || a.DataHash != (crypto.Hash{}) {
			t.Fatalf("legacy codec: %+v from %x", a, buf)
		}
		if !bytes.Equal(b.MarshalBinaryGood(), buf) {
			t.Fatalf("Good codec round trip: %x -> %x", buf, b.MarshalBinaryGood())
		}
		if got := a.MarshalBinary(); len(got) != 33 || got[0] != buf[0] || !bytes.Equal(got[1:], make([]byte, 32)) {
			t.Fatalf("legacy MarshalBinary: %x", got)
		}
	})
}

// execution under the gas limit: an arbitrary String argument to entrypoints that store it, measure it and loop on
// it; every run returns (no panic escapes Execute_sc_function), the compute gas never passes the 10,000,000 limit
// by more than one charge, and a failed run commits nothing
func FuzzR31ExecuteUnderGasLimit(f *testing.F) {
	const code = `
Function Initialize() Uint64
10 RETURN 0
End Function

Function Go(s String, n Uint64) Uint64
10 DIM i as Uint64
20 STORE("len", STRLEN(s))
30 STORE("s", s)
40 IF n == 0 THEN GOTO 100
50 LET i = i + 1
60 IF i < n THEN GOTO 50
100 STORE("h", HEX(SHA256(s)))
110 IF STRLEN(s) > 3 THEN GOTO 130
120 RETURN 0
130 STORE("sub", SUBSTR(s, 1, 2))
140 RETURN n % 3
End Function
`
	f.Add("", uint64(0), uint64(0))
	f.Add("dero", uint64(10), uint64(1_000))
	f.Add(strings.Repeat("x", 4096), uint64(1<<40), uint64(1_000_000))
	f.Add("\x00\xff", uint64(2), uint64(5))
	f.Fuzz(func(t *testing.T, s string, n, fees uint64) {
		if len(s) > 1<<16 {
			return
		}
		r := r27_new_sim(t, code)
		var gc uint64
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic escaped execution: %v", p)
				}
			}()
			gc, _, err = r.s.RunSC(map[crypto.Hash]uint64{}, r31_args("Go", r.scid,
				rpc.Argument{Name: "s", DataType: rpc.DataString, Value: s}, rpc.Argument{Name: "n", DataType: rpc.DataUint64, Value: n}), r.addr, fees%(1<<20))
		}()
		if gc > 10_000_000+25_000 {
			t.Fatalf("compute gas %d passed the limit by more than one charge", gc)
		}
		if err != nil && r.read("len") != nil {
			t.Fatalf("failed run (%v) committed a STORE", err)
		}
		if err == nil && r.read("len") != uint64(len(s)) {
			t.Fatalf("successful run stored len %v, want %d", r.read("len"), len(s))
		}
	})
}
