package dvm

// R31 (dero-rft §7 B289 / B292; D-21 non-consensus: tests only, no DVM semantics or gas change). KATs that pin the
// execution guards (compute gas limit, storage gas per stored byte, the revert path and its value conservation), the
// MIN/MAX second-argument behaviour (B292, disclosure-style: pinned, never changed) and fuzz targets with seed corpora
// for the DVM parser, the store codecs and execution under the gas limit (detector fuzz-coverage findings, B281).

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

const r31_sc = `
Function Initialize() Uint64
10 RETURN 0
End Function

Function Spin() Uint64
10 GOTO 10
End Function

Function Put(s String) Uint64
10 STORE("s", s)
20 RETURN 0
End Function

Function Pay(amount Uint64) Uint64
10 SEND_DERO_TO_ADDRESS(SIGNER(), amount)
20 RETURN 0
End Function

Function Fail() Uint64
10 STORE("f", 1)
20 RETURN 1
End Function

Function MinMax(which Uint64) Uint64
10 IF which == 1 THEN GOTO 100
20 IF which == 2 THEN GOTO 200
30 IF which == 3 THEN GOTO 300
40 IF which == 4 THEN GOTO 400
50 STORE("min", MIN(9, 4))
60 STORE("max", MAX(9, 4))
70 RETURN 0
100 STORE("z", MIN(1, "a"))
110 RETURN 0
200 STORE("z", MAX(1, "a"))
210 RETURN 0
300 STORE("z", MIN("a", 1))
310 RETURN 0
400 STORE("z", MAX("a", 1))
410 RETURN 0
End Function
`

func r31_args(entry string, scid crypto.Hash, extra ...rpc.Argument) rpc.Arguments {
	return append(rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid}, {Name: "entrypoint", DataType: rpc.DataString, Value: entry}}, extra...)
}

// B292: MIN/MAX test a1's type twice and never a2's (dvm_functions.go dvm_min/dvm_max). Today a non-uint64 second
// argument fails at the unchecked a2.(uint64) assertion; RunSmartContract recovers it into an SC error, nothing is
// stored, the node does not crash. Pinned as is (DVM behaviour is consensus-visible; D-21: never changed locally).
func TestR31MinMaxSecondArgPinned(t *testing.T) {
	for which, c := range map[uint64]struct{ what, why string }{
		1: {"MIN(1, \"a\")", "interface conversion"},
		2: {"MAX(1, \"a\")", "interface conversion"},
		3: {"MIN(\"a\", 1)", "input argument must be uint64"},
		4: {"MAX(\"a\", 1)", "input argument must be uint64"},
	} {
		r := r27_new_sim(t, r31_sc)
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%s: panic escaped the VM: %v", c.what, p)
				}
			}()
			err = r.call("MinMax", nil, rpc.Argument{Name: "which", DataType: rpc.DataUint64, Value: which})
		}()
		if err == nil || !strings.Contains(err.Error(), "Recovered in function") || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: err %.100q, want a recovered SC error naming %q", c.what, err, c.why)
		}
		if v := r.read("z"); v != nil {
			t.Errorf("%s: z = %#v stored, want nothing", c.what, v)
		}
	}
	r := r27_new_sim(t, r31_sc)
	r.must("MinMax", nil, rpc.Argument{Name: "which", DataType: rpc.DataUint64, Value: uint64(0)})
	if r.read("min") != uint64(4) || r.read("max") != uint64(9) {
		t.Fatalf("MIN(9,4)=%v MAX(9,4)=%v, want 4 9", r.read("min"), r.read("max"))
	}
}

// the compute gas limit (sc.go: 10,000,000 per execution) stops an endless loop; the gas reported is pinned
func TestR31GasComputeLimitKAT(t *testing.T) {
	r := r27_new_sim(t, r31_sc)
	gc, _, err := r.s.RunSC(map[crypto.Hash]uint64{}, r31_args("Spin", r.scid), r.addr, 0)
	if err == nil || !strings.Contains(err.Error(), "Insufficient Gas") {
		t.Fatalf("endless loop: err %.100q, want Insufficient Gas", err)
	}
	t.Logf("Spin: gascompute %d", gc)
	if gc != 10_005_000 {
		t.Fatalf("Spin: gascompute %d, want %d (limit 10,000,000 crossed by one charge)", gc, uint64(10_005_000))
	}
}

// storage gas: every stored byte is charged (dvm_store.go Store), and a storage gas budget below the need fails
func TestR31GasStorageKAT(t *testing.T) {
	put := func(fees uint64, s string) (uint64, error) {
		r := r27_new_sim(t, r31_sc)
		_, gs, err := r.s.RunSC(map[crypto.Hash]uint64{}, r31_args("Put", r.scid, rpc.Argument{Name: "s", DataType: rpc.DataString, Value: s}), r.addr, fees)
		return gs, err
	}
	small, err := put(100_000, "x")
	if err != nil {
		t.Fatal(err)
	}
	big, err := put(100_000, strings.Repeat("x", 1001))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("storage gas: 1 byte %d, 1001 bytes %d", small, big)
	// the 1,000 extra bytes are charged twice: once in the SCDATA argument (sc.go ConsumeStorageGas(len(SCDATA))),
	// once in the stored value (dvm_store.go Store: len(vbytes) * 1), plus one byte of varint length growth in each
	if small != 77 || big != 2079 {
		t.Fatalf("storage gas %d / %d, want 77 / 2079", small, big)
	}
	if _, err := put(big-1, strings.Repeat("x", 1001)); err == nil || !strings.Contains(err.Error(), "Insufficient Storage Gas") {
		t.Fatalf("one unit short: err %.100q, want Insufficient Storage Gas", err)
	}
	if _, err := put(big, strings.Repeat("x", 1001)); err != nil {
		t.Fatalf("exact budget: %v", err)
	}
}

// the revert path: a non-zero RETURN discards every STORE and refunds the deposit to the signer; a successful payout
// moves value from the SC to the signer. SC balance + refunded + paid out = deposited, at every step (B157 class).
func TestR31SimulatorRevertConservationKAT(t *testing.T) {
	r := r27_new_sim(t, r31_sc)
	if err := r.call("Pay", map[crypto.Hash]uint64{crypto.ZEROHASH: 50_000}, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(20_000)}); err != nil {
		t.Fatal(err)
	}
	if r.held(crypto.ZEROHASH) != 30_000 {
		t.Fatalf("after Pay: SC holds %d, want 30000", r.held(crypto.ZEROHASH))
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 20_000)) {
		t.Fatal("after Pay: signer balance is not zero + 20000")
	}
	err := r.call("Fail", map[crypto.Hash]uint64{crypto.ZEROHASH: 7_000})
	if err == nil || !strings.Contains(err.Error(), "Discarded knowingly") {
		t.Fatalf("Fail: err %v, want Discarded knowingly", err)
	}
	if r.read("f") != nil {
		t.Fatal("Fail: its STORE was committed")
	}
	if r.held(crypto.ZEROHASH) != 30_000 {
		t.Fatalf("after Fail: SC holds %d, want 30000 (deposit refunded, not kept)", r.held(crypto.ZEROHASH))
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 27_000)) {
		t.Fatal("after Fail: signer balance is not zero + 20000 + 7000 refund")
	}
	// overdraw: SanityCheckExternalTransfers refuses, nothing moves, the deposit is refunded
	if err := r.call("Pay", map[crypto.Hash]uint64{crypto.ZEROHASH: 1_000}, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(1_000_000)}); err == nil {
		t.Fatal("overdraw succeeded")
	}
	if r.held(crypto.ZEROHASH) != 30_000 {
		t.Fatalf("after overdraw: SC holds %d, want 30000", r.held(crypto.ZEROHASH))
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 28_000)) {
		t.Fatal("after overdraw: signer balance is not zero + 27000 + 1000 refund")
	}
}
