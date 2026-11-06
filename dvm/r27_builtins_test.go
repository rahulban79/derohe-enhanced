// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package dvm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/graviton"
)

// Round 27 (dvm-blockchain): known-answer tests for the SC builtins the in-package tests left at 0.0% coverage
// (R27 sweep: EXISTS/DELETE, DERO, UPDATE_SC_CODE, IS_ADDRESS_VALID, ADDRESS_RAW, ADDRESS_STRING,
// SEND_ASSET_TO_ADDRESS, ASSETVALUE, ITOA, ATOI, STRLEN; measured here as well: MIN, MAX, PANIC), plus a pin of the
// builtin compute-gas table. dvm/ is consensus code: nothing here changes it. Every test runs a contract through the
// same Execute_sc_function -> SanityCheckExternalTransfers -> ProcessExternal / ErrorRevert path the chain uses
// (blockchain/transaction_execute.go process_transaction_sc), via the package's Simulator, and reads the committed
// trees afterwards. Where the behaviour is a footgun it is pinned as it is ("premise changed" if it ever moves).

const r27_test_address = "deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p" // simulator_test.go's key

const r27_builtins_sc = `
Function Initialize() Uint64
10 STORE("k", 7)
20 STORE("k2", 8)
30 RETURN 0
End Function

Function Scalars(s String) Uint64
10 STORE("dero", HEX(DERO()))
20 STORE("itoa", ITOA(12345))
30 STORE("atoi", ATOI("678"))
40 STORE("strlen", STRLEN(s))
50 STORE("min", MIN(3, 7))
60 STORE("max", MAX(3, 7))
70 STORE("ex_k", EXISTS("k"))
80 STORE("ex_none", EXISTS("nokey"))
90 RETURN 0
End Function

Function Addr(a String) Uint64
10 STORE("valid_raw", IS_ADDRESS_VALID(ADDRESS_RAW(a)))
20 STORE("valid_str", IS_ADDRESS_VALID(a))
30 STORE("valid_u64", IS_ADDRESS_VALID(5))
40 STORE("raw", HEX(ADDRESS_RAW(a)))
50 STORE("str", ADDRESS_STRING(ADDRESS_RAW(a)))
60 STORE("bad_raw", ADDRESS_RAW("nonsense"))
70 STORE("bad_str", ADDRESS_STRING("nonsense"))
80 STORE("u64_raw", ADDRESS_RAW(5))
90 RETURN 0
End Function

Function Assets(asset String) Uint64
10 STORE("av_dero", ASSETVALUE(DERO()))
20 STORE("dv", DEROVALUE())
30 STORE("av_x", ASSETVALUE(asset))
40 RETURN 0
End Function

Function Del() Uint64
10 DELETE("k")
20 RETURN 0
End Function

Function ExK() Uint64
10 STORE("ex_k_after", EXISTS("k"))
20 RETURN 0
End Function

Function DelThenExists() Uint64
10 DELETE("k2")
20 STORE("same_tx", EXISTS("k2"))
30 RETURN 0
End Function

Function Fail(which Uint64) Uint64
10 IF which == 1 THEN GOTO 100
20 IF which == 2 THEN GOTO 200
30 IF which == 3 THEN GOTO 300
40 IF which == 4 THEN GOTO 400
50 IF which == 5 THEN GOTO 500
60 RETURN 0
100 PANIC()
110 RETURN 0
200 STORE("z", ATOI("12a"))
210 RETURN 0
300 STORE("z", ATOI("18446744073709551616"))
310 RETURN 0
400 STORE("z", MIN(1, "a"))
410 RETURN 0
500 STORE("z", MAX("a", 1))
510 RETURN 0
End Function

Function Pay(dest String, amount Uint64, asset String) Uint64
10 SEND_ASSET_TO_ADDRESS(dest, amount, asset)
20 RETURN 0
End Function

Function PayDero(amount Uint64) Uint64
10 SEND_ASSET_TO_ADDRESS(SIGNER(), amount, DERO())
20 RETURN 0
End Function

Function PayShortAsset(amount Uint64) Uint64
10 SEND_ASSET_TO_ADDRESS(SIGNER(), amount, "short")
20 RETURN 0
End Function

Function Mint(amount Uint64) Uint64
10 SEND_ASSET_TO_ADDRESS(SIGNER(), amount, SCID())
20 RETURN 0
End Function

Function Upd(code String) Uint64
10 STORE("upd", UPDATE_SC_CODE(code))
20 RETURN 0
End Function

Function UpdU64() Uint64
10 STORE("upd_u64", UPDATE_SC_CODE(5))
20 RETURN 0
End Function
`

type r27_sim struct {
	t    *testing.T
	s    *Simulator
	scid crypto.Hash
	addr *rpc.Address
}

func r27_new_sim(t *testing.T, code string) *r27_sim {
	t.Helper()
	addr, err := rpc.NewAddress(r27_test_address)
	if err != nil {
		t.Fatal(err)
	}
	s := SimulatorInitialize(nil, 0)
	s.AccountAddBalance(*addr, crypto.ZEROHASH, 0) // registers the key with a zero balance (pub, G)
	scid, _, _, err := s.SCInstall(code, map[crypto.Hash]uint64{}, rpc.Arguments{}, addr, 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return &r27_sim{t: t, s: s, scid: scid, addr: addr}
}

func (r *r27_sim) call(entry string, deposits map[crypto.Hash]uint64, args ...rpc.Argument) error {
	a := rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: r.scid}, {Name: "entrypoint", DataType: rpc.DataString, Value: entry}}
	if deposits == nil {
		deposits = map[crypto.Hash]uint64{}
	}
	_, _, err := r.s.RunSC(deposits, append(a, args...), r.addr, 0)
	return err
}

func (r *r27_sim) must(entry string, deposits map[crypto.Hash]uint64, args ...rpc.Argument) {
	r.t.Helper()
	if err := r.call(entry, deposits, args...); err != nil {
		r.t.Fatalf("%s: %v", entry, err)
	}
}

func (r *r27_sim) data() *Tree_Wrapper { return Wrapped_tree(r.s.cache, r.s.ss, r.scid) }
func (r *r27_sim) read(key string) interface{} {
	return ReadSCValue(r.data(), r.scid, key)
}
func (r *r27_sim) held(asset crypto.Hash) uint64 {
	v, _ := LoadSCAssetValue(r.data(), r.scid, asset)
	return v
}

// the balance a key holds in tree t (nil: not present)
func r27_balance(t *testing.T, tree *graviton.Tree, key []byte) []byte {
	t.Helper()
	b, err := tree.Get(key)
	if err != nil {
		return nil
	}
	return b
}

// pub + v*G on Left, G on Right: a registered zero balance after an ElGamal.Plus(v)
func r27_expect(addr *rpc.Address, v uint64) []byte {
	e := crypto.ConstructElGamal((*bn256.G1)(addr.PublicKey), crypto.ElGamal_BASE_G).Plus(new(big.Int).SetUint64(v))
	return (&crypto.NonceBalance{Balance: e}).Serialize()
}

func TestR27BuiltinScalarsKAT(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	r.must("Scalars", nil, rpc.Argument{Name: "s", DataType: rpc.DataString, Value: "héllo"})
	want := map[string]interface{}{
		"dero":    strings.Repeat("00", 32), // DERO() is the 32-byte zero hash
		"itoa":    "12345",
		"atoi":    uint64(678),
		"strlen":  uint64(6), // bytes, not runes
		"min":     uint64(3),
		"max":     uint64(7),
		"ex_k":    uint64(1),
		"ex_none": uint64(0),
	}
	for k, v := range want {
		if got := r.read(k); got != v {
			t.Errorf("%s = %#v, want %#v", k, got, v)
		}
	}
}

func TestR27BuiltinAddressKAT(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	r.must("Addr", nil, rpc.Argument{Name: "a", DataType: rpc.DataString, Value: r27_test_address})
	main := *r.addr
	main.Mainnet = true
	want := map[string]interface{}{
		"valid_raw": uint64(1),
		"valid_str": uint64(0), // IS_ADDRESS_VALID takes the 33-byte raw key, not the string form
		"valid_u64": uint64(0),
		"raw":       hex.EncodeToString(r.addr.Compressed()),
		// ADDRESS_STRING always encodes a MAINNET address (rpc.NewAddressFromKeys sets Mainnet: true): the round trip
		// of a testnet/simulator address returns the dero1 form of the same key, not the input
		"str":     main.String(),
		"bad_raw": "",
		"bad_str": "",
		"u64_raw": "",
	}
	if !strings.HasPrefix(main.String(), "dero1") || main.String() == r27_test_address {
		t.Fatalf("premise: mainnet form %q", main.String())
	}
	for k, v := range want {
		if got := r.read(k); got != v {
			t.Errorf("%s = %#v, want %#v", k, got, v)
		}
	}
}

func TestR27BuiltinAssetValueKAT(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	var x crypto.Hash
	x[0], x[31] = 0x51, 0x15
	r.must("Assets", map[crypto.Hash]uint64{crypto.ZEROHASH: 40, x: 25}, rpc.Argument{Name: "asset", DataType: rpc.DataHash, Value: x})
	for k, v := range map[string]uint64{"av_dero": 40, "dv": 40, "av_x": 25} {
		if got := r.read(k); got != v {
			t.Errorf("%s = %#v, want %d", k, got, v)
		}
	}
	if r.held(crypto.ZEROHASH) != 40 || r.held(x) != 25 {
		t.Fatalf("SC holds DERO %d asset %d, want 40 25", r.held(crypto.ZEROHASH), r.held(x))
	}
}

func TestR27BuiltinExistsDelete(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	r.must("Del", nil)
	if v := r.read("k"); v != nil {
		t.Fatalf("k after DELETE in an earlier tx = %#v, want gone", v)
	}
	r.must("ExK", nil)
	if v := r.read("ex_k_after"); v != uint64(0) {
		t.Fatalf("EXISTS after a committed DELETE = %#v, want 0", v)
	}
	// footgun, pinned: within ONE invocation, EXISTS (or LOAD) of a key DELETEd earlier in it reads the deletion
	// marker (an empty value, dvm_store.go TX_Storage.Delete), which Variable.UnmarshalBinary refuses, and Load
	// panics: the whole call fails and is reverted instead of answering 0
	if err := r.call("DelThenExists", nil); err == nil || !strings.Contains(err.Error(), "invalid, probably corruption") {
		t.Fatalf("premise changed: EXISTS after DELETE in the same invocation no longer fails the call that way (%v)", err)
	}
	if v := r.read("k2"); v != uint64(8) {
		t.Fatalf("k2 after the failed call = %#v, want 8 (the DELETE was reverted with the call)", v)
	}
}

func TestR27BuiltinFailuresRevert(t *testing.T) {
	// the reason each one fails is pinned too. MIN/MAX type-check their FIRST argument twice (dvm_functions.go
	// dvm_min/dvm_max test a1 where a2 is meant), so a String second argument still fails, but at the unchecked
	// a2.(uint64) assertion ("interface conversion") rather than at the intended check: same verdict, other message.
	for which, c := range map[uint64]struct{ what, why string }{
		1: {"PANIC()", "panic function called"},
		2: {"ATOI non-digit", "invalid syntax"},
		3: {"ATOI overflow", "value out of range"},
		4: {"MIN with a String 2nd arg", "interface conversion"},
		5: {"MAX with a String 1st arg", "input argument must be uint64"},
	} {
		what := c.what
		r := r27_new_sim(t, r27_builtins_sc)
		if err := r.call("Fail", map[crypto.Hash]uint64{crypto.ZEROHASH: 9}, rpc.Argument{Name: "which", DataType: rpc.DataUint64, Value: which}); err == nil {
			t.Errorf("%s: call succeeded, want failure", what)
		} else if !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: failed with %.80q, want %q", what, err.Error(), c.why)
		}
		if v := r.read("z"); v != nil {
			t.Errorf("%s: z = %#v, want nothing stored", what, v)
		}
		// the failed call's deposit goes back to the signer (ErrorRevert), not to the SC
		if r.held(crypto.ZEROHASH) != 0 {
			t.Errorf("%s: SC holds %d after a failed call, want 0", what, r.held(crypto.ZEROHASH))
		}
		if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 9)) {
			t.Errorf("%s: signer balance is not its zero balance + 9 (refund)", what)
		}
	}
	r := r27_new_sim(t, r27_builtins_sc)
	r.must("Fail", nil, rpc.Argument{Name: "which", DataType: rpc.DataUint64, Value: uint64(0)}) // control: no failure
}

func TestR27SendAssetToAddressDERO(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	// SEND_ASSET_TO_ADDRESS with DERO() is SEND_DERO_TO_ADDRESS: debits the SC, credits the balance tree by Plus
	r.must("Pay", map[crypto.Hash]uint64{crypto.ZEROHASH: 700},
		rpc.Argument{Name: "dest", DataType: rpc.DataString, Value: string(r.addr.Compressed())},
		rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(300)},
		rpc.Argument{Name: "asset", DataType: rpc.DataHash, Value: crypto.ZEROHASH})
	if h := r.held(crypto.ZEROHASH); h != 400 {
		t.Fatalf("SC holds %d, want 700-300 = 400", h)
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 300)) {
		t.Fatal("destination balance is not its zero balance + 300*G")
	}
	// amount 0: no transfer record, nothing moves
	r.must("PayDero", nil, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(0)})
	if h := r.held(crypto.ZEROHASH); h != 400 {
		t.Fatalf("SC holds %d after a 0 payout, want 400", h)
	}
	// more than the SC holds: SanityCheckExternalTransfers underflow -> the call fails, the deposit is refunded
	if err := r.call("PayDero", map[crypto.Hash]uint64{crypto.ZEROHASH: 5}, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(406)}); err == nil || !strings.Contains(err.Error(), "underflow") {
		t.Fatalf("an overdraft payout was not refused as an underflow (%v)", err)
	}
	if h := r.held(crypto.ZEROHASH); h != 400 {
		t.Fatalf("SC holds %d after a refused overdraft, want 400", h)
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 305)) {
		t.Fatal("signer balance after the refused overdraft is not zero + 300 + 5 (refund)")
	}
	// an asset string that is not 32 bytes panics (only when amount > 0)
	if err := r.call("PayShortAsset", nil, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(1)}); err == nil || !strings.Contains(err.Error(), "32 byte length") {
		t.Fatalf("a short asset id was not refused (%v)", err)
	}
	r.must("PayShortAsset", nil, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(0)})
}

func TestR27SendAssetToAddressToken(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	var x crypto.Hash
	x[0], x[31] = 0x52, 0x25
	// a foreign token: debited from the SC's holding of x, credited in tree x (not the balance tree)
	r.must("Pay", map[crypto.Hash]uint64{x: 1000},
		rpc.Argument{Name: "dest", DataType: rpc.DataString, Value: string(r.addr.Compressed())},
		rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: uint64(300)},
		rpc.Argument{Name: "asset", DataType: rpc.DataHash, Value: x})
	if h := r.held(x); h != 700 {
		t.Fatalf("SC holds %d of x, want 700", h)
	}
	if got := r27_balance(t, r.s.cache[x], r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 300)) {
		t.Fatal("token tree x: destination is not zero + 300")
	}
	if got := r27_balance(t, r.s.balance_tree, r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, 0)) {
		t.Fatal("a token payout moved the DERO balance tree")
	}
	// the SC's own token (asset == SCID) is minted without limit (SanityCheckExternalTransfers skips asset == scid,
	// StoreSCValue never writes key == scid) and is credited inside the SC's own data tree, keyed by the holder
	const big_mint = uint64(1) << 62
	r.must("Mint", nil, rpc.Argument{Name: "amount", DataType: rpc.DataUint64, Value: big_mint})
	if got := r27_balance(t, r.s.cache[r.scid], r.addr.Compressed()); !bytes.Equal(got, r27_expect(r.addr, big_mint)) {
		t.Fatal("own-token mint is not credited in the SC data tree")
	}
	if h := r.held(r.scid); h != 0 {
		t.Fatalf("SC 'holds' %d of its own token, want 0 (never stored)", h)
	}
}

func TestR27UpdateSCCode(t *testing.T) {
	r := r27_new_sim(t, r27_builtins_sc)
	r.must("UpdU64", nil)
	if v := r.read("upd_u64"); v != uint64(0) {
		t.Fatalf("UPDATE_SC_CODE(Uint64) = %#v, want 0 (no change)", v)
	}
	next := `Function V() Uint64
10 STORE("v2", 1)
20 RETURN 0
End Function
Function Upd(code String) Uint64
10 STORE("upd", UPDATE_SC_CODE(code))
20 RETURN 0
End Function`
	r.must("Upd", nil, rpc.Argument{Name: "code", DataType: rpc.DataString, Value: next})
	if v := r.read("upd"); v != uint64(1) {
		t.Fatalf("UPDATE_SC_CODE(code) = %#v, want 1", v)
	}
	if err := r.call("Scalars", nil, rpc.Argument{Name: "s", DataType: rpc.DataString, Value: "x"}); err == nil {
		t.Fatal("an entrypoint of the replaced code still runs")
	}
	r.must("V", nil)
	if v := r.read("v2"); v != uint64(1) {
		t.Fatalf("new code did not run: v2 = %#v", v)
	}
	// footgun, pinned: the new code is stored without being parsed ("TODO verify code authenticity"), so source that
	// does not parse bricks the contract: every later call fails, including Upd itself
	r.must("Upd", nil, rpc.Argument{Name: "code", DataType: rpc.DataString, Value: "this is not DVM-BASIC"})
	if _, _, found := ReadSC(&Tree_Wrapper{Tree: r.s.sc_tree, Entries: map[string][]byte{}}, r.data(), r.scid); found {
		t.Fatal("premise changed: unparseable code is no longer stored")
	}
	if err := r.call("Upd", nil, rpc.Argument{Name: "code", DataType: rpc.DataString, Value: next}); err == nil {
		t.Fatal("premise changed: a contract with unparseable code can still be called")
	}
}

// The builtin compute-gas table is consensus pricing (B10: a change needs coordinated activation). This pins every
// entry so an edit to one is caught here, not only by a chain split.
func TestR27BuiltinGasTablePinned(t *testing.T) {
	want := map[string]int64{
		"version": 1000, "load": 5000, "exists": 5000, "store": 10000, "delete": 3000, "mapexists": 1000,
		"mapget": 1000, "mapstore": 1000, "mapdelete": 1000, "random": 2500, "scid": 2000, "blid": 2000,
		"txid": 2000, "dero": 10000, "block_height": 2000, "block_timestamp": 2500, "signer": 5000,
		"update_sc_code": 5000, "is_address_valid": 50000, "address_raw": 60000, "address_string": 50000,
		"send_dero_to_address": 70000, "send_asset_to_address": 90000, "derovalue": 10000, "assetvalue": 10000,
		"atoi": 5000, "itoa": 5000, "sha256": 25000, "sha3256": 25000, "keccak256": 25000, "hex": 10000,
		"hexdecode": 10000, "min": 5000, "max": 5000, "strlen": 20000, "substr": 20000, "panic": 10000,
	}
	if len(func_table) != len(want) {
		t.Fatalf("func_table has %d builtins, the pin %d", len(func_table), len(want))
	}
	for name, cost := range want {
		fs, ok := func_table[name]
		if !ok || len(fs) != 1 {
			t.Errorf("%s: %d versions, want 1", name, len(fs))
			continue
		}
		if fs[0].ComputeCost != cost || fs[0].StorageCost != 0 {
			t.Errorf("%s: compute %d storage %d, want %d 0", name, fs[0].ComputeCost, fs[0].StorageCost, cost)
		}
	}
}
