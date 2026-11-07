// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package globals

// r28 (glue-global): globals/ money, amount, address and clock-offset code pinned by tests only (globals.go is
// content-pinned by forensics/r25: rft §7 B147, r28_b147_state_test.go). Each defect below was measured on this tree
// (harness/runtime/r28_glue_global_20261106.txt); while b147_landed is false the test pins the defective output AND
// checks it differs from the exact answer, so a silent change of either is caught.
//
//   GG27-1 / GG28-2 ParseAmount rounds digits past the 5th decimal (0.000009 -> 1 unit), loses the last unit at 19-20
//          digits, accepts a binary exponent ('1p3' = 8 DERO) and spends seconds and hundreds of MB on a long
//          exponent ('1e9999999': 10.5 s, 323 MB, a 10 MB error string; '1e99999999' > 300 s).
//   GG27-2 / GG28-1 FormatMoneyPrecision divides at 64 bits: a wrong 5th decimal for ~16 % of amounts >= 2^63, and
//          wrong digits past the 5th decimal for nearly every amount >= 2^40 at precision 12 (>= 2^53 at 8).
//   GG27-3 GetOffset is the negated correction Time() applies.
//   GG28-3 ParseValidateAddress accepts a 'deroproof' string (a payment proof) as a mainnet address (report-only:
//          rpc/address.go is pinned too).

import (
	"math"
	"math/big"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// exact_money is the reference: amount / 1e5 printed with prec decimals, ties to even below 5 decimals (the rounding
// big.Float.Text applies, which the held patch keeps: FormatMoney0(250000) = "2").
func exact_money(amount uint64, prec int) string {
	q, r := amount/100000, amount%100000
	if prec >= 5 {
		frac := strings.Repeat("0", 5-len(itoa(r))) + itoa(r) + strings.Repeat("0", prec-5)
		return itoa(q) + "." + frac
	}
	num := new(big.Int).SetUint64(amount)
	den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(5-prec)), nil)
	quo, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	twice := new(big.Int).Lsh(rem, 1)
	if c := twice.Cmp(den); c > 0 || (c == 0 && quo.Bit(0) == 1) {
		quo.Add(quo, big.NewInt(1))
	}
	s := quo.String()
	if prec == 0 {
		return s
	}
	for len(s) <= prec {
		s = "0" + s
	}
	return s[:len(s)-prec] + "." + s[len(s)-prec:]
}

func itoa(v uint64) string { return new(big.Int).SetUint64(v).String() }

func TestR28ExactMoneyOracle(t *testing.T) { // the reference itself, on hand-computed values
	for _, c := range []struct {
		a    uint64
		p    int
		want string
	}{{0, 5, "0.00000"}, {1, 5, "0.00001"}, {1, 12, "0.000010000000"}, {150000, 0, "2"}, {250000, 0, "2"},
		{350000, 0, "4"}, {123456, 2, "1.23"}, {123500, 2, "1.24"}, {124500, 2, "1.24"}, {5, 4, "0.0000"}, {15, 4, "0.0002"},
		{math.MaxUint64, 5, "184467440737095.51615"}, {math.MaxUint64, 0, "184467440737096"}} {
		if got := exact_money(c.a, c.p); got != c.want {
			t.Fatalf("exact_money(%d, %d) = %s, want %s", c.a, c.p, got, c.want)
		}
	}
}

// below 2^40 every precision is exact today; below 2^53 precisions 0..8 are: the agreement region the fix keeps.
func TestR28FormatMoneyAgreesBelowTheDefectRegion(t *testing.T) {
	rng := rand.New(rand.NewSource(28))
	for i := 0; i < 20000; i++ {
		a := rng.Uint64() % (1 << 40)
		b := rng.Uint64() % (1 << 53)
		for _, p := range []int{0, 5, 8, 12} { // the wrappers' precisions (1-4 round a binary value: ties are not exact)
			if got, want := FormatMoneyPrecision(a, p), exact_money(a, p); got != want {
				t.Fatalf("FormatMoneyPrecision(%d, %d) = %s, want %s", a, p, got, want)
			}
			if p > 8 {
				continue
			}
			if got, want := FormatMoneyPrecision(b, p), exact_money(b, p); got != want {
				t.Fatalf("FormatMoneyPrecision(%d, %d) = %s, want %s", b, p, got, want)
			}
		}
	}
	for _, c := range []struct {
		f    func(uint64) string
		p    int
		name string
	}{{FormatMoney, 5, "FormatMoney"}, {FormatMoney0, 0, "FormatMoney0"}, {FormatMoney5, 5, "FormatMoney5"},
		{FormatMoney8, 8, "FormatMoney8"}, {FormatMoney12, 12, "FormatMoney12"}} {
		for _, a := range []uint64{0, 1, 99999, 100000, 123456789, 1 << 39} {
			if got, want := c.f(a), exact_money(a, c.p); got != want {
				t.Fatalf("%s(%d) = %s, want %s", c.name, a, got, want)
			}
		}
	}
}

// the defect region: pinned outputs (measured) while held; exact once landed.
func TestR28FormatMoneyDefectRegion(t *testing.T) {
	pinned := []struct {
		a    uint64
		p    int
		held string // the current output (a wrong digit)
	}{
		{math.MaxUint64, 5, "184467440737095.51614"},
		{15229278382510024769, 5, "152292783825100.24770"},
		{4468711520580859, 12, "44687115205.808589998633"},
		{2322686249184832139, 8, "23226862491848.32139015"},
		{16104396465743066577, 12, "161043964657430.665771484375"},
	}
	for _, c := range pinned {
		got, want := FormatMoneyPrecision(c.a, c.p), exact_money(c.a, c.p)
		if b147_landed && got != want {
			t.Fatalf("landed: FormatMoneyPrecision(%d, %d) = %s, want %s", c.a, c.p, got, want)
		}
		if !b147_landed && (got != c.held || got == want) {
			t.Fatalf("held: FormatMoneyPrecision(%d, %d) = %s; pinned %s (exact %s): globals.go changed without the "+
				"B147 landing patch", c.a, c.p, got, c.held, want)
		}
	}
	// the rate the rft cites (B144: ~16 % of [2^63, 2^64) at 5 decimals): a fixed-seed sample of 20,000
	rng := rand.New(rand.NewSource(63))
	bad := 0
	for i := 0; i < 20000; i++ {
		a := 1<<63 | rng.Uint64()
		if FormatMoneyPrecision(a, 5) != exact_money(a, 5) {
			bad++
		}
	}
	t.Logf("GG27-2 rate: %d / 20000 amounts in [2^63, 2^64) print a wrong 5th decimal", bad)
	if b147_landed != (bad == 0) || (!b147_landed && (bad < 2000 || bad > 4500)) {
		t.Fatalf("wrong-5th-decimal rate %d / 20000 (landed %v; held expects 10-22 %%)", bad, b147_landed)
	}
	if !b147_landed {
		return
	}
	for i := 0; i < 20000; i++ { // landed: the whole uint64 range, every wrapper precision, exact
		a := rng.Uint64()
		for _, p := range []int{0, 5, 8, 12} {
			if got, want := FormatMoneyPrecision(a, p), exact_money(a, p); got != want {
				t.Fatalf("landed: FormatMoneyPrecision(%d, %d) = %s, want %s", a, p, got, want)
			}
		}
	}
}

func TestR28ParseAmountAgreementAndRoundTrip(t *testing.T) {
	ok := map[string]uint64{"1": 100000, "0.00001": 1, ".5": 50000, "5.": 500000, "  2 ": 200000, "\t3\n": 300000,
		"1e3": 100000000, "2.500000e-4": 25, "0": 0, "0.000000": 0, "123456789.12345": 12345678912345,
		"1E2": 10000000, "+7": 700000}
	for s, want := range ok {
		if got, err := ParseAmount(s); err != nil || got != want {
			t.Fatalf("ParseAmount(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"-1", "-0.00001", "0x10", "0b1", "1_000", "Inf", "-Inf", "NaN", "1,5", "", " ", "abc",
		"1/3", "184467440737095.51616", "1e15", "1e999999999"} {
		if got, err := ParseAmount(s); err == nil {
			t.Fatalf("ParseAmount(%q) = %d, nil; want an error", s, got)
		}
	}
	if _, err := ParseAmount("-1"); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("ParseAmount(-1): %v, want the negative-amount message", err)
	}
	if _, err := ParseAmount("12a"); err == nil || !strings.Contains(err.Error(), "could not be parsed") {
		t.Fatalf("ParseAmount(12a): %v, want the parse message", err)
	}
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 20000; i++ { // FormatMoney -> ParseAmount is the identity below 2^53 atomic units
		a := rng.Uint64() % (1 << 53)
		if got, err := ParseAmount(FormatMoney(a)); err != nil || got != a {
			t.Fatalf("round trip %d -> %s -> %d %v", a, FormatMoney(a), got, err)
		}
	}
}

func TestR28ParseAmountDefectsPinned(t *testing.T) {
	for _, c := range []struct {
		in     string
		held   uint64 // current result, accepted with err == nil
		exact  uint64
		refuse bool // the landed code refuses the input instead
	}{
		{"0.000009", 1, 0, true}, {"0.000005", 0, 0, true}, {"1.000005", 100000, 0, true}, {"0.000015", 1, 0, true},
		{"1p3", 800000, 0, true}, // a binary exponent: amounts are decimal
		{"92233720368547.75807", 9223372036854775806, 9223372036854775807, false},
		{"184467440737095.51614", 18446744073709551612, 18446744073709551614, false},
		{"184467440737095.51615", 18446744073709551614, 0, true}, // MaxUint64 is refused by the code's own rule
	} {
		got, err := ParseAmount(c.in)
		switch {
		case b147_landed && c.refuse && err == nil:
			t.Fatalf("landed: ParseAmount(%q) = %d, nil; want an error", c.in, got)
		case b147_landed && !c.refuse && (err != nil || got != c.exact):
			t.Fatalf("landed: ParseAmount(%q) = %d, %v; want %d", c.in, got, err, c.exact)
		case !b147_landed && (err != nil || got != c.held):
			t.Fatalf("held: ParseAmount(%q) = %d, %v; pinned %d: globals.go changed without the B147 landing patch",
				c.in, got, err, c.held)
		}
	}
}

// GG28-2: a long decimal exponent made ParseAmount build the whole number (and an error string of it). Measured on
// the current code: 1e9999999 10.5 s / 323 MB (a 10,000,024-byte error); 1e99999999 > 300 s. The held code is pinned on
// a cheap instance of the same cost (1e99999: a 100,024-byte error string); the landed code is timed on the long ones.
func TestR28ParseAmountLongExponentBounded(t *testing.T) {
	if !b147_landed {
		_, err := ParseAmount("1e99999")
		if err == nil || len(err.Error()) < 100000 {
			t.Fatalf("held: ParseAmount(1e99999) error of %d bytes; pinned >= 100,000 (the whole number printed): "+
				"globals.go changed without the B147 landing patch", len(err.Error()))
		}
		return
	}
	for _, s := range []string{"1e9999999", "1e99999999", "1p99999999", "1e-99999999", "0e99999999", "1e99999",
		"1" + strings.Repeat("0", 100000)} {
		t0 := time.Now()
		got, err := ParseAmount(s)
		if d := time.Since(t0); err == nil || d > 200*time.Millisecond || len(err.Error()) > 200 {
			t.Fatalf("landed: ParseAmount(%.20q...) = %d, %v in %v", s, got, err, d)
		}
	}
}

// GG27-3: GetOffset is the negated correction (held); the landed one is the correction itself, same sign as NTP.
func TestR28GetOffsetSignPinned(t *testing.T) {
	clock_state(t)
	if got := GetOffset(); got > time.Millisecond || got < -time.Millisecond {
		t.Fatalf("before NTP: GetOffset %v, want ~0", got)
	}
	const off = 1500 * time.Millisecond
	SetClockOffsetNTP(off)
	got := GetOffset()
	if b147_landed && got != off {
		t.Fatalf("landed: GetOffset %v, want %v", got, off)
	}
	if !b147_landed && (got > -off || got < -off-time.Second) { // now - (now'+off): -off minus the read jitter
		t.Fatalf("held: GetOffset %v, pinned -%v (minus jitter): globals.go changed without the B147 landing patch", got, off)
	}
	TimeIsInSync = true
	if g := GetOffset(); g > time.Millisecond || g < -time.Millisecond {
		t.Fatalf("--timeisinsync: GetOffset %v, want ~0", g)
	}
	TimeIsInSync = false
	atomic.StoreUint32(&ntp_in_sync, 0)
}

func r28_address(mainnet, proof bool) string {
	var k bn256.G1 // a synthetic key (G times a hash), not a wallet
	k.ScalarMult(crypto.G, crypto.HashtoNumber([]byte("r28 globals synthetic key")))
	a := rpc.Address{Mainnet: mainnet, Proof: proof, PublicKey: (*crypto.Point)(&k)}
	if proof { // a proof string carries its payload as arguments (an empty one does not decode)
		a.Arguments = rpc.Arguments{{Name: "V", DataType: rpc.DataUint64, Value: uint64(28)}}
	}
	return a.String()
}

func TestR28ParseValidateAddressNetworks(t *testing.T) {
	args_state(t)
	main, test, proof := r28_address(true, false), r28_address(false, false), r28_address(true, true)
	if !strings.HasPrefix(main, "dero1") || !strings.HasPrefix(test, "deto1") || !strings.HasPrefix(proof, "deroproof1") {
		t.Fatalf("synthetic addresses %s %s %s", main, test, proof)
	}
	for _, net := range []config.CHAIN_CONFIG{config.Mainnet, config.Testnet} {
		Config = net
		own, other := main, test
		if !IsMainnet() {
			own, other = test, main
		}
		a, err := ParseValidateAddress("  " + own + "\n")
		if err != nil || a.String() != own || a.IsMainnet() != IsMainnet() {
			t.Fatalf("%s: own-network address refused: %v", net.Name, err)
		}
		if _, err := ParseValidateAddress(other); err == nil || !strings.Contains(err.Error(), "invalid on current network") {
			t.Fatalf("%s: other-network address: %v, want the network message", net.Name, err)
		}
		for _, bad := range []string{"", own[:len(own)-1] + "x", strings.ToUpper(own[:5]) + own[5:], "dero1"} {
			if _, err := ParseValidateAddress(bad); err == nil {
				t.Fatalf("%s: %q accepted", net.Name, bad)
			}
		}
	}
	Config = config.Mainnet
	a, err := ParseValidateAddress(proof) // GG28-3 (report-only): a payment-proof string passes as an address
	if err != nil || !a.Proof {
		t.Fatalf("pinned GG28-3: ParseValidateAddress(deroproof...) = %v, %v; the observation changed, update rft B144", a, err)
	}
}

// the console core keeps its caller-stripping through With (a logger with fields), and StackTrace returns this stack.
func TestR28LoggerWithAndStackTrace(t *testing.T) {
	args_state(t)
	var con, file strings.Builder
	InitializeLog(&con, &file)
	Logger.WithValues("peer", "r28").Info("r28 with probe")
	if !strings.Contains(con.String(), "r28 with probe") || !strings.Contains(con.String(), "peer") ||
		strings.Contains(con.String(), "r28_globals_test.go") {
		t.Fatalf("console line %q: want the message and field, without the caller", con.String())
	}
	if !strings.Contains(file.String(), "r28_globals_test.go") {
		t.Fatalf("file line %q: want the caller", file.String())
	}
	if st := StackTrace(true); !strings.Contains(st, "TestR28LoggerWithAndStackTrace") {
		t.Fatalf("StackTrace does not hold the caller: %.200s", st)
	}
}
