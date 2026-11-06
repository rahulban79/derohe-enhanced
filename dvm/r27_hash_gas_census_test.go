// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package dvm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// Round 27 offline census of the unmetered hash gas (B10 / C7, consensus pricing, report-only): how many bytes one SC
// invocation can hash under the fixed compute limit. Run with the limit sc.go Execute_sc_function sets (10,000,000)
// and its check on, so "Insufficient Gas" ends the call exactly where the chain would. No timing is taken (the
// per-MiB wall cost is the R23 bench, r23_hash_gas_bench_test.go); every figure below is gas accounting, which is
// deterministic.

const r27_census_limit = int64(10000000) // sc.go: state.GasComputeLimit

// Loop hashes its argument n times. Build makes the longest string the DVM allows (dvm.go string ADD refuses
// len >= 1 MiB) INSIDE the contract, from one byte, so no large tx argument is needed, then hashes it n times.
const r27_census_sc = `
Function Loop(s String, n Uint64) Uint64
10 DIM i as Uint64
20 IF i >= n THEN GOTO 60
30 %[1]s(s)
40 LET i = i + 1
50 GOTO 20
60 RETURN 0
End Function

Function Build(n Uint64) Uint64
10 DIM i, k as Uint64
11 DIM s as String
12 LET s = "a"
13 IF k >= 19 THEN GOTO 17
14 LET s = s + s
15 LET k = k + 1
16 GOTO 13
17 LET s = s + SUBSTR(s, 0, STRLEN(s) - 1)
18 IF STRLEN(s) != 1048575 THEN GOTO 99
20 IF i >= n THEN GOTO 60
30 %[1]s(s)
40 LET i = i + 1
50 GOTO 20
60 RETURN 0
99 RETURN 1
End Function
`

// runs entry with the chain's compute limit; returns gas used and whether it ran to RETURN 0
func r27_census_run(t *testing.T, fn, entry string, params map[string]interface{}) (gas int64, ok bool, err error) {
	t.Helper()
	sc, _, err := ParseSmartContract(fmt.Sprintf(r27_census_sc, fn))
	if err != nil {
		t.Fatal(err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{SCID: crypto.ZEROHASH, BLID: crypto.ZEROHASH, TXID: crypto.ZEROHASH},
		RamStore: map[Variable]Variable{}, GasComputeLimit: r27_census_limit, GasComputeCheck: true}
	res, err := RunSmartContract(&sc, entry, state, params)
	return state.GasComputeUsed, err == nil && res.Type == Uint64 && res.ValueUint64 == 0, err
}

// largest n for which entry completes within the limit (binary search; gas is monotone in n)
func r27_census_nmax(t *testing.T, fn, entry string, params map[string]interface{}) int {
	lo, hi := 0, 2000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		p := map[string]interface{}{"n": fmt.Sprint(mid)}
		for k, v := range params {
			p[k] = v
		}
		if _, ok, _ := r27_census_run(t, fn, entry, p); ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

func TestR27HashGasCensus(t *testing.T) {
	long := strings.Repeat("a", 1048575)
	for _, fn := range []string{"SHA256", "SHA3256", "KECCAK256"} {
		// the price does not depend on the input: 1 byte and 1,048,575 bytes cost the same gas
		g1, ok1, _ := r27_census_run(t, fn, "Loop", map[string]interface{}{"s": "a", "n": "10"})
		gL, okL, _ := r27_census_run(t, fn, "Loop", map[string]interface{}{"s": long, "n": "10"})
		if !ok1 || !okL || g1 != gL {
			t.Fatalf("%s: 10 calls cost %d gas on 1 byte, %d on 1,048,575 bytes (ok %v %v), want equal", fn, g1, gL, ok1, okL)
		}
		g0, _, _ := r27_census_run(t, fn, "Loop", map[string]interface{}{"s": "a", "n": "0"})
		per := (g1 - g0) / 10
		if per != 46600 { // 25,000 builtin + the loop's own line (5,000 each) and expression (800 each) costs
			t.Errorf("%s: %d gas per loop iteration, pinned 46,600", fn, per)
		}
		// gas is length-independent (above), so the call budget is found on a 1-byte string ...
		nArg := r27_census_nmax(t, fn, "Loop", map[string]interface{}{"s": "a"})
		if nArg != 214 {
			t.Errorf("%s: max calls per invocation %d, pinned 214", fn, nArg)
		}
		t.Logf("%s: %d gas/iteration; one invocation hashes up to %d x 1,048,575 = %d bytes", fn, per, nArg, int64(nArg)*1048575)
	}
	// ... and confirmed at the boundary on the longest string, and with the string built inside the contract from
	// one byte (no large tx argument), once (the price is the same for all three: pinned above)
	for _, c := range []struct {
		entry  string
		params map[string]interface{}
		n      int
	}{{"Loop", map[string]interface{}{"s": long}, 214}, {"Build", map[string]interface{}{}, 203}} {
		for _, n := range []int{c.n, c.n + 1} {
			p := map[string]interface{}{"n": fmt.Sprint(n)}
			for k, v := range c.params {
				p[k] = v
			}
			_, ok, err := r27_census_run(t, "SHA256", c.entry, p)
			if want := n == c.n; ok != want {
				t.Errorf("%s n=%d: completed %v, want %v (%v)", c.entry, n, ok, want, err)
			} else if !ok && (err == nil || !strings.Contains(err.Error(), "Insufficient Gas")) {
				t.Errorf("%s n=%d: failed with %v, want Insufficient Gas", c.entry, n, err)
			}
		}
	}
	t.Logf("in-SC built 1,048,575-byte string: %d calls = %d bytes per invocation", 203, int64(203)*1048575)
}
