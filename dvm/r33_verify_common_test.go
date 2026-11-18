package dvm

// R33 pre-deployment invariant verification (D-21 non-consensus: tests only, no DVM semantics or gas change).
// Shared helpers for dvm/r33_verify_<contract>_test.go. Every test drives a contract in the simulator with several
// signers at chosen heights, keeps an independent ledger of what each signer deposited and what the rules award it,
// and after EVERY call checks:
//   - the SC's DERO balance equals the liability derived from the contract's stored variables (conservation);
//   - every DERO the SC sent went to the participant the rules name, in the amount the rules name (deroIs);
//   - the gas of every entrypoint stays below the 10,000,000 compute limit (2000 interpreted lines at 5000 gas/line,
//     dvm/dvm.go:71,522, dvm/sc.go:241) and the 20,000 storage-gas cap a mainnet call can buy
//     (config.MAX_STORAGE_GAS_ATOMIC_UNITS, dvm/sc.go:247-251).
// Simulator artefact (dvm/simulator.go:180-189): a deposit is credited to the SC without being debited from the
// signer; a reverted call credits the deposit back to the signer (w.refund). So only what the SC SENDS and HOLDS is
// counted, never the signer's own debit.
// Failing invariants are reported with t.Errorf("INVARIANT FAILS ...") so one run lists all of them.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

const (
	vComputeLimit = uint64(10000000)
	vStorageLimit = uint64(20000)
)

// vLedger is the per-participant ledger kept by a verification test.
type vLedger struct {
	t     *testing.T
	w     *gtWorld
	scid  crypto.Hash
	dep   map[string]uint64 // DERO deposited in successful calls
	recv  map[string]uint64 // DERO the SC sent (model: what the rules name)
	award map[string]uint64 // part of recv the rules award beyond the participant's own deposits
	loss  map[string]uint64 // deposits the rules take from the participant (slash, forfeit, fee)
	calls int
}

func vNewLedger(t *testing.T, w *gtWorld, scid crypto.Hash) *vLedger {
	return &vLedger{t: t, w: w, scid: scid, dep: map[string]uint64{}, recv: map[string]uint64{},
		award: map[string]uint64{}, loss: map[string]uint64{}}
}

// do runs entry; want says whether the model predicts success; pay is what the model says the SC sends to whom.
// On success the SC balance change must equal deposit - sum(pay) and every payee's balance must match the ledger.
func (l *vLedger) do(want bool, entry, signer string, dero uint64, assets map[crypto.Hash]uint64, pay map[string]uint64, args ...rpc.Argument) error {
	l.t.Helper()
	l.calls++
	before := l.w.held(l.scid, crypto.ZEROHASH)
	err := l.w.call(l.scid, entry, signer, dero, assets, args...)
	if (err == nil) != want {
		l.t.Fatalf("call %d %s by %s (deposit %d, args %v): model predicted success=%v, got err=%v", l.calls, entry, signer, dero, vArgs(args), want, err)
	}
	if err != nil {
		return err
	}
	l.dep[signer] += dero
	var sum uint64
	for n, a := range pay {
		sum += a
		l.recv[n] += a
	}
	after := l.w.held(l.scid, crypto.ZEROHASH)
	if before+dero-sum != after {
		l.t.Fatalf("call %d %s by %s: SC balance %d + deposit %d - model payouts %d = %d, SC holds %d", l.calls, entry, signer, before, dero, sum, before+dero-sum, after)
	}
	for n := range pay {
		l.w.deroIs(n, l.recv[n])
	}
	return nil
}

func vArgs(args []rpc.Argument) string {
	var b strings.Builder
	for _, a := range args {
		s := fmt.Sprintf("%v", a.Value)
		if len(s) > 24 {
			s = s[:24] + "..."
		}
		fmt.Fprintf(&b, "%s=%s ", a.Name, s)
	}
	return b.String()
}

// balances checks the cumulative identity recv == dep + award - loss for every participant, and recv <= dep + award.
func (l *vLedger) balances(names ...string) {
	l.t.Helper()
	for _, n := range names {
		if l.recv[n] > l.dep[n]+l.award[n] {
			l.t.Errorf("INVARIANT FAILS (no excess payout): %s received %d > deposited %d + awarded %d", n, l.recv[n], l.dep[n], l.award[n])
		}
		if l.recv[n]+l.loss[n] != l.dep[n]+l.award[n] {
			l.t.Errorf("INVARIANT FAILS (participant ledger): %s received %d + lost %d != deposited %d + awarded %d", n, l.recv[n], l.loss[n], l.dep[n], l.award[n])
		}
		l.w.deroIs(n, l.recv[n])
	}
}

// conserve compares the SC DERO balance with a liability computed from the stored variables.
func (l *vLedger) conserve(liab uint64, what string) {
	l.t.Helper()
	if held := l.w.held(l.scid, crypto.ZEROHASH); held != liab {
		l.t.Fatalf("conservation after call %d: SC holds %d, liability (%s) = %d (diff %d)", l.calls, held, what, liab, int64(held)-int64(liab))
	}
}

// vGas checks the measured maxima of every entrypoint of file against the compute and storage limits.
func vGas(t *testing.T, w *gtWorld, file string) {
	t.Helper()
	keys := []string{}
	for k := range w.gas {
		if strings.HasPrefix(k, file+":") || strings.HasPrefix(k, "proof:") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := w.gas[k]
		t.Logf("gas %-34s compute %8d (%.1f %%)  storage %6d", k, g[0], 100*float64(g[0])/float64(vComputeLimit), g[1])
		if g[0] >= vComputeLimit {
			t.Errorf("INVARIANT FAILS (gas): %s compute %d >= %d", k, g[0], vComputeLimit)
		}
		if !strings.HasSuffix(k, ":Initialize") && g[1] > vStorageLimit {
			t.Errorf("INVARIANT FAILS (gas): %s storage %d > %d (a mainnet call cannot buy more)", k, g[1], vStorageLimit)
		}
	}
}

// vOptU reads a uint64 key that may be missing.
func (w *gtWorld) vOptU(scid crypto.Hash, key string) (uint64, bool) {
	v, ok := w.read(scid, key).(uint64)
	return v, ok
}

func (w *gtWorld) vExists(scid crypto.Hash, key string) bool { return w.read(scid, key) != nil }

func (w *gtWorld) raw(name string) string { return string(w.addr[name].Compressed()) }

func vMin(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
