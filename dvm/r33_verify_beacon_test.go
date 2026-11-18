package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_beacon.bas (M6 discovery beacon). See r33_verify_common_test.go.
// Liability: 0 (the beacon owes nobody anything); the SC must hold 0 DERO after every call.

import (
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

type bcRun struct {
	t     *testing.T
	w     *gtWorld
	sc    crypto.Hash
	l     *vLedger
	keys  map[string]string
	subs  map[string]bool
	H     uint64
	names []string
}

func bcStart(t *testing.T, names ...string) *bcRun {
	all := append([]string{"owner"}, names...)
	w := gtNew(t, all...)
	w.at(100)
	sc := w.install("gt_beacon.bas", "owner")
	return &bcRun{t: t, w: w, sc: sc, l: vNewLedger(t, w, sc), keys: map[string]string{}, subs: map[string]bool{}, H: 100, names: all}
}

func (r *bcRun) check() {
	r.t.Helper()
	r.l.conserve(0, "the beacon holds nothing")
	if got := r.w.readU(r.sc, "nent"); got != uint64(len(r.keys)) {
		r.t.Fatalf("nent %d, distinct keys %d", got, len(r.keys))
	}
	if got := r.w.readU(r.sc, "nsub"); got != uint64(len(r.subs)) {
		r.t.Fatalf("nsub %d, subscribers %d", got, len(r.subs))
	}
	for _, n := range r.names {
		k := "sub_" + hex.EncodeToString(r.w.addr[n].Compressed())
		if r.w.vExists(r.sc, k) != r.subs[n] {
			r.t.Fatalf("%s for %s: exists %v, model %v", k, n, r.w.vExists(r.sc, k), r.subs[n])
		}
	}
}

func (r *bcRun) publish(who, k, v string, from, upto, dep uint64) {
	ok := who == "owner" && dep == 0 && len(k) > 0 && len(k) <= 32 && len(v) <= 512 && from <= upto && upto <= r.H
	r.l.do(ok, "Publish", who, dep, nil, nil, gtS("k", k), gtS("v", v), gtU("from", from), gtU("upto", upto))
	if ok {
		r.keys[k] = v
		if got := r.w.read(r.sc, "v_"+k); got != v {
			r.t.Fatalf("v_%s = %v", k, got)
		}
		if got := r.w.read(r.sc, "r_"+k); got != fmt.Sprintf("%d-%d", from, upto) {
			r.t.Fatalf("r_%s = %v", k, got)
		}
	}
	r.check()
}

func (r *bcRun) subscribe(who string, dep uint64) {
	ok := dep == 0 && !r.subs[who]
	r.l.do(ok, "Subscribe", who, dep, nil, nil)
	if ok {
		r.subs[who] = true
	}
	r.check()
}

func (r *bcRun) unsubscribe(who string, dep uint64) {
	ok := dep == 0 && r.subs[who]
	r.l.do(ok, "Unsubscribe", who, dep, nil, nil)
	if ok {
		delete(r.subs, who)
	}
	r.check()
}

func TestR33VerifyBeaconAccess(t *testing.T) {
	r := bcStart(t, "x")
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.publish("x", "k", "v", 1, 2, 0)
	r.publish("owner", "k", "v", 1, 2, 5) // deposit refused
	r.publish("owner", "k", "v", 1, 2, 0)
	r.publish("owner", "", "v", 1, 2, 0)
	r.publish("owner", strings.Repeat("k", 33), "v", 1, 2, 0)
	r.publish("owner", "k", strings.Repeat("v", 513), 1, 2, 0)
	r.publish("owner", "k", "v", 3, 2, 0)
	r.publish("owner", "k", "v", 3, 101, 0) // future range
	if r.w.read(r.sc, "owner") != r.w.raw("owner") {
		t.Fatalf("owner changed")
	}
	// anonymous signer (ring > 2): Subscribe refused, so no zero-key entry can exist
	if err := r.w.callAnon(r.sc, "Subscribe", 0); err == nil {
		t.Fatalf("anonymous Subscribe accepted")
	}
	r.check()
	// Initialize with a deposit is refused: install with 1 DERO must fail
	w2 := gtNew(t, "owner")
	if _, _, _, err := w2.s.SCInstall(gtCode(t, "gt_beacon.bas"), map[crypto.Hash]uint64{crypto.ZEROHASH: 5}, nil, w2.addr["owner"], 0); err == nil {
		t.Errorf("INVARIANT FAILS: gt_beacon Initialize accepted a deposit")
	}
}

func TestR33VerifyBeaconRandom(t *testing.T) {
	r := bcStart(t, "s1", "s2", "s3", "x")
	rng := mrand.New(mrand.NewSource(33))
	pick := func(s ...string) string { return s[rng.Intn(len(s))] }
	for step := 0; step < 600; step++ {
		r.H += uint64(rng.Intn(3))
		r.w.at(r.H)
		dep := uint64(0)
		if rng.Intn(10) == 0 {
			dep = uint64(1 + rng.Intn(100))
		}
		switch rng.Intn(3) {
		case 0:
			from := uint64(rng.Intn(int(r.H) + 5))
			upto := from + uint64(rng.Intn(20))
			k := fmt.Sprintf("k%d", rng.Intn(12))
			if rng.Intn(20) == 0 {
				k = strings.Repeat("q", 30+rng.Intn(5))
			}
			r.publish(pick("owner", "owner", "x"), k, strings.Repeat("v", rng.Intn(520)), from, upto, dep)
		case 1:
			r.subscribe(pick("s1", "s2", "s3", "x", "owner"), dep)
		default:
			r.unsubscribe(pick("s1", "s2", "s3", "x", "owner"), dep)
		}
	}
	t.Logf("%d calls, %d keys, %d subscribers", r.l.calls, len(r.keys), len(r.subs))
	vGas(t, r.w, "gt_beacon.bas")
}

// bounds: maximal key (32) and value (512) bytes stay under the 20,000 storage gas a mainnet call can buy
func TestR33VerifyBeaconBounds(t *testing.T) {
	r := bcStart(t, "x")
	for i := 0; i < 5; i++ {
		r.publish("owner", strings.Repeat(fmt.Sprint(i), 32), strings.Repeat("v", 512), 0, 100, 0)
	}
	vGas(t, r.w, "gt_beacon.bas")
}
