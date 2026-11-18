package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_service.bas (M2 notary + rebate). See r33_verify_common_test.go.
// Liability derived from the contract's variables (checked after every call):
//   treasury + per epoch e with W<e>: W == 0 -> P<e> (a sponsor-only pool awaiting its roll);
//   W > 0 and Z < C -> P<e> - Q<e> (unclaimed rebates + the remainder the last claim sweeps); Z == C -> 0.
// MAT: the SC's MAT balance equals the sum of ms<u> (stakes).

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

type svEpoch struct {
	W, P, C, Z, Q uint64
	w             map[string]uint64
	z             map[string]bool
	fees          map[string]uint64
	external      bool // sponsor money or a rolled pool joined
	sw            bool // swept after the claim deadline
}

type svModel struct {
	fee, rho, boost, epoch, minmat uint64
	frozen                         bool
	ep                             map[uint64]*svEpoch
	le                             uint64
	hasLe                          bool
	treasury                       uint64
	docs                           map[string]bool
	ms, ml                         map[string]uint64
	hasMs                          map[string]bool
}

// svPay is ClaimRebate's formula (gt_service.bas BASIC 84-93, r33 verify fix: no wrap of wt * 100000)
func svPay(pp, wt, ww uint64) uint64 {
	if pp > math.MaxUint64/wt {
		sh := wt * 100000 / ww
		if wt > 184467440737095 {
			sh = wt / (ww/100000 + 1)
		}
		return pp/100000*sh + pp%100000*sh/100000
	}
	return pp * wt / ww
}

type svRun struct {
	t     *testing.T
	w     *gtWorld
	mat   crypto.Hash
	sc    crypto.Hash
	m     *svModel
	l     *vLedger
	names []string
	H     uint64
}

func svStart(t *testing.T, names ...string) *svRun {
	all := append([]string{"owner", "miner"}, names...)
	w := gtNew(t, all...)
	w.at(100)
	mat := w.install("gt_attest.bas", "owner")
	w.must(mat, "Freeze", "owner", 0, nil)
	sc := w.install("gt_service.bas", "owner")
	m := &svModel{fee: 1000, rho: 50, boost: 100, epoch: 100, minmat: 100, ep: map[uint64]*svEpoch{}, docs: map[string]bool{},
		ms: map[string]uint64{}, ml: map[string]uint64{}, hasMs: map[string]bool{}}
	return &svRun{t: t, w: w, mat: mat, sc: sc, m: m, l: vNewLedger(t, w, sc), names: all, H: 100}
}

func (r *svRun) at(h uint64) { r.H = h; r.w.at(h) }

// earn gives name 100 MAT through an honest unchallenged gt_attest claim
func (r *svRun) earn(name string, from uint64) {
	r.w.must(r.mat, "Claim", name, gtBond, nil, gtU("from", from), gtU("upto", from), gtU("k", 1))
}

func svLiab(w *gtWorld, sc crypto.Hash, maxE uint64) uint64 {
	L := w.readU(sc, "treasury")
	for e := uint64(0); e <= maxE; e++ {
		W, ok := w.vOptU(sc, fmt.Sprintf("W%d", e))
		if !ok {
			continue
		}
		P := w.readU(sc, fmt.Sprintf("P%d", e))
		if W == 0 {
			L += P
			continue
		}
		if w.readU(sc, fmt.Sprintf("Z%d", e)) < w.readU(sc, fmt.Sprintf("C%d", e)) {
			L += P - w.readU(sc, fmt.Sprintf("Q%d", e))
		}
	}
	return L
}

func (r *svRun) check() {
	r.t.Helper()
	r.l.conserve(svLiab(r.w, r.sc, r.H/r.m.epoch+1), "treasury + open epoch pools")
	if got := r.w.readU(r.sc, "treasury"); got != r.m.treasury {
		r.t.Fatalf("treasury %d, model %d", got, r.m.treasury)
	}
	var ms uint64
	for _, v := range r.m.ms {
		ms += v
	}
	if got := r.w.held(r.sc, r.mat); got != ms {
		r.t.Fatalf("SC holds %d MAT, stakes sum %d", got, ms)
	}
}

func (r *svRun) epopen(e uint64) *svEpoch {
	if r.m.ep[e] == nil {
		r.m.ep[e] = &svEpoch{w: map[string]uint64{}, z: map[string]bool{}, fees: map[string]uint64{}}
	}
	return r.m.ep[e]
}

func (r *svRun) roll(e uint64) {
	m := r.m
	r.epopen(e)
	if !m.hasLe {
		m.le, m.hasLe = e, true
		return
	}
	if m.le >= e {
		return
	}
	if l := m.ep[m.le]; l.W == 0 && l.P != 0 {
		m.ep[e].P += l.P
		m.ep[e].external = true
		l.P = 0
	}
	m.le = e
}

func (r *svRun) notarize(u, doc string, dep uint64) {
	m := r.m
	ok := m.frozen && dep == m.fee && len(doc) > 0 && len(doc) <= 64 && !m.docs[doc]
	r.l.do(ok, "Notarize", u, dep, nil, nil, gtS("doc", doc))
	if ok {
		m.docs[doc] = true
		e := r.H / m.epoch
		r.roll(e)
		E := m.ep[e]
		rr := m.fee * m.rho / 100
		wt := m.fee
		if m.hasMs[u] && m.ms[u] >= m.minmat {
			wt = m.fee * (100 + m.boost) / 100
		}
		if _, seen := E.w[u]; !seen {
			E.C++
		}
		E.w[u] += wt
		E.fees[u] += m.fee
		E.W += wt
		E.P += rr
		m.treasury += m.fee - rr
		r.l.loss[u] += m.fee
		if m.hasMs[u] && m.ml[u] <= e {
			m.ml[u] = e
		}
		if got := r.w.read(r.sc, "by"+doc); got != r.w.raw(u) {
			r.t.Fatalf("by%s = %v", doc, got)
		}
	}
	r.check()
}

func (r *svRun) sponsor(s string, dep uint64) {
	m := r.m
	ok := m.frozen && dep > 0
	r.l.do(ok, "Sponsor", s, dep, nil, nil)
	if ok {
		e := r.H / m.epoch
		r.roll(e)
		m.ep[e].P += dep
		m.ep[e].external = true
		r.l.loss[s] += dep
	}
	r.check()
}

func (r *svRun) claim(u string, e uint64) {
	m := r.m
	E := m.ep[e]
	ok := (e+1)*m.epoch <= r.H && r.H < (e+11)*m.epoch && E != nil
	if ok {
		_, has := E.w[u]
		ok = has && !E.z[u] && E.W != 0
	}
	var pay map[string]uint64
	if ok {
		p := svPay(E.P, E.w[u], E.W)
		exact := new(big.Int).Mul(new(big.Int).SetUint64(E.P), new(big.Int).SetUint64(E.w[u]))
		exact.Div(exact, new(big.Int).SetUint64(E.W))
		if new(big.Int).SetUint64(p).Cmp(exact) > 0 {
			r.t.Errorf("INVARIANT FAILS (rebate above the pro-rata share): epoch %d %s pay %d > exact %s", e, u, p, exact)
		}
		if !E.external && E.C == 1 && p > E.fees[u] {
			r.t.Errorf("INVARIANT FAILS (no-wash): epoch %d sole payer %s rebate %d > fees paid %d", e, u, p, E.fees[u])
		}
		pay = map[string]uint64{u: p}
		r.l.award[u] += p
		E.z[u] = true
		E.Z++
		E.Q += p
		if E.Z == E.C {
			m.treasury += E.P - E.Q
		}
	}
	r.l.do(ok, "ClaimRebate", u, 0, nil, pay, gtU("e", e))
	r.check()
}

// sweep: anyone, once, after (e + 11) * epoch, when not every payer claimed: P - Q goes to the treasury
func (r *svRun) sweep(who string, e uint64) {
	m := r.m
	E := m.ep[e]
	ok := r.H >= (e+11)*m.epoch && E != nil && !E.sw && E.Z != E.C
	if ok {
		m.treasury += E.P - E.Q
		E.Q = E.P
		E.sw = true
	}
	r.l.do(ok, "Sweep", who, 0, nil, nil, gtU("e", e))
	r.check()
}

func (r *svRun) stakeMAT(u string, amt uint64) {
	m := r.m
	ok := amt > 0
	var as map[crypto.Hash]uint64
	if amt > 0 {
		as = map[crypto.Hash]uint64{r.mat: amt}
	}
	r.l.do(ok, "StakeMAT", u, 0, as, nil)
	if ok {
		m.ms[u] += amt
		m.hasMs[u] = true
		m.ml[u] = r.H / m.epoch
	}
	r.check()
}

func (r *svRun) unstakeMAT(u string, amt uint64) {
	m := r.m
	ok := m.hasMs[u] && r.H/m.epoch > m.ml[u] && amt > 0 && amt <= m.ms[u]
	r.l.do(ok, "UnstakeMAT", u, 0, nil, nil, gtU("amount", amt))
	if ok {
		m.ms[u] -= amt
	}
	r.check()
}

func (r *svRun) withdrawTreasury(who string, amt uint64) {
	m := r.m
	ok := who == "owner" && amt > 0 && amt <= m.treasury
	var pay map[string]uint64
	if ok {
		pay = map[string]uint64{who: amt}
		r.l.award[who] += amt
		m.treasury -= amt
	}
	r.l.do(ok, "WithdrawTreasury", who, 0, nil, pay, gtU("amount", amt))
	r.check()
}

func svParams(fee, rho, boost, epoch, minmat uint64) []rpc.Argument {
	return []rpc.Argument{gtU("fee", fee), gtU("rho", rho), gtU("boost", boost), gtU("epoch", epoch), gtU("minmat", minmat)}
}

func (r *svRun) setMAT(who string) {
	r.l.do(who == "owner" && !r.m.frozen, "SetMAT", who, 0, nil, nil, gtS("scidhex", hex.EncodeToString(r.mat[:])))
}

func (r *svRun) freeze() {
	r.l.do(true, "Freeze", "owner", 0, nil, nil)
	r.m.frozen = true
}

// drain: every closed epoch can be claimed by every payer, MAT unstaked and the treasury withdrawn; what is left
// is exactly the pool of the last epoch with activity when it had no fee payer (it waits for the next call)
func (r *svRun) drain() {
	r.t.Helper()
	m := r.m
	r.at((r.H/m.epoch + 2) * m.epoch)
	var last uint64
	for e, E := range m.ep {
		if e > last {
			last = e
		}
		for u := range E.w {
			if !E.z[u] && r.H < (e+11)*m.epoch {
				r.claim(u, e)
			}
		}
	}
	// epochs whose claim deadline passed with payers who never claimed: Sweep releases the rest to the treasury
	r.at(vMaxU(r.H, (last+11)*m.epoch))
	for e, E := range m.ep {
		if E.Z != E.C && !E.sw {
			r.sweep("x", e)
		}
	}
	for u, v := range m.ms {
		if v > 0 {
			r.unstakeMAT(u, v)
		}
	}
	if m.treasury > 0 {
		r.withdrawTreasury("owner", m.treasury)
	}
	var waiting uint64
	if m.hasLe && m.ep[m.le].W == 0 {
		waiting = m.ep[m.le].P
	}
	if waiting > 0 { // the documented roll: any later Notarize takes it into a claimable pool
		r.notarize(r.names[len(r.names)-1], fmt.Sprintf("drain-%d", r.H), m.fee)
		r.at(r.H + m.epoch)
		r.drain()
		return
	}
	if got := r.w.held(r.sc, crypto.ZEROHASH); got != 0 {
		r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d after every payer claimed and the treasury was withdrawn", got)
	}
	r.l.balances(r.names...)
}

func TestR33VerifyServiceAccess(t *testing.T) {
	r := svStart(t, "u1", "x")
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.l.do(false, "SetParams", "x", 0, nil, nil, svParams(1000, 50, 100, 100, 100)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, svParams(1000, 60, 100, 100, 100)...) // no-wash bound
	r.l.do(false, "SetParams", "owner", 0, nil, nil, svParams(1000000000001, 50, 100, 100, 100)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, svParams(1000, 9, 1001, 100, 100)...)
	r.l.do(true, "SetParams", "owner", 0, nil, nil, svParams(1000, 50, 100, 100, 100)...)
	r.setMAT("x")
	r.setMAT("owner")
	r.l.do(false, "Freeze", "x", 0, nil, nil)
	r.l.do(false, "WithdrawTreasury", "x", 0, nil, nil, gtU("amount", 1))
	r.notarize("u1", "before-freeze", 1000)
	r.sponsor("x", 1000)
	r.freeze()
	r.l.do(false, "Freeze", "owner", 0, nil, nil) // one-time (r33 verify fix)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, svParams(1000, 50, 100, 100, 100)...)
	r.setMAT("owner")
	r.check()
	vGas(t, r.w, "gt_service.bas")
}

func TestR33VerifyServiceRandom(t *testing.T) {
	for _, seed := range []int64{33, 3301, 3302} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := svStart(t, "u1", "u2", "u3", "sp", "x")
			rng := mrand.New(mrand.NewSource(seed))
			pick := func(s ...string) string { return s[rng.Intn(len(s))] }
			r.setMAT("owner")
			r.freeze()
			r.earn("miner", 90)
			r.earn("u1", 90)
			r.at(121)
			r.w.must(r.mat, "Finalize", "x", 0, nil, gtU("i", 0))
			r.w.must(r.mat, "Finalize", "x", 0, nil, gtU("i", 1))
			// gt_attest returned each bond: DERO from outside this contract, kept out of the service ledger
			r.w.refund["miner"] += gtBond
			r.w.refund["u1"] += gtBond
			r.at(150)
			for step := 0; step < 700; step++ {
				r.at(r.H + uint64(rng.Intn(9)))
				cur := r.H / r.m.epoch
				switch a := rng.Intn(100); {
				case a < 40:
					dep := r.m.fee
					if rng.Intn(15) == 0 {
						dep++
					}
					doc := fmt.Sprintf("doc-%d", rng.Intn(400))
					if rng.Intn(30) == 0 {
						doc = ""
					}
					r.notarize(pick("u1", "u2", "u3", "miner"), doc, dep)
				case a < 47:
					r.sponsor(pick("sp", "x"), uint64(rng.Intn(5000)))
				case a < 75:
					e := cur
					if cur > 0 {
						e = cur - uint64(rng.Intn(int(vMin(cur, 4))+1))
					}
					if rng.Intn(6) == 0 && cur >= 11 {
						r.sweep(pick("x", "u1"), cur-11+uint64(rng.Intn(2))-uint64(rng.Intn(4)))
					} else {
						r.claim(pick("u1", "u2", "u3", "miner", "x"), e)
					}
				case a < 82:
					r.stakeMAT(pick("miner", "u1"), uint64(rng.Intn(3))*50)
				case a < 89:
					u := pick("miner", "u1", "u2")
					amt := uint64(1 + rng.Intn(200))
					if rng.Intn(2) == 0 && r.m.ms[u] > 0 {
						amt = r.m.ms[u]
					}
					r.unstakeMAT(u, amt)
				case a < 94:
					r.withdrawTreasury(pick("owner", "owner", "x"), uint64(1+rng.Intn(int(r.m.treasury+2))))
				default:
					switch rng.Intn(3) {
					case 0:
						r.l.do(false, "SetParams", "owner", 0, nil, nil, svParams(1000, 50, 100, 100, 100)...)
					case 1:
						r.setMAT(pick("owner", "x"))
					default:
						r.l.do(false, "Initialize", pick("owner", "x"), 0, nil, nil)
					}
					r.check()
				}
			}
			t.Logf("seed %d: %d calls, %d epochs, %d docs, treasury %d, height %d", seed, r.l.calls, len(r.m.ep), len(r.m.docs), r.m.treasury, r.H)
			r.drain()
			vGas(t, r.w, "gt_service.bas")
		})
	}
}

// sponsor-only epochs roll into the next epoch with a call; nothing is stuck once anyone notarizes
func TestR33VerifyServiceRollLiveness(t *testing.T) {
	r := svStart(t, "u1", "sp")
	r.setMAT("owner")
	r.freeze()
	r.at(200)
	r.sponsor("sp", 7000) // epoch 2, no payer
	r.at(350)
	r.sponsor("sp", 3) // epoch 3: epoch 2's pool rolls here
	r.at(720)
	r.claim("u1", 2)               // no weight: refused
	r.notarize("u1", "late", 1000) // epoch 7: epoch 3's pool (7003) rolls here
	if got := r.w.read(r.sc, "R3"); got != uint64(7) {
		t.Fatalf("R3 = %v, want 7", got)
	}
	r.at(800)
	r.claim("u1", 7)
	r.drain()
}

// liveness when a payer stops cooperating (regression of the r33 verify finding): before the fix an epoch's floor
// remainder reached the treasury only with the epoch's LAST claim, so a silent payer locked it forever. Now claims
// close at (e + 11) * epoch and Sweep(e), by anyone, once, moves what is left to the treasury.
func TestR33VerifyServiceLivenessSilentPayer(t *testing.T) {
	r := svStart(t, "u1", "u2", "sp", "x")
	r.setMAT("owner")
	r.freeze()
	r.at(200)
	r.notarize("u1", "a", 1000)
	r.notarize("u2", "b", 1000)
	r.notarize("u2", "c", 1000)
	r.sponsor("sp", 1001) // P = 1500 + 1001 = 2501; weights 1000 : 2000
	r.at(300)
	r.claim("u1", 2)
	r.withdrawTreasury("owner", r.m.treasury)
	r.sweep("x", 2) // claims still open: refused
	r.at(1299)
	r.sweep("x", 2) // one height before the deadline: refused
	r.at(1300)
	r.l.do(false, "ClaimRebate", "u1", 0, nil, nil, gtU("e", 2))
	r.sweep("x", 2)
	r.sweep("x", 2) // once
	r.sweep("x", 3) // no such epoch: refused
	r.withdrawTreasury("owner", r.m.treasury)
	if got := r.w.held(r.sc, crypto.ZEROHASH); got != 0 {
		t.Errorf("INVARIANT FAILS (liveness): SC holds %d after Sweep and the treasury withdrawal", got)
	}
	r.l.balances(r.names...)
}

// Sweep is refused when every payer claimed (nothing is left) and for a sponsor-only epoch (it rolls instead)
func TestR33VerifyServiceSweepGuards(t *testing.T) {
	r := svStart(t, "u1", "sp", "x")
	r.setMAT("owner")
	r.freeze()
	r.at(200)
	r.notarize("u1", "a", 1000)
	r.at(300)
	r.claim("u1", 2)
	r.sponsor("sp", 500) // epoch 3, no payer
	r.at(1400)
	r.sweep("x", 2) // every payer claimed
	r.sweep("x", 3) // no payer: refused (the pool waits for its roll)
	r.drain()
}

// bounds (regression of the r33 verify finding): fee 10^12 and rho 100 are inside the documented bounds. Before the
// fix, once a payer's epoch weight wt exceeded 2^64/10^5 = 1.8e14 (185 notarizations of fee 10^12), wt * 100000
// wrapped (paid 15,532,000,000,000 of 200,000,000,000,000). Now the share is wt / (ww / 10^5 + 1) there: never
// above the exact share and at most ~2e-5 below it.
func TestR33VerifyServiceBounds(t *testing.T) {
	r := svStart(t, "u1", "u2")
	r.l.do(true, "SetParams", "owner", 0, nil, nil, svParams(1000000000000, 100, 0, 100, 100)...)
	r.m.fee, r.m.rho, r.m.boost = 1000000000000, 100, 0
	r.setMAT("owner")
	r.freeze()
	r.at(200)
	for i := 0; i < 200; i++ {
		r.notarize("u1", fmt.Sprintf("big-%d", i), r.m.fee)
	}
	r.at(300)
	E := r.m.ep[2]
	want := E.P // the only payer: pool * w / W = pool
	scaled := new(big.Int).SetUint64(E.P / 100000)
	scaled.Mul(scaled, new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(E.w["u1"]), big.NewInt(100000)), new(big.Int).SetUint64(E.W)))
	r.claim("u1", 2)
	got := r.l.recv["u1"]
	t.Logf("pool %d, weight %d: rebate paid %d, exact share %d, the documented 1e-5 scaled share %s", E.P, E.w["u1"], got, want, scaled)
	// the documented rule: exact pool*w/W when it fits, else a 10^-5 scaled share: never above, at most ~2e-5 below
	if got > want || want-got > 2*(want/100000)+1 {
		t.Errorf("INVARIANT FAILS (bounds: Uint64 wrap): 200 x Notarize(fee 10^12, rho 100) by u1 in epoch 2, then ClaimRebate(2): paid %d, rule pool*w/W = %d (scaled share without wrap %s); wt*100000 = %d*100000 wraps at gt_service.bas:90; the %d difference goes to the treasury", got, want, scaled, E.w["u1"], want-got)
	}
	vGas(t, r.w, "gt_service.bas")
}
