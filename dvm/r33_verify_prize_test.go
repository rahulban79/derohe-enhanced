package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_prize.bas (M3 no-loss prize). See r33_verify_common_test.go.
// Liability derived from the contract's variables (checked after every call):
//   treasury + prize<rd> + sum over rounds r and entries j not withdrawn (x == 0):
//   a<r_j> + (drawn<r> ? v<r_j> * rbond : rbond)

import (
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

type pzEntry struct {
	p         string
	a, t, num uint64
	salt      string
	v, x      bool
}

type pzRound struct {
	e                   []*pzEntry
	in                  map[string]bool
	prize, tw, sd, forf uint64
	drawn               bool
	win                 int
}

type pzModel struct {
	rbond, commitw, revealw, maxn, boost, minmat, fee, minp uint64
	frozen                                                  bool
	rd, rs, treasury                                        uint64
	r                                                       map[uint64]*pzRound
	ms, ml                                                  map[string]uint64
	hasMs                                                   map[string]bool
}

type pzRun struct {
	t     *testing.T
	w     *gtWorld
	mat   crypto.Hash
	sc    crypto.Hash
	m     *pzModel
	l     *vLedger
	names []string
	H     uint64
}

func pzStart(t *testing.T, names ...string) *pzRun {
	all := append([]string{"owner", "miner"}, names...)
	w := gtNew(t, all...)
	w.at(100)
	mat := w.install("gt_attest.bas", "owner")
	w.must(mat, "Freeze", "owner", 0, nil)
	sc := w.install("gt_prize.bas", "owner")
	m := &pzModel{rbond: 10000, commitw: 10, revealw: 10, maxn: 32, boost: 100, minmat: 100, fee: 1000, minp: 1000, rs: 100,
		r: map[uint64]*pzRound{0: {in: map[string]bool{}}}, ms: map[string]uint64{}, ml: map[string]uint64{}, hasMs: map[string]bool{}}
	return &pzRun{t: t, w: w, mat: mat, sc: sc, m: m, l: vNewLedger(t, w, sc), names: all, H: 100}
}

func (r *pzRun) at(h uint64) { r.H = h; r.w.at(h) }

func pzLiab(w *gtWorld, sc crypto.Hash) uint64 {
	rbond := w.readU(sc, "rbond")
	rd := w.readU(sc, "rd")
	L := w.readU(sc, "treasury") + w.readU(sc, fmt.Sprintf("prize%d", rd))
	for r := uint64(0); r <= rd; r++ {
		n := w.readU(sc, fmt.Sprintf("n%d", r))
		drawn := w.vExists(sc, fmt.Sprintf("drawn%d", r))
		for j := uint64(0); j < n; j++ {
			q := fmt.Sprintf("%d_%d", r, j)
			if w.readU(sc, "x"+q) != 0 {
				continue
			}
			L += w.readU(sc, "a"+q)
			if !drawn || w.readU(sc, "v"+q) == 1 {
				L += rbond
			}
		}
	}
	return L
}

func (r *pzRun) check() {
	r.t.Helper()
	r.l.conserve(pzLiab(r.w, r.sc), "treasury + current prize + unwithdrawn principals and bonds")
	if got := r.w.readU(r.sc, "treasury"); got != r.m.treasury {
		r.t.Fatalf("treasury %d, model %d", got, r.m.treasury)
	}
	if got := r.w.readU(r.sc, "rd"); got != r.m.rd {
		r.t.Fatalf("rd %d, model %d", got, r.m.rd)
	}
}

func (r *pzRun) freeze(who string) {
	ok := who == "owner" && !r.m.frozen // r33 verify fix: Freeze is one-time
	r.l.do(ok, "Freeze", who, 0, nil, nil)
	if ok {
		r.m.frozen = true
		r.m.rs = r.H
	}
	r.check()
}

func (r *pzRun) setMAT() {
	r.l.do(true, "SetMAT", "owner", 0, nil, nil, gtS("scidhex", hex.EncodeToString(r.mat[:])))
}

func (r *pzRun) fund(s string, dep uint64) {
	m := r.m
	ok := dep > 0
	r.l.do(ok, "Fund", s, dep, nil, nil)
	if ok {
		m.r[m.rd].prize += dep
		r.l.loss[s] += dep
	}
	r.check()
}

func (r *pzRun) enter(u string, dep, num uint64, salt string) {
	m := r.m
	R := m.r[m.rd]
	ok := m.frozen && r.H <= m.rs+m.commitw && uint64(len(R.e)) < m.maxn && dep >= m.rbond+m.fee+m.minp && !R.in[u]
	r.l.do(ok, "Enter", u, dep, nil, nil, gtS("commit", gtCommitNum(num, salt)))
	if ok {
		a := dep - m.rbond - m.fee
		wt := a
		if m.hasMs[u] && m.ms[u] >= m.minmat {
			wt = a * (100 + m.boost) / 100
			m.ml[u] = m.rd
		}
		R.e = append(R.e, &pzEntry{p: u, a: a, t: wt, num: num, salt: salt})
		R.in[u] = true
		m.treasury += m.fee
		r.l.loss[u] += m.fee
	}
	r.check()
}

func (r *pzRun) reveal(u string, j uint64, wrong bool) {
	m := r.m
	R := m.r[m.rd]
	t := m.rs + m.commitw
	ok := r.H > t && r.H <= t+m.revealw && j < uint64(len(R.e))
	var E *pzEntry
	num, salt := uint64(0), "none"
	if j < uint64(len(R.e)) {
		E = R.e[j]
		num, salt = E.num, E.salt
		ok = ok && E.p == u && !E.v && !wrong
	}
	if wrong {
		num++
	}
	r.l.do(ok, "Reveal", u, 0, nil, nil, gtU("j", j), gtU("num", num), gtS("salt", salt))
	if ok {
		E.v = true
		R.sd += E.num
		R.tw += E.t
	}
	r.check()
}

func (r *pzRun) draw(who string) {
	m := r.m
	R := m.r[m.rd]
	ok := m.frozen && r.H > m.rs+m.commitw+m.revealw
	pay := map[string]uint64{}
	if ok {
		for _, E := range R.e {
			if !E.v {
				R.forf += m.rbond
				r.l.loss[E.p] += m.rbond
			}
		}
		m.treasury += R.forf
		R.win = -1
		next := R.prize
		if R.tw > 0 {
			pick := R.sd % R.tw
			var acc uint64
			for j, E := range R.e {
				if !E.v {
					continue
				}
				acc += E.t
				if pick < acc {
					R.win = j
					break
				}
			}
			if R.prize > 0 {
				pay[R.e[R.win].p] = R.prize
			}
			r.l.award[R.e[R.win].p] += R.prize
			next = 0
		}
		R.drawn = true
		m.rd++
		m.rs = r.H
		m.r[m.rd] = &pzRound{in: map[string]bool{}, prize: next}
	}
	r.l.do(ok, "Draw", who, 0, nil, pay)
	if ok && R.win >= 0 {
		if got := r.w.readU(r.sc, fmt.Sprintf("win%d", m.rd-1)); got != uint64(R.win) {
			r.t.Fatalf("round %d winner %d, model (seed %% tw walk) %d", m.rd-1, got, R.win)
		}
	}
	r.check()
}

func (r *pzRun) withdraw(u string, rd, j uint64) {
	m := r.m
	R := m.r[rd]
	ok := R != nil && R.drawn && j < uint64(len(R.e))
	var pay map[string]uint64
	if ok {
		E := R.e[j]
		ok = E.p == u && !E.x
		if ok {
			amt := E.a
			if E.v {
				amt += m.rbond
			}
			pay = map[string]uint64{u: amt}
			E.x = true
		}
	}
	r.l.do(ok, "Withdraw", u, 0, nil, pay, gtU("r", rd), gtU("j", j))
	r.check()
}

func (r *pzRun) stakeMAT(u string, amt uint64) {
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
		m.ml[u] = m.rd
	}
	r.check()
}

func (r *pzRun) unstakeMAT(u string, amt uint64) {
	m := r.m
	ok := m.hasMs[u] && m.rd > m.ml[u] && amt > 0 && amt <= m.ms[u]
	r.l.do(ok, "UnstakeMAT", u, 0, nil, nil, gtU("amount", amt))
	if ok {
		m.ms[u] -= amt
	}
	r.check()
}

func (r *pzRun) withdrawTreasury(who string, amt uint64) {
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

// drain: draw the open round after its windows, every entrant withdraws, the treasury is withdrawn; what stays is
// only the carried prize of a round nobody revealed in (it waits for the next round's winner)
func (r *pzRun) drain() {
	r.t.Helper()
	m := r.m
	r.at(m.rs + m.commitw + m.revealw + 1)
	r.draw("owner")
	for rd := uint64(0); rd < m.rd; rd++ {
		for j, E := range m.r[rd].e {
			if !E.x {
				r.withdraw(E.p, rd, uint64(j))
			}
		}
	}
	if m.treasury > 0 {
		r.withdrawTreasury("owner", m.treasury)
	}
	if got, carry := r.w.held(r.sc, crypto.ZEROHASH), m.r[m.rd].prize; got != carry {
		r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d after every withdrawal, the carried prize is %d", got, carry)
	}
	if carry := m.r[m.rd].prize; carry > 0 { // the carried prize goes to the next round's winner
		last := r.names[len(r.names)-1]
		r.enter(last, m.rbond+m.fee+m.minp, 7, "drain")
		r.at(m.rs + m.commitw + 1)
		r.reveal(last, 0, false)
		r.drain()
		return
	}
	r.l.balances(r.names...)
}

func pzSetParams(rbond, commitw, revealw, maxn, boost, minmat uint64) []rpc.Argument {
	return []rpc.Argument{gtU("rbond", rbond), gtU("commitw", commitw), gtU("revealw", revealw), gtU("maxn", maxn), gtU("boost", boost), gtU("minmat", minmat)}
}

func TestR33VerifyPrizeAccess(t *testing.T) {
	r := pzStart(t, "a", "x")
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.l.do(false, "SetParams", "x", 0, nil, nil, pzSetParams(10000, 10, 10, 32, 100, 100)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, pzSetParams(10000, 10, 10, 65, 100, 100)...)
	r.l.do(false, "SetFees", "x", 0, nil, nil, gtU("fee", 1000), gtU("minp", 1000))
	r.l.do(false, "SetFees", "owner", 0, nil, nil, gtU("fee", 1000), gtU("minp", 0))
	r.l.do(false, "SetMAT", "x", 0, nil, nil, gtS("scidhex", hex.EncodeToString(r.mat[:])))
	r.l.do(true, "SetParams", "owner", 0, nil, nil, pzSetParams(10000, 10, 10, 32, 100, 100)...)
	r.l.do(true, "SetFees", "owner", 0, nil, nil, gtU("fee", 1000), gtU("minp", 1000))
	r.setMAT()
	r.enter("a", 30000, 1, "s") // not frozen
	r.l.do(false, "Draw", "a", 0, nil, nil)
	r.freeze("x")
	r.freeze("owner")
	r.l.do(false, "SetParams", "owner", 0, nil, nil, pzSetParams(10000, 10, 10, 32, 100, 100)...)
	r.l.do(false, "SetFees", "owner", 0, nil, nil, gtU("fee", 1000), gtU("minp", 1000))
	r.l.do(false, "SetMAT", "owner", 0, nil, nil, gtS("scidhex", hex.EncodeToString(r.mat[:])))
	r.withdrawTreasury("x", 1)
	r.check()
	vGas(t, r.w, "gt_prize.bas")
}

func TestR33VerifyPrizeRandom(t *testing.T) {
	for _, seed := range []int64{33, 3301, 3302} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := pzStart(t, "e1", "e2", "e3", "e4", "e5", "sp", "x")
			rng := mrand.New(mrand.NewSource(seed))
			pick := func(s ...string) string { return s[rng.Intn(len(s))] }
			r.setMAT()
			r.w.must(r.mat, "Claim", "e1", gtBond, nil, gtU("from", 90), gtU("upto", 90), gtU("k", 1))
			r.at(121)
			r.w.must(r.mat, "Finalize", "x", 0, nil, gtU("i", 0))
			r.w.refund["e1"] += gtBond // gt_attest returned the bond: outside this contract's ledger
			r.freeze("owner")
			for step := 0; step < 800; step++ {
				r.at(r.H + uint64(rng.Intn(3)))
				m := r.m
				R := m.r[m.rd]
				switch a := rng.Intn(100); {
				case a < 25:
					dep := m.rbond + m.fee + m.minp + uint64(rng.Intn(60000))
					if rng.Intn(12) == 0 {
						dep = m.rbond + m.fee + m.minp - 1
					}
					r.enter(pick("e1", "e2", "e3", "e4", "e5", "owner"), dep, rng.Uint64(), fmt.Sprintf("s%d", rng.Intn(99)))
				case a < 45:
					if n := len(R.e); n > 0 {
						j := uint64(rng.Intn(n + 1))
						u := pick("e1", "e2", "e3", "e4", "e5", "owner")
						if j < uint64(n) && rng.Intn(5) > 0 {
							u = R.e[j].p
						}
						r.reveal(u, j, rng.Intn(12) == 0)
					}
				case a < 52:
					r.fund(pick("sp", "x"), uint64(rng.Intn(8000)))
				case a < 64:
					r.draw(pick("x", "sp", "e2"))
				case a < 84:
					if m.rd > 0 {
						rd := uint64(rng.Intn(int(m.rd) + 1))
						if n := len(m.r[rd].e); n > 0 {
							j := uint64(rng.Intn(n))
							u := m.r[rd].e[j].p
							if rng.Intn(6) == 0 {
								u = pick("e1", "x")
							}
							r.withdraw(u, rd, j)
						}
					}
				case a < 89:
					r.stakeMAT("e1", uint64(rng.Intn(3))*50)
				case a < 93:
					amt := uint64(1 + rng.Intn(150))
					if rng.Intn(2) == 0 && m.ms["e1"] > 0 {
						amt = m.ms["e1"]
					}
					r.unstakeMAT(pick("e1", "e2"), amt)
				case a < 97:
					r.withdrawTreasury(pick("owner", "x"), uint64(1+rng.Intn(int(m.treasury+2))))
				default:
					switch rng.Intn(3) {
					case 0:
						r.l.do(false, "SetParams", "owner", 0, nil, nil, pzSetParams(10000, 10, 10, 32, 100, 100)...)
					case 1:
						r.l.do(false, "SetFees", "owner", 0, nil, nil, gtU("fee", 1000), gtU("minp", 1000))
					default:
						r.l.do(false, "Initialize", pick("owner", "x"), 0, nil, nil)
					}
					r.check()
				}
			}
			won := 0
			for rd := uint64(0); rd < r.m.rd; rd++ {
				if r.m.r[rd].win >= 0 && r.m.r[rd].tw > 0 {
					won++
				}
			}
			t.Logf("seed %d: %d calls, %d rounds drawn (%d with a winner), treasury %d, height %d", seed, r.l.calls, r.m.rd, won, r.m.treasury, r.H)
			r.drain()
			vGas(t, r.w, "gt_prize.bas")
		})
	}
}

// Regression of the r33 verify finding: Freeze was not one-time; every later Freeze reset rs = BLOCK_HEIGHT(),
// re-opening the commit phase after the others revealed (a Sybil then chose its number and won with certainty), and
// repeated Freeze calls postponed Draw forever. Now a second Freeze is refused, the round keeps its windows, a late
// entrant is refused, and Draw and every Withdraw go through.
func TestR33VerifyPrizeRefreeze(t *testing.T) {
	r := pzStart(t, "a", "b", "sybil", "sp", "x")
	r.freeze("owner") // rs = 100
	r.fund("sp", 50000)
	r.enter("a", 100000+r.m.rbond+r.m.fee, 11111, "sa")
	r.enter("b", 100000+r.m.rbond+r.m.fee, 22222, "sb")
	r.at(111)
	r.reveal("a", 0, false)
	r.reveal("b", 1, false)
	r.freeze("owner") // refused: rs stays 100
	if got := r.w.readU(r.sc, "rs"); got != 100 {
		t.Fatalf("rs %d, want 100", got)
	}
	R := r.m.r[0]
	n := (R.tw) + R.tw + 1000 - R.sd%(R.tw+1000)
	r.enter("sybil", 1000+r.m.rbond+r.m.fee, n, "rig") // the commit phase is over: refused
	r.at(121)
	r.freeze("owner") // still refused right before the draw height
	r.draw("x")
	if R.win != 0 && R.win != 1 {
		t.Fatalf("winner %d", R.win)
	}
	r.enter("a", 100000+r.m.rbond+r.m.fee, 3, "x3")
	for k := 0; k < 5; k++ {
		r.freeze("owner") // every repeat refused
	}
	r.at(r.m.rs + r.m.commitw + 1)
	r.reveal("a", 0, false)
	r.at(r.m.rs + r.m.commitw + r.m.revealw + 1)
	r.draw("x") // round 1 is drawn on time
	r.drain()
}

// bounds: maxn = 64 (the documented maximum) entrants, all revealing, and all withholding, at the documented
// maxima rbond = fee = minp = 10^12, boost 1000; Draw stays below the gas limits
func TestR33VerifyPrizeBounds(t *testing.T) {
	for _, revealAll := range []bool{true, false} {
		t.Run(fmt.Sprintf("reveal=%v", revealAll), func(t *testing.T) {
			names := []string{}
			for i := 0; i < 65; i++ {
				names = append(names, fmt.Sprintf("p%02d", i))
			}
			r := pzStart(t, names...)
			r.l.do(true, "SetParams", "owner", 0, nil, nil, pzSetParams(1000000000000, 10, 10, 64, 1000, 100)...)
			r.l.do(true, "SetFees", "owner", 0, nil, nil, gtU("fee", 1000000000000), gtU("minp", 1000000000000))
			r.m.rbond, r.m.maxn, r.m.boost, r.m.fee, r.m.minp = 1000000000000, 64, 1000, 1000000000000, 1000000000000
			r.freeze("owner")
			r.fund("owner", 123456789)
			for i, n := range names {
				r.enter(n, 3000000000000+uint64(i), uint64(i)*0x9e3779b97f4a7c15, n) // the 65th is refused
			}
			r.at(111)
			if revealAll {
				for i, n := range names[:64] {
					r.reveal(n, uint64(i), false)
				}
			}
			r.at(121)
			r.draw("owner")
			r.drain()
			g := r.w.gas["gt_prize.bas:Draw"]
			t.Logf("Draw with 64 entries (reveal=%v): compute %d, storage %d", revealAll, g[0], g[1])
			vGas(t, r.w, "gt_prize.bas")
		})
	}
}
