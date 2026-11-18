package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_attest.bas (M1, MAT). See r33_verify_common_test.go.
// Liability derived from the contract's variables (checked after every call):
//   treasury + sum st<j>
//   + per claim c<i>: s 0 -> b; s 1 -> b * (1 + nx) + sum of juror escrows c<i>w<j>;
//     s 2/3/4 with a dispute (c<i>cwin exists) and nz < nj -> sum over unclaimed jurors of what ClaimJuror will give
//     back or pay (w + pay, w, or w - cut) + the residual the last ClaimJuror sweeps (pool + all cuts - all pays).

import (
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

type atJuror struct {
	w, vote uint64
	salt    string
	rev     bool
	claimed bool
}

type atClaim struct {
	m                         string
	from, upto, k, b, h       uint64
	s                         int
	xs                        []string
	yes, no, cw               uint64
	jur                       []string
	j                         map[string]*atJuror
	win                       uint64
	pool, pot, cwin, cuts, pd uint64
	nz                        int
}

type atModel struct {
	bond, reward, window, commitw, revealw, maxmb, maxspan, slash, minstake, maxstake, maxch uint64
	claims                                                                                   []*atClaim
	st                                                                                       map[string]uint64
	hasSt                                                                                    map[string]bool
	lc                                                                                       map[string]uint64
	hasLc                                                                                    map[string]bool
	treasury                                                                                 uint64
	minted                                                                                   map[string]uint64
}

func atNewModel() *atModel {
	return &atModel{bond: 100000, reward: 100, window: 20, commitw: 10, revealw: 10, maxmb: 10, maxspan: 1000, slash: 10,
		minstake: 100000, maxstake: 1000000000, maxch: 8, st: map[string]uint64{}, hasSt: map[string]bool{},
		lc: map[string]uint64{}, hasLc: map[string]bool{}, minted: map[string]uint64{}}
}

// atPay is ClaimJuror's payout formula (gt_attest.bas:150-170)
func atPay(x, w, cwin uint64) uint64 {
	if x > math.MaxUint64/w {
		return x/1000000*(w*1000000/cwin) + x%1000000*(w*1000000/cwin)/1000000
	}
	return x * w / cwin
}

func atCut(w, slash uint64) uint64 { return (w*slash + 99) / 100 }

// atLiab computes the liability from the stored variables only.
func atLiab(t *testing.T, w *gtWorld, sc crypto.Hash, names []string) uint64 {
	t.Helper()
	L := w.readU(sc, "treasury")
	for _, n := range names {
		if v, ok := w.vOptU(sc, "st"+w.raw(n)); ok {
			L += v
		}
	}
	slash := w.readU(sc, "slash")
	nc := w.readU(sc, "nc")
	for i := uint64(0); i < nc; i++ {
		p := fmt.Sprintf("c%d", i)
		s, b, nx := w.readU(sc, p+"s"), w.readU(sc, p+"b"), w.readU(sc, p+"nx")
		switch {
		case s == 0:
			L += b
		case s == 1:
			L += b * (1 + nx)
			for _, n := range names {
				if v, ok := w.vOptU(sc, p+"w"+w.raw(n)); ok {
					L += v
				}
			}
		default:
			if !w.vExists(sc, p+"cwin") || w.readU(sc, p+"nz") == w.readU(sc, p+"nj") {
				continue
			}
			win, pot, cwin, pool := w.readU(sc, p+"win"), w.readU(sc, p+"pot"), w.readU(sc, p+"cwin"), w.readU(sc, p+"pool")
			var owed, pays, cuts uint64
			for _, n := range names {
				if !w.vExists(sc, p+"v"+w.raw(n)) {
					continue
				}
				wv := w.readU(sc, p+"w"+w.raw(n))
				r, rev := w.vOptU(sc, p+"r"+w.raw(n))
				var o uint64
				switch {
				case rev && win == 2:
					o = wv
				case rev && r == win:
					pay := atPay(pot, wv, cwin)
					pays += pay
					o = wv + pay
				default:
					c := atCut(wv, slash)
					cuts += c
					o = wv - c
				}
				if !w.vExists(sc, p+"z"+w.raw(n)) {
					owed += o
				}
			}
			if pool+cuts < pays {
				t.Fatalf("claim %d: pays %d exceed pool %d + cuts %d (the last ClaimJuror would wrap the treasury)", i, pays, pool, cuts)
			}
			L += owed + pool + cuts - pays
		}
	}
	return L
}

type atRun struct {
	t     *testing.T
	w     *gtWorld
	sc    crypto.Hash
	m     *atModel
	l     *vLedger
	names []string
	H     uint64
}

func atStart(t *testing.T, names ...string) *atRun {
	all := append([]string{"owner"}, names...)
	w := gtNew(t, all...)
	w.at(100)
	sc := w.install("gt_attest.bas", "owner")
	return &atRun{t: t, w: w, sc: sc, m: atNewModel(), l: vNewLedger(t, w, sc), names: all, H: 100}
}

func (r *atRun) at(h uint64) { r.H = h; r.w.at(h) }

func (r *atRun) check() {
	r.t.Helper()
	r.l.conserve(atLiab(r.t, r.w, r.sc, r.names), "treasury + stakes + open bonds + escrows + unclaimed juror dues")
	if got := r.w.readU(r.sc, "treasury"); got != r.m.treasury {
		r.t.Fatalf("treasury %d, model %d", got, r.m.treasury)
	}
}

func (r *atRun) stake(j string, amt uint64) {
	m := r.m
	ok := amt > 0 && m.st[j]+amt <= m.maxstake
	r.l.do(ok, "Stake", j, amt, nil, nil)
	if ok {
		m.st[j] += amt
		m.hasSt[j] = true
	}
	r.check()
}

func (r *atRun) unstake(j string, amt uint64) {
	m := r.m
	ok := m.hasSt[j] && amt > 0 && amt <= m.st[j]
	var pay map[string]uint64
	if ok {
		pay = map[string]uint64{j: amt}
	}
	r.l.do(ok, "Unstake", j, 0, nil, pay, gtU("amount", amt))
	if ok {
		m.st[j] -= amt
	}
	r.check()
}

func (r *atRun) claim(miner string, from, upto, k, dep uint64) bool {
	m := r.m
	ok := upto >= from && upto-from < m.maxspan && upto < r.H && k > 0 && k <= (upto-from+1)*m.maxmb &&
		(!m.hasLc[miner] || from > m.lc[miner]) && dep == k*m.bond
	r.l.do(ok, "Claim", miner, dep, nil, nil, gtU("from", from), gtU("upto", upto), gtU("k", k))
	if ok {
		m.claims = append(m.claims, &atClaim{m: miner, from: from, upto: upto, k: k, b: dep, h: r.H, j: map[string]*atJuror{}})
		m.lc[miner], m.hasLc[miner] = upto, true
	}
	r.check()
	return ok
}

func (c *atClaim) isX(n string) bool {
	for _, x := range c.xs {
		if x == n {
			return true
		}
	}
	return false
}

func (r *atRun) challenge(x string, i, dep uint64) {
	m := r.m
	ok := i < uint64(len(m.claims))
	var c *atClaim
	if ok {
		c = m.claims[i]
		ok = c.s <= 1 && r.H <= c.h+m.window && dep == c.b && x != c.m && !c.isX(x) && c.j[x] == nil && uint64(len(c.xs)) < m.maxch
	}
	r.l.do(ok, "Challenge", x, dep, nil, nil, gtU("i", i))
	if ok {
		c.s = 1
		c.xs = append(c.xs, x)
	}
	r.check()
}

func (r *atRun) commit(j string, i, vote uint64, salt string) {
	m := r.m
	ok := i < uint64(len(m.claims))
	var c *atClaim
	if ok {
		c = m.claims[i]
		ok = c.s == 1 && r.H <= c.h+m.window+m.commitw && m.hasSt[j] && m.st[j] > 0 && m.st[j] >= m.minstake &&
			j != c.m && !c.isX(j) && c.j[j] == nil
	}
	r.l.do(ok, "CommitVote", j, 0, nil, nil, gtU("i", i), gtS("h", gtCommitVote(i, vote, salt, r.w.gtAuditAddr(j))))
	if ok {
		c.j[j] = &atJuror{w: m.st[j], vote: vote, salt: salt}
		c.jur = append(c.jur, j)
		c.cw += m.st[j]
		m.st[j] = 0
	}
	r.check()
}

func (r *atRun) reveal(j string, i uint64, wrongSalt bool) {
	m := r.m
	c := m.claims[i]
	jj := c.j[j]
	if jj == nil {
		r.l.do(false, "RevealVote", j, 0, nil, nil, gtU("i", i), gtU("vote", 0), gtS("salt", "none"))
		return
	}
	t := c.h + m.window + m.commitw
	ok := c.s == 1 && r.H > t && r.H <= t+m.revealw && !jj.rev && !wrongSalt
	salt := jj.salt
	if wrongSalt {
		salt += "x"
	}
	r.l.do(ok, "RevealVote", j, 0, nil, nil, gtU("i", i), gtU("vote", jj.vote), gtS("salt", salt))
	if ok {
		jj.rev = true
		if jj.vote == 1 {
			c.yes += jj.w
		} else {
			c.no += jj.w
		}
	}
	r.check()
}

func (r *atRun) finalize(caller string, i uint64) {
	m := r.m
	ok := i < uint64(len(m.claims))
	var c *atClaim
	if ok {
		c = m.claims[i]
		switch c.s {
		case 0:
			ok = r.H > c.h+m.window
		case 1:
			ok = r.H > c.h+m.window+m.commitw+m.revealw
		default:
			ok = false
		}
	}
	pay := map[string]uint64{}
	mint := false
	if ok {
		n := uint64(len(c.xs))
		switch {
		case c.s == 0:
			pay[c.m] = c.b
			mint = true
			c.s = 2
		case c.yes > c.no:
			lb := n * c.b
			half := lb / 2
			pay[c.m] = c.b + half
			r.l.award[c.m] += half
			for _, x := range c.xs {
				r.l.loss[x] += c.b
			}
			c.win, c.cwin, c.pool = 1, c.yes, lb-half
			c.pot = c.pool + (c.cw-c.yes)*m.slash/100
			mint = true
			c.s = 2
		case c.no > c.yes:
			half := c.b / 2
			each := half / n
			for _, x := range c.xs {
				pay[x] = c.b + each
				r.l.award[x] += each
			}
			r.l.loss[c.m] += c.b
			m.treasury += half - each*n
			c.win, c.cwin, c.pool = 0, c.no, c.b-half
			c.pot = c.pool + (c.cw-c.no)*m.slash/100
			c.s = 3
		default:
			pay[c.m] = c.b
			for _, x := range c.xs {
				pay[x] = c.b
			}
			c.win, c.cwin, c.pool, c.pot = 2, 0, 0, 0
			c.s = 4
		}
		if mint {
			m.minted[c.m] += c.k * m.reward
		}
	}
	r.l.do(ok, "Finalize", caller, 0, nil, pay, gtU("i", i))
	r.check()
}

func (r *atRun) claimJuror(j string, i uint64) {
	ok, pay := r.jclaim(j, i)
	r.l.do(ok, "ClaimJuror", j, 0, nil, pay, gtU("i", i))
	r.check()
}

// claimJurorFor: anyone settles juror number k of claim i after h + window + commitw + 11 * revealw (gt_attest
// ClaimJurorFor, r33 verify fix): exactly what that juror's own ClaimJuror would do, paid to the juror
func (r *atRun) claimJurorFor(caller string, i, k uint64) {
	m := r.m
	ok := i < uint64(len(m.claims))
	var pay map[string]uint64
	if ok {
		c := m.claims[i]
		ok = k < uint64(len(c.jur)) && r.H > c.h+m.window+m.commitw+11*m.revealw
		if ok {
			ok, pay = r.jclaim(c.jur[k], i)
		}
	}
	r.l.do(ok, "ClaimJurorFor", caller, 0, nil, pay, gtU("i", i), gtU("k", k))
	r.check()
}

// jclaim is the model of gt_attest jclaim(i, who): it predicts success and applies the effect
func (r *atRun) jclaim(j string, i uint64) (bool, map[string]uint64) {
	m := r.m
	ok := i < uint64(len(m.claims))
	var c *atClaim
	var jj *atJuror
	if ok {
		c = m.claims[i]
		jj = c.j[j]
		ok = c.s >= 2 && len(c.xs) > 0 && jj != nil && !jj.claimed
	}
	var pay map[string]uint64
	if ok {
		switch {
		case jj.rev && c.win == 2:
			m.st[j] += jj.w
		case jj.rev && jj.vote == c.win:
			p := atPay(c.pot, jj.w, c.cwin)
			pay = map[string]uint64{j: p}
			r.l.award[j] += p
			c.pd += p
			m.st[j] += jj.w
		default:
			cut := atCut(jj.w, m.slash)
			r.l.loss[j] += cut
			c.cuts += cut
			m.st[j] += jj.w - cut
		}
		jj.claimed = true
		c.nz++
		if c.nz == len(c.jur) {
			m.treasury += c.pool + c.cuts - c.pd
		}
	}
	return ok, pay
}

func (r *atRun) withdrawTreasury(who string, amt uint64) {
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

func atParams(bond, reward, window, commitw, revealw, maxmb, slash, minstake uint64) []rpc.Argument {
	return []rpc.Argument{gtU("bond", bond), gtU("reward", reward), gtU("window", window), gtU("commitw", commitw),
		gtU("revealw", revealw), gtU("maxmb", maxmb), gtU("slash", slash), gtU("minstake", minstake)}
}

// drain: after every documented window, every claim can be finalized, every juror claimed, every stake and the
// treasury withdrawn, and the SC ends at 0 (liveness; nothing owed by nobody).
func (r *atRun) drain() {
	r.t.Helper()
	m := r.m
	r.at(r.H + m.window + m.commitw + m.revealw + 1)
	for i, c := range m.claims {
		if c.s <= 1 {
			r.finalize("x", uint64(i))
		}
	}
	for i, c := range m.claims {
		for _, j := range c.jur {
			if !c.j[j].claimed {
				r.claimJuror(j, uint64(i))
			}
		}
	}
	for _, n := range r.names {
		if m.st[n] > 0 {
			r.unstake(n, m.st[n])
		}
	}
	if m.treasury > 0 {
		r.withdrawTreasury("owner", m.treasury)
	}
	if got := r.w.held(r.sc, crypto.ZEROHASH); got != 0 {
		r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d after every participant withdrew", got)
	}
	r.l.balances(r.names...)
	for n, v := range m.minted {
		r.w.tokenIs(r.sc, n, v)
	}
	if got := r.w.readU(r.sc, "minted"); got != func() (s uint64) {
		for _, v := range m.minted {
			s += v
		}
		return
	}() {
		r.t.Errorf("minted %d differs from the model", got)
	}
}

// access control, one-time Initialize, Freeze
func TestR33VerifyAttestAccess(t *testing.T) {
	r := atStart(t, "m1", "x")
	w, sc := r.w, r.sc
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.l.do(false, "SetParams", "x", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 10, 10, 100000)...)
	r.l.do(false, "Freeze", "x", 0, nil, nil)
	r.l.do(false, "WithdrawTreasury", "x", 0, nil, nil, gtU("amount", 1))
	r.l.do(false, "Claim", "m1", 100000, nil, nil, gtU("from", 1), gtU("upto", 2), gtU("k", 1)) // not frozen
	r.l.do(true, "SetParams", "owner", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 10, 10, 100000)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, atParams(1000000000001, 100, 20, 10, 10, 10, 10, 100000)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 101, 10, 100000)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 10, 10, 1000000001)...)
	r.l.do(true, "Freeze", "owner", 0, nil, nil)
	r.l.do(false, "Freeze", "owner", 0, nil, nil) // one-time (r33 verify fix)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 10, 10, 100000)...)
	if w.readU(sc, "frozen") != 1 || w.read(sc, "owner") != w.raw("owner") {
		t.Fatalf("freeze/owner state")
	}
	r.check()
	vGas(t, w, "gt_attest.bas")
}

// table: every dispute outcome with 1..3 challengers and several juror behaviours; drain to 0 afterwards
func TestR33VerifyAttestOutcomes(t *testing.T) {
	type jv struct {
		name   string
		stake  uint64
		vote   uint64
		reveal bool
	}
	cases := []struct {
		name string
		nx   int
		jur  []jv
	}{
		{"unchallenged", 0, nil},
		{"upheld 1x", 1, []jv{{"j1", 300000, 1, true}, {"j2", 100000, 0, true}, {"j3", 200000, 1, false}}},
		{"rejected 1x", 1, []jv{{"j1", 300000, 0, true}, {"j2", 100000, 1, true}, {"j3", 200000, 0, true}}},
		{"rejected 3x odd", 3, []jv{{"j1", 333333, 0, true}, {"j2", 100001, 1, true}}},
		{"upheld 3x", 3, []jv{{"j1", 123457, 1, true}, {"j2", 765431, 1, true}, {"j3", 100000, 0, false}, {"j4", 999999, 0, true}}},
		{"undecided tie", 2, []jv{{"j1", 200000, 1, true}, {"j2", 200000, 0, true}, {"j3", 150000, 1, false}}},
		{"undecided no reveal", 2, []jv{{"j1", 200000, 1, false}, {"j2", 300000, 0, false}}},
		{"challenged no jurors", 2, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := atStart(t, "m1", "c1", "c2", "c3", "j1", "j2", "j3", "j4", "x")
			r.l.do(true, "Freeze", "owner", 0, nil, nil)
			for _, j := range tc.jur {
				r.stake(j.name, j.stake)
			}
			r.at(200)
			k := uint64(3)
			r.claim("m1", 150, 160, k, k*r.m.bond)
			for i := 0; i < tc.nx; i++ {
				r.challenge(fmt.Sprintf("c%d", i+1), 0, k*r.m.bond)
			}
			r.challenge("m1", 0, k*r.m.bond) // self challenge refused
			if tc.nx > 0 {
				r.challenge("c1", 0, k*r.m.bond) // twice refused
			}
			for _, j := range tc.jur {
				r.commit(j.name, 0, j.vote, "s"+j.name)
				r.commit(j.name, 0, j.vote, "s"+j.name) // one vote per juror
			}
			r.unstake("j1", 1) // escrowed: refused while the vote is open
			r.at(230)
			r.reveal("j1", 0, false) // commit phase: refused
			r.at(231)
			for _, j := range tc.jur {
				if j.reveal {
					r.reveal(j.name, 0, true)
					r.reveal(j.name, 0, false)
					r.reveal(j.name, 0, false) // twice refused
				}
			}
			r.at(240)
			r.finalize("x", 0)
			r.at(241)
			r.finalize("x", 0)
			r.finalize("x", 0) // one-time
			for _, j := range tc.jur {
				r.claimJuror(j.name, 0)
				r.claimJuror(j.name, 0) // one-time
			}
			r.drain()
		})
	}
}

// randomized: 700 calls by 10 signers at increasing heights, fixed seed; model-predicted success/failure, exact
// payouts and the liability identity after every call; then drain
func TestR33VerifyAttestRandom(t *testing.T) {
	for _, seed := range []int64{33, 3301, 3302} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := atStart(t, "m1", "m2", "c1", "c2", "c3", "j1", "j2", "j3", "j4", "x")
			r.l.do(true, "Freeze", "owner", 0, nil, nil)
			rng := mrand.New(mrand.NewSource(seed))
			pick := func(s ...string) string { return s[rng.Intn(len(s))] }
			r.at(200)
			nextFrom := map[string]uint64{"m1": 10, "m2": 10, "c1": 10}
			for step := 0; step < 700; step++ {
				r.at(r.H + uint64(rng.Intn(4)))
				nc := uint64(len(r.m.claims))
				ri := func() uint64 {
					if nc == 0 {
						return 0
					}
					if rng.Intn(10) == 0 {
						return nc // out of range
					}
					if rng.Intn(10) < 7 && nc > 3 { // mostly the recent claims, so disputes run to every outcome
						return nc - 1 - uint64(rng.Intn(3))
					}
					return uint64(rng.Intn(int(nc)))
				}
				switch a := rng.Intn(100); {
				case a < 10:
					r.stake(pick("j1", "j2", "j3", "j4", "c1"), uint64(50000+rng.Intn(300000)))
				case a < 15:
					j := pick("j1", "j2", "j3", "j4", "x")
					amt := uint64(1 + rng.Intn(400000))
					if rng.Intn(2) == 0 && r.m.st[j] > 0 {
						amt = r.m.st[j]
					}
					r.unstake(j, amt)
				case a < 27:
					mn := pick("m1", "m2", "c1")
					from := nextFrom[mn] + uint64(rng.Intn(3))
					upto := from + uint64(rng.Intn(5))
					k := uint64(1 + rng.Intn(3))
					dep := k * r.m.bond
					if rng.Intn(8) == 0 {
						dep += 1
					}
					if r.claim(mn, from, upto, k, dep) {
						nextFrom[mn] = upto + 1
					} else if rng.Intn(3) == 0 {
						nextFrom[mn] = upto + 1
					}
				case a < 40:
					i := ri()
					dep := r.m.bond
					if i < nc {
						dep = r.m.claims[i].b
					}
					if rng.Intn(10) == 0 {
						dep--
					}
					r.challenge(pick("c1", "c2", "c3", "m2", "j1"), i, dep)
				case a < 55:
					i := ri()
					r.commit(pick("j1", "j2", "j3", "j4", "c2"), i, uint64(rng.Intn(2)), fmt.Sprintf("s%d", rng.Intn(1000)))
				case a < 68:
					if i := ri(); i < nc {
						r.reveal(pick("j1", "j2", "j3", "j4"), i, rng.Intn(10) == 0)
					}
				case a < 80:
					r.finalize(pick("x", "owner", "j1"), ri())
				case a < 92:
					if nc > 0 {
						if rng.Intn(3) == 0 {
							r.claimJurorFor(pick("x", "owner", "j1"), ri(), uint64(rng.Intn(5)))
						} else {
							r.claimJuror(pick("j1", "j2", "j3", "j4", "c1"), ri())
						}
					}
				case a < 95:
					amt := uint64(1 + rng.Intn(int(r.m.treasury+2)))
					r.withdrawTreasury(pick("owner", "owner", "x"), amt)
				default: // setters after Freeze, outsiders
					switch rng.Intn(4) {
					case 0:
						r.l.do(false, "SetParams", "owner", 0, nil, nil, atParams(100000, 100, 20, 10, 10, 10, 10, 100000)...)
					case 1:
						r.l.do(false, "Initialize", pick("owner", "x"), 0, nil, nil)
					case 2:
						r.l.do(false, "Freeze", "owner", 0, nil, nil) // r33 fix: Freeze is one-time
					default:
						r.l.do(false, "Freeze", "x", 0, nil, nil)
					}
					r.check()
				}
			}
			outcomes := map[int]int{}
			for _, c := range r.m.claims {
				outcomes[c.s]++
			}
			t.Logf("seed %d: %d calls, %d claims, status counts %v, treasury %d, final height %d", seed, r.l.calls, len(r.m.claims), outcomes, r.m.treasury, r.H)
			r.drain()
			vGas(t, r.w, "gt_attest.bas")
		})
	}
}

// Liveness when a juror stops cooperating (regression of the r33 verify finding): before the fix the dispute's
// treasury residual reached the treasury only with the LAST juror's own ClaimJuror, so a silent juror locked it
// forever. ClaimJurorFor lets anyone settle that juror after h + window + commitw + 11 * revealw; the juror's pot
// share goes to the juror, its stake stays the juror's, and the contract then drains to 0.
func TestR33VerifyAttestLivenessSilentJuror(t *testing.T) {
	cases := []struct {
		name   string
		votes  map[string]uint64
		reveal map[string]bool
	}{
		// rejected 2:1; the silent juror j3 voted with the minority: residual = ceil cut - floor slash share = dust
		{"rejected, incoherent juror silent", map[string]uint64{"j1": 0, "j2": 0, "j3": 1}, map[string]bool{"j1": true, "j2": true, "j3": true}},
		// tie 1:1 (undecided); j3 never revealed and never claims: its whole slash (10 %) is the treasury's
		{"undecided, unrevealed juror silent", map[string]uint64{"j1": 0, "j2": 1, "j3": 1}, map[string]bool{"j1": true, "j2": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := atStart(t, "m1", "c1", "j1", "j2", "j3", "x")
			r.l.do(true, "Freeze", "owner", 0, nil, nil)
			stake := map[string]uint64{"j1": 300001, "j2": 300001, "j3": 200007}
			if tc.name[0] == 'r' {
				stake["j2"] = 100003
			}
			for _, j := range []string{"j1", "j2", "j3"} {
				r.stake(j, stake[j])
			}
			r.at(200)
			b := 4 * r.m.bond
			r.claim("m1", 190, 199, 4, b)
			r.challenge("c1", 0, b)
			for _, j := range []string{"j1", "j2", "j3"} {
				r.commit(j, 0, tc.votes[j], "s"+j)
			}
			r.at(231)
			for _, j := range []string{"j1", "j2", "j3"} {
				if tc.reveal[j] {
					r.reveal(j, 0, false)
				}
			}
			r.at(241)
			r.finalize("x", 0)
			r.claimJuror("j1", 0)
			r.claimJuror("j2", 0)
			for _, n := range []string{"j1", "j2"} {
				if r.m.st[n] > 0 {
					r.unstake(n, r.m.st[n])
				}
			}
			if r.m.treasury > 0 {
				r.withdrawTreasury("owner", r.m.treasury)
			}
			// j3 never calls ClaimJuror: the treasury share stays put until the ClaimJurorFor deadline
			c := r.m.claims[0]
			dl := c.h + r.m.window + r.m.commitw + 11*r.m.revealw
			r.claimJurorFor("x", 0, 0) // j1 already claimed: refused
			r.claimJurorFor("x", 0, 2) // before the deadline: refused
			r.claimJurorFor("x", 0, 3) // no juror 3: refused
			r.at(dl)
			r.claimJurorFor("x", 0, 2) // still refused at the deadline height itself
			r.at(dl + 1)
			r.claimJurorFor("x", 0, 2)     // anyone settles j3
			r.claimJurorFor("owner", 0, 2) // once
			r.l.do(false, "ClaimJuror", "j3", 0, nil, nil, gtU("i", 0))
			if r.m.treasury == 0 {
				t.Fatalf("the residual did not reach the treasury")
			}
			t.Logf("treasury residual released by ClaimJurorFor: %d", r.m.treasury)
			r.withdrawTreasury("owner", r.m.treasury)
			r.unstake("j3", r.m.st["j3"]) // j3's stake stayed its own
			if got := r.w.held(r.sc, crypto.ZEROHASH); got != 0 {
				t.Errorf("INVARIANT FAILS (liveness): SC holds %d after ClaimJurorFor and every withdrawal", got)
			}
			r.l.balances(r.names...)
		})
	}
}

// bounds: the documented maxima (bond 10^12, maxmb 100, maxspan 1000 -> b = 10^17; 8 challengers; reward 10^6;
// stakes up to maxstake 10^9) never wrap, the scaled juror share never exceeds the exact share, and Finalize with
// maxch challengers stays far below the gas limits
func TestR33VerifyAttestBounds(t *testing.T) {
	for _, outcome := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("vote%d", outcome), func(t *testing.T) {
			names := []string{"m1", "j1", "j2", "j3", "j4", "x"}
			for i := 1; i <= 9; i++ {
				names = append(names, fmt.Sprintf("c%d", i))
			}
			r := atStart(t, names...)
			r.l.do(true, "SetParams", "owner", 0, nil, nil, atParams(1000000000000, 1000000, 1000000, 1000000, 1000000, 100, 100, 1000000000)...)
			r.m.bond, r.m.reward, r.m.window, r.m.commitw, r.m.revealw, r.m.maxmb, r.m.slash, r.m.minstake = 1000000000000, 1000000, 1000000, 1000000, 1000000, 100, 100, 1000000000
			r.l.do(true, "Freeze", "owner", 0, nil, nil)
			for _, j := range []string{"j1", "j2", "j3", "j4"} {
				r.stake(j, 1000000000)
			}
			r.at(2000)
			k := uint64(1000 * 100)
			b := k * r.m.bond
			if !r.claim("m1", 0, 999, k, b) {
				t.Fatalf("max claim refused")
			}
			for i := 1; i <= 9; i++ {
				r.challenge(fmt.Sprintf("c%d", i), 0, b) // the 9th is refused (maxch 8)
			}
			r.commit("j1", 0, outcome, "1")
			r.commit("j2", 0, outcome, "2")
			r.commit("j3", 0, outcome, "3")
			r.commit("j4", 0, 1-outcome, "4")
			c := r.m.claims[0]
			r.at(c.h + r.m.window + r.m.commitw + 1)
			for _, j := range []string{"j1", "j2", "j3", "j4"} {
				r.reveal(j, 0, false)
			}
			r.at(c.h + r.m.window + r.m.commitw + r.m.revealw + 1)
			r.finalize("x", 0)
			exact := new(big.Int)
			for _, j := range []string{"j1", "j2", "j3"} {
				e := new(big.Int).Mul(new(big.Int).SetUint64(c.pot), new(big.Int).SetUint64(c.j[j].w))
				e.Div(e, new(big.Int).SetUint64(c.cwin))
				got := atPay(c.pot, c.j[j].w, c.cwin)
				if new(big.Int).SetUint64(got).Cmp(e) > 0 {
					t.Errorf("INVARIANT FAILS (bounds): scaled juror pay %d > exact %s", got, e)
				}
				exact.Add(exact, e)
			}
			t.Logf("b %d, pot %d, exact coherent pays %s", b, c.pot, exact)
			r.drain()
			vGas(t, r.w, "gt_attest.bas")
		})
	}
}
