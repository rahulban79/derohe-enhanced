package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_audit.bas (R32a audit bounty). See r33_verify_common_test.go.
// Liability derived from the contract's variables (checked after every call):
//   carry + per round a: st 0, to 0 -> bounty + n * bond;
//   st 0, to 1 (timed out) -> (sbx ? 0 : bounty) + bond per entrant not withdrawn;
//   st 1 (settled) -> (sbx ? 0 : sb) + cr per entrant not withdrawn.

import (
	"fmt"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

type auEntrant struct {
	who, ans string
	v, x     bool
	cr       uint64
}

type auRound struct {
	fund, cin, bounty, start uint64
	ans, salt                string
	sa                       bool
	e                        []*auEntrant
	in                       map[string]bool
	st, to, sbx, disp        bool
	md, nw, sb, share        uint64
}

type auModel struct {
	bond, commitw, revealw, maxn, tmo uint64
	frozen                            bool
	carry                             uint64
	r                                 []*auRound
}

type auRun struct {
	t     *testing.T
	w     *gtWorld
	sc    crypto.Hash
	m     *auModel
	l     *vLedger
	names []string
	H     uint64
}

func auStart(t *testing.T, names ...string) *auRun {
	all := append([]string{"owner"}, names...)
	w := gtNew(t, all...)
	w.at(100)
	sc := w.install("gt_audit.bas", "owner")
	return &auRun{t: t, w: w, sc: sc, m: &auModel{bond: 10000, commitw: 20, revealw: 20, maxn: 16, tmo: 2000}, l: vNewLedger(t, w, sc), names: all, H: 100}
}

func (r *auRun) at(h uint64) { r.H = h; r.w.at(h) }

func auLiab(w *gtWorld, sc crypto.Hash) uint64 {
	bond := w.readU(sc, "bond")
	L := w.readU(sc, "carry")
	na := w.readU(sc, "na")
	for a := uint64(0); a < na; a++ {
		p := fmt.Sprintf("a%d_", a)
		n := w.readU(sc, p+"n")
		st, to, sbx := w.readU(sc, p+"st"), w.readU(sc, p+"to"), w.readU(sc, p+"sbx")
		switch {
		case st == 0 && to == 0:
			L += w.readU(sc, p+"bounty") + n*bond
		case st == 0:
			if sbx == 0 {
				L += w.readU(sc, p+"bounty")
			}
			for j := uint64(0); j < n; j++ {
				if w.readU(sc, fmt.Sprintf("%s%d_x", p, j)) == 0 {
					L += bond
				}
			}
		default:
			if sbx == 0 {
				L += w.readU(sc, p+"sb")
			}
			for j := uint64(0); j < n; j++ {
				if w.readU(sc, fmt.Sprintf("%s%d_x", p, j)) == 0 {
					L += w.readU(sc, fmt.Sprintf("%s%d_cr", p, j))
				}
			}
		}
	}
	return L
}

func (r *auRun) check() {
	r.t.Helper()
	r.l.conserve(auLiab(r.w, r.sc), "carry + open bounties and bonds + settled credits + owed bounties")
	if got := r.w.readU(r.sc, "carry"); got != r.m.carry {
		r.t.Fatalf("carry %d, model %d", got, r.m.carry)
	}
}

func (r *auRun) post(who string, dep uint64, ans, salt string) {
	m := r.m
	ok := who == "owner" && m.frozen && dep > 0 && r.H > 0
	r.l.do(ok, "Post", who, dep, nil, nil, gtU("task", 1), gtU("from", 0), gtU("upto", r.H-1), gtS("commit", gtAuditSponsorCommit(ans, salt)))
	if ok {
		m.r = append(m.r, &auRound{fund: dep, cin: m.carry, bounty: dep + m.carry, start: r.H, ans: ans, salt: salt, in: map[string]bool{}})
		m.carry = 0
	}
	r.check()
}

func (r *auRun) enter(u string, a uint64, ans string, dep uint64) {
	m := r.m
	ok := a < uint64(len(m.r))
	var R *auRound
	if ok {
		R = m.r[a]
		ok = u != "owner" && r.H <= R.start+m.commitw && dep == m.bond && uint64(len(R.e)) < m.maxn && !R.in[u]
	}
	r.l.do(ok, "Enter", u, dep, nil, nil, gtU("a", a), gtS("commit", gtAuditCommit(ans, "s-"+u, r.w.gtAuditAddr(u))))
	if ok {
		R.e = append(R.e, &auEntrant{who: u, ans: ans})
		R.in[u] = true
	}
	r.check()
}

func (r *auRun) reveal(u string, a, j uint64, wrong bool) {
	m := r.m
	R := m.r[a]
	t := R.start + m.commitw
	ok := j < uint64(len(R.e)) && r.H > t && r.H <= t+m.revealw && !wrong
	ans := "none"
	if j < uint64(len(R.e)) {
		E := R.e[j]
		ans = E.ans
		ok = ok && E.who == u && !E.v
	}
	salt := "s-" + u
	if wrong {
		salt += "!"
	}
	r.l.do(ok, "Reveal", u, 0, nil, nil, gtU("a", a), gtU("j", j), gtS("answer", ans), gtS("salt", salt))
	if ok {
		R.e[j].v = true
	}
	r.check()
}

func (r *auRun) revealSponsor(who string, a uint64, wrong bool) {
	m := r.m
	R := m.r[a]
	t := R.start + m.commitw
	ok := who == "owner" && !R.sa && r.H > t && r.H <= t+m.revealw && !wrong
	salt := R.salt
	if wrong {
		salt += "!"
	}
	r.l.do(ok, "RevealSponsor", who, 0, nil, nil, gtU("a", a), gtS("answer", R.ans), gtS("salt", salt))
	if ok {
		R.sa = true
	}
	r.check()
}

func (r *auRun) settle(who string, a uint64) {
	m := r.m
	ok := a < uint64(len(m.r))
	var R *auRound
	if ok {
		R = m.r[a]
		ok = !R.st && !R.to && r.H > R.start+m.commitw+m.revealw
	}
	if ok {
		R.md = 2
		if R.sa {
			var nr, match uint64
			for _, E := range R.e {
				if E.v {
					nr++
					if E.ans == R.ans {
						match++
					}
				}
			}
			if nr == match {
				R.md, R.nw = 1, match
			} else {
				R.disp = true
			}
		}
		if R.md == 2 {
			for _, E := range R.e {
				E.cr = m.bond
			}
			R.sb = R.bounty
		} else {
			var rem, forf uint64
			if R.nw > 0 {
				R.share = R.bounty / R.nw
				rem = R.bounty - R.share*R.nw
			}
			for _, E := range R.e {
				if E.v {
					E.cr = R.share + m.bond
					r.l.award[E.who] += R.share
				} else {
					forf += m.bond
					r.l.loss[E.who] += m.bond
				}
			}
			m.carry += forf + rem
			if R.nw == 0 {
				m.carry += R.bounty
			}
			r.l.loss["owner"] += R.fund
			// the carry R.cin joined into this bounty is paid to the winners (award) or carried again
		}
		R.st = true
	}
	r.l.do(ok, "Settle", who, 0, nil, nil, gtU("a", a))
	if ok {
		for j, E := range R.e {
			r.w.auditCredit(r.sc, a, uint64(j), E.cr)
		}
	}
	r.check()
}

func (r *auRun) withdraw(u string, a, j uint64) {
	m := r.m
	ok := a < uint64(len(m.r))
	var pay map[string]uint64
	if ok {
		R := m.r[a]
		ok = j < uint64(len(R.e)) && R.e[j].who == u && !R.e[j].x
		if ok {
			E := R.e[j]
			amt := E.cr
			if R.st {
				ok = amt > 0
			} else {
				ok = r.H > R.start+m.commitw+m.revealw+m.tmo
				amt = m.bond
				if ok {
					R.to = true
				}
			}
			if ok {
				E.x = true
				pay = map[string]uint64{u: amt}
			}
		}
	}
	r.l.do(ok, "Withdraw", u, 0, nil, pay, gtU("a", a), gtU("j", j))
	r.check()
}

func (r *auRun) reclaim(who string, a uint64) {
	m := r.m
	ok := who == "owner" && a < uint64(len(m.r))
	var pay map[string]uint64
	if ok {
		R := m.r[a]
		dl := R.start + m.commitw + m.revealw + m.tmo
		amt := uint64(0)
		switch {
		case R.sbx:
			ok = false
		case R.st:
			amt = R.sb
			ok = amt > 0 && (R.disp || r.H > dl)
		default:
			ok = r.H > dl
			amt = R.bounty
			if ok {
				R.to = true
			}
		}
		if ok {
			R.sbx = true
			pay = map[string]uint64{who: amt}
			r.l.award["owner"] += R.cin
			r.l.loss["owner"] += 0
		}
	}
	r.l.do(ok, "Reclaim", who, 0, nil, pay, gtU("a", a))
	r.check()
}

func auParams(bond, commitw, revealw, maxn uint64) []rpc.Argument {
	return []rpc.Argument{gtU("bond", bond), gtU("commitw", commitw), gtU("revealw", revealw), gtU("maxn", maxn)}
}

// drain: after every documented window and the timeout, every round is settled or timed out, every credit and bond
// withdrawn and every owed bounty reclaimed; what stays is exactly the carry (it joins the next Post)
func (r *auRun) drain() {
	r.t.Helper()
	m := r.m
	last := uint64(0)
	for _, R := range m.r {
		if R.start > last {
			last = R.start
		}
	}
	r.at(vMaxU(r.H, last+m.commitw+m.revealw+1))
	for a, R := range m.r {
		if !R.st && !R.to {
			r.settle("x", uint64(a))
		}
	}
	r.at(r.H + m.tmo + m.commitw + m.revealw + 1)
	for a, R := range m.r {
		for j, E := range R.e {
			if !E.x && (E.cr > 0 || !R.st) {
				r.withdraw(E.who, uint64(a), uint64(j))
			}
		}
		if !R.sbx && (!R.st || R.sb > 0) {
			r.reclaim("owner", uint64(a))
		}
	}
	if got := r.w.held(r.sc, crypto.ZEROHASH); got != m.carry {
		r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d after every withdrawal, carry is %d", got, m.carry)
	}
	if m.carry > 0 { // the documented path for the carry: the next Post joins it; the owner can reclaim it by timeout
		r.post("owner", 1, "carry-round", "z")
		r.at(r.H + m.commitw + m.revealw + m.tmo + 1)
		r.reclaim("owner", uint64(len(m.r)-1))
		if got := r.w.held(r.sc, crypto.ZEROHASH); got != 0 {
			r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d after the carry round was reclaimed", got)
		}
	}
	r.l.balances(r.names...)
}

func vMaxU(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func TestR33VerifyAuditAccess(t *testing.T) {
	r := auStart(t, "A", "x")
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.l.do(false, "SetParams", "x", 0, nil, nil, auParams(10000, 20, 20, 16)...)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, auParams(10000, 20, 20, 33)...)
	r.l.do(true, "SetParams", "owner", 0, nil, nil, auParams(10000, 20, 20, 16)...)
	r.at(200)
	r.post("owner", 5000, "d", "s") // not frozen
	r.l.do(false, "Freeze", "x", 0, nil, nil)
	r.l.do(true, "Freeze", "owner", 0, nil, nil)
	r.m.frozen = true
	r.l.do(false, "Freeze", "owner", 0, nil, nil) // one-time (r33 verify fix)
	r.l.do(false, "SetParams", "owner", 0, nil, nil, auParams(10000, 20, 20, 16)...)
	r.post("x", 5000, "d", "s")
	r.post("owner", 5000, "d", "s")
	r.enter("owner", 0, "d", 10000) // the sponsor cannot enter
	r.enter("A", 0, "d", 10000)
	r.at(221)
	r.revealSponsor("x", 0, false)
	r.revealSponsor("owner", 0, false)
	r.revealSponsor("owner", 0, false) // once
	r.reveal("A", 0, 0, false)
	r.reveal("A", 0, 0, false) // once
	r.at(241)
	r.settle("x", 0)
	r.settle("x", 0) // once
	r.reclaim("x", 0)
	r.withdraw("x", 0, 0)
	r.withdraw("A", 0, 0)
	r.withdraw("A", 0, 0) // once
	r.drain()
	vGas(t, r.w, "gt_audit.bas")
}

func TestR33VerifyAuditRandom(t *testing.T) {
	for _, seed := range []int64{33, 3301, 3302} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			names := []string{"A", "B", "C", "D", "E", "F", "x"}
			r := auStart(t, names...)
			rng := mrand.New(mrand.NewSource(seed))
			pick := func(s ...string) string { return s[rng.Intn(len(s))] }
			r.l.do(true, "Freeze", "owner", 0, nil, nil)
			r.m.frozen = true
			r.at(200)
			long := strings.Repeat("ab", 128)
			answers := []string{"good", "good", "good", "bad", long}
			for step := 0; step < 900; step++ {
				r.at(r.H + uint64(rng.Intn(4)))
				m := r.m
				na := uint64(len(m.r))
				ra := func() uint64 {
					if na == 0 {
						return 0
					}
					if rng.Intn(10) < 6 { // mostly a round whose reveal window is open
						open := []uint64{}
						for i, R := range m.r {
							if r.H > R.start+m.commitw && r.H <= R.start+m.commitw+m.revealw {
								open = append(open, uint64(i))
							}
						}
						if len(open) > 0 && rng.Intn(2) == 0 {
							return open[rng.Intn(len(open))]
						}
					}
					if rng.Intn(10) < 7 && na > 2 {
						return na - 1 - uint64(rng.Intn(2))
					}
					return uint64(rng.Intn(int(na)))
				}
				switch a := rng.Intn(100); {
				case a < 6:
					ans := "good"
					if rng.Intn(4) == 0 {
						ans = long
					}
					r.post(pick("owner", "owner", "owner", "x"), uint64(1+rng.Intn(50000)), ans, fmt.Sprintf("p%d", step))
				case a < 30:
					if na > 0 {
						u := pick(names[:6]...)
						i := ra()
						ans := answers[rng.Intn(len(answers))]
						if ans == "good" {
							ans = m.r[i].ans
						}
						dep := m.bond
						if rng.Intn(15) == 0 {
							dep--
						}
						r.enter(u, i, ans, dep)
					}
				case a < 52:
					if na > 0 {
						i := ra()
						if n := len(m.r[i].e); n > 0 {
							j := uint64(rng.Intn(n))
							u := m.r[i].e[j].who
							if rng.Intn(8) == 0 {
								u = pick(names...)
							}
							r.reveal(u, i, j, rng.Intn(15) == 0)
						}
					}
				case a < 60:
					if na > 0 {
						i := ra()
						if rng.Intn(4) > 0 { // the sponsor withholds a quarter of its reveals
							r.revealSponsor(pick("owner", "owner", "owner", "A"), i, rng.Intn(15) == 0)
						}
					}
				case a < 72:
					if na > 0 {
						r.settle(pick("x", "A", "owner"), ra())
					}
				case a < 88:
					if na > 0 {
						i := uint64(rng.Intn(int(na)))
						if n := len(m.r[i].e); n > 0 {
							j := uint64(rng.Intn(n))
							u := m.r[i].e[j].who
							if rng.Intn(8) == 0 {
								u = pick(names...)
							}
							r.withdraw(u, i, j)
						}
					}
				case a < 96:
					if na > 0 {
						r.reclaim(pick("owner", "owner", "x"), uint64(rng.Intn(int(na))))
					}
				default:
					switch rng.Intn(3) {
					case 0:
						r.l.do(false, "SetParams", "owner", 0, nil, nil, auParams(10000, 20, 20, 16)...)
					case 1:
						r.l.do(false, "Initialize", pick("owner", "x"), 0, nil, nil)
					default:
						if rng.Intn(3) == 0 {
							r.at(r.H + uint64(rng.Intn(2500))) // a long pause: timeouts
						}
					}
					r.check()
				}
			}
			paths := map[string]int{}
			for _, R := range r.m.r {
				switch {
				case R.st && R.md == 1:
					paths["paid"]++
				case R.st && R.disp:
					paths["disputed"]++
				case R.st:
					paths["withheld"]++
				case R.to:
					paths["timeout"]++
				default:
					paths["open"]++
				}
			}
			t.Logf("seed %d: %d calls, %d rounds %v, carry %d, height %d", seed, r.l.calls, len(r.m.r), paths, r.m.carry, r.H)
			r.drain()
			vGas(t, r.w, "gt_audit.bas")
		})
	}
}

// liveness when the sponsor stops cooperating (never reveals, never reclaims) and when entrants vanish
func TestR33VerifyAuditLiveness(t *testing.T) {
	r := auStart(t, "A", "B", "x")
	r.l.do(true, "Freeze", "owner", 0, nil, nil)
	r.m.frozen = true
	r.at(200)
	r.post("owner", 40000, "d", "s")
	r.enter("A", 0, "d", 10000)
	r.enter("B", 0, "d", 10000)
	r.at(221)
	r.reveal("A", 0, 0, false)
	// nobody settles, the sponsor never reveals: after the timeout each entrant pulls its bond itself
	r.at(200 + 20 + 20 + 2000)
	r.withdraw("A", 0, 0) // not yet
	r.at(200 + 20 + 20 + 2001)
	r.withdraw("A", 0, 0)
	r.settle("x", 0) // refused after the first timeout withdrawal
	r.withdraw("B", 0, 1)
	r.reclaim("owner", 0)
	r.drain()
}

// bounds: maxn = 32 entrants with 256-byte answers, every one revealed; Settle and Reveal stay below the limits
func TestR33VerifyAuditBounds(t *testing.T) {
	names := []string{}
	for i := 0; i < 33; i++ {
		names = append(names, fmt.Sprintf("a%02d", i))
	}
	r := auStart(t, names...)
	r.l.do(true, "SetParams", "owner", 0, nil, nil, auParams(1000000000000, 1000000, 1000000, 32)...)
	r.m.bond, r.m.commitw, r.m.revealw, r.m.maxn = 1000000000000, 1000000, 1000000, 32
	r.l.do(true, "Freeze", "owner", 0, nil, nil)
	r.m.frozen = true
	r.at(200)
	long := strings.Repeat("x", 256)
	r.post("owner", 1000000000003, long, "salt")
	for _, n := range names {
		r.enter(n, 0, long, r.m.bond) // the 33rd is refused
	}
	r.at(200 + r.m.commitw + 1)
	r.revealSponsor("owner", 0, false)
	for j, n := range names[:32] {
		r.reveal(n, 0, uint64(j), false)
	}
	r.at(200 + r.m.commitw + r.m.revealw + 1)
	r.settle("x", 0)
	g := r.w.gas["gt_audit.bas:Settle"]
	t.Logf("Settle with 32 revealed 256-byte answers: compute %d, storage %d", g[0], g[1])
	r.drain()
	vGas(t, r.w, "gt_audit.bas")
}
