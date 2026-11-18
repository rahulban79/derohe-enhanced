package dvm

// R32a (dero-game-theory-rft; D-21 non-consensus: tests only, no DVM semantics or gas change).
// Executes gametheory/contracts/gt_audit.bas (audit bounty: pay for independent detection) in the in-process DVM
// simulator, reusing the gtWorld harness of r32_gametheory_test.go.
// Simulator artefact (dvm/simulator.go common/ErrorRevert, child rft lesson 1): a deposit is NOT debited from the
// sender, and a reverted call credits its deposit back to the signer. So a sender's balance only ever shows what the
// contract SENT it (plus reverted deposits, tracked in gtWorld.refund), and the checks count what the contract
// sends and what it HOLDS; a revert is asserted by its error and by the SC balance staying unchanged (gtWorld.call).
// DVM quirk: ADDRESS_STRING(SIGNER()) always encodes the MAINNET form ("dero1..."; dvm_address_string uses
// rpc.NewAddressFromKeys, which sets Mainnet true), even though the test addresses are testnet; the auditor commit
// must hash that exact string (gtAuditAddr).

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

const gtAuditBond = uint64(10000) // gt_audit.bas Initialize default bond

// gtAuditAddr is the string ADDRESS_STRING(SIGNER()) returns inside the DVM for name.
func (w *gtWorld) gtAuditAddr(name string) string {
	return rpc.NewAddressFromKeys(w.addr[name].PublicKey).String()
}

func gtAuditSponsorCommit(answer, salt string) string {
	h := sha256.Sum256([]byte(answer + ":" + salt))
	return hex.EncodeToString(h[:])
}

func gtAuditCommit(answer, salt, addr string) string {
	h := sha256.Sum256([]byte(answer + ":" + salt + ":" + addr))
	return hex.EncodeToString(h[:])
}

// gtAuditReady installs at 100, freezes, and posts round na with fund at height 200 (task 1, blocks 150..199).
func gtAuditReady(t *testing.T, names ...string) (*gtWorld, crypto.Hash) {
	w := gtNew(t, append([]string{"owner"}, names...)...)
	w.at(100)
	scid := w.install("gt_audit.bas", "owner")
	w.must(scid, "Freeze", "owner", 0, nil)
	return w, scid
}

func (w *gtWorld) auditPost(scid crypto.Hash, fund uint64, answer, salt string) uint64 {
	w.t.Helper()
	a := w.readU(scid, "na")
	w.must(scid, "Post", "owner", fund, nil, gtU("task", 1), gtU("from", 150), gtU("upto", 199),
		gtS("commit", gtAuditSponsorCommit(answer, salt)))
	return a
}

func (w *gtWorld) auditEnter(scid crypto.Hash, a uint64, name, answer string) {
	w.t.Helper()
	w.must(scid, "Enter", name, gtAuditBond, nil, gtU("a", a), gtS("commit", gtAuditCommit(answer, "s-"+name, w.gtAuditAddr(name))))
}

func (w *gtWorld) auditReveal(scid crypto.Hash, a, j uint64, name, answer string) {
	w.t.Helper()
	w.must(scid, "Reveal", name, 0, nil, gtU("a", a), gtU("j", j), gtS("answer", answer), gtS("salt", "s-"+name))
}

func (w *gtWorld) auditSponsor(scid crypto.Hash, a uint64, answer, salt string) {
	w.t.Helper()
	w.must(scid, "RevealSponsor", "owner", 0, nil, gtU("a", a), gtS("answer", answer), gtS("salt", salt))
}

func (w *gtWorld) auditCredit(scid crypto.Hash, a, j, want uint64) {
	w.t.Helper()
	if got := w.readU(scid, "a"+strconv.FormatUint(a, 10)+"_"+strconv.FormatUint(j, 10)+"_cr"); got != want {
		w.t.Fatalf("round %d entrant %d credit %d, want %d", a, j, got, want)
	}
}

func TestR32aAuditHonestRound(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "C", "other")
	// worked example for gametheory/contracts/gt_audit_commit.md (the Python playbook checks against these)
	t.Logf("EXAMPLE sponsor HEX(SHA256(%q)) = %s", "d1g3st:pepper", gtAuditSponsorCommit("d1g3st", "pepper"))
	t.Logf("EXAMPLE auditor A address_string = %s", w.gtAuditAddr("A"))
	t.Logf("EXAMPLE auditor HEX(SHA256(%q)) = %s", "d1g3st:s-A:"+w.gtAuditAddr("A"), gtAuditCommit("d1g3st", "s-A", w.gtAuditAddr("A")))
	w.at(200)
	a := w.auditPost(scid, 90001, "d1g3st", "pepper")
	w.at(205)
	for _, n := range []string{"A", "B", "C"} {
		w.auditEnter(scid, a, n, "d1g3st")
	}
	if got := w.held(scid, crypto.ZEROHASH); got != 90001+3*gtAuditBond {
		t.Fatalf("SC holds %d, want bounty + 3 bonds", got)
	}
	w.at(221)
	w.auditSponsor(scid, a, "d1g3st", "pepper")
	for j, n := range []string{"A", "B", "C"} {
		w.auditReveal(scid, a, uint64(j), n, "d1g3st")
	}
	w.at(240)
	w.mustFail(scid, "Settle", "other", 0, nil, "inside the reveal window", gtU("a", a))
	w.at(241)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	w.mustFail(scid, "Settle", "other", 0, nil, "settled twice", gtU("a", a))
	if w.readU(scid, "a0_nw") != 3 || w.readU(scid, "a0_disp") != 0 || w.readU(scid, "a0_share") != 30000 ||
		w.readU(scid, "a0_rem") != 1 || w.readU(scid, "carry") != 1 || w.readU(scid, "a0_refund") != 0 {
		t.Fatalf("nw %d disp %d share %d rem %d carry %d", w.readU(scid, "a0_nw"), w.readU(scid, "a0_disp"),
			w.readU(scid, "a0_share"), w.readU(scid, "a0_rem"), w.readU(scid, "carry"))
	}
	w.mustFail(scid, "Withdraw", "B", 0, nil, "wrong signer", gtU("a", a), gtU("j", 0))
	w.mustFail(scid, "Withdraw", "other", 0, nil, "not an entrant", gtU("a", a), gtU("j", 0))
	for j, n := range []string{"A", "B", "C"} {
		w.auditCredit(scid, a, uint64(j), 30000+gtAuditBond)
		w.must(scid, "Withdraw", n, 0, nil, gtU("a", a), gtU("j", uint64(j)))
		w.mustFail(scid, "Withdraw", n, 0, nil, "withdraw twice", gtU("a", a), gtU("j", uint64(j)))
		w.deroIs(n, 30000+gtAuditBond)
	}
	if got := w.held(scid, crypto.ZEROHASH); got != 1 {
		t.Fatalf("SC holds %d after the withdrawals, want the remainder 1", got)
	}
}

// B copies A's commit: B's reveal of A's answer and salt fails (the hash binds A's address), B forfeits its bond.
func TestR32aAuditCopyAttack(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "other")
	w.at(200)
	a := w.auditPost(scid, 50000, "dg", "k")
	w.at(201)
	cA := gtAuditCommit("dg", "s-A", w.gtAuditAddr("A"))
	w.must(scid, "Enter", "A", gtAuditBond, nil, gtU("a", a), gtS("commit", cA))
	w.must(scid, "Enter", "B", gtAuditBond, nil, gtU("a", a), gtS("commit", cA)) // copied from A's Enter tx
	w.at(221)                                                                    // maxn 16 is not reached here, so only the commit window refuses this entry
	w.mustFail(scid, "Enter", "other", gtAuditBond, nil, "after the commit window", gtU("a", a),
		gtS("commit", gtAuditCommit("dg", "s-other", w.gtAuditAddr("other"))))
	w.auditSponsor(scid, a, "dg", "k")
	w.mustFail(scid, "Reveal", "B", 0, nil, "copied commit", gtU("a", a), gtU("j", 1), gtS("answer", "dg"), gtS("salt", "s-A"))
	w.mustFail(scid, "Reveal", "B", 0, nil, "A's entry", gtU("a", a), gtU("j", 0), gtS("answer", "dg"), gtS("salt", "s-A"))
	w.auditReveal(scid, a, 0, "A", "dg")
	w.at(241)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	w.auditCredit(scid, a, 0, 50000+gtAuditBond)
	w.auditCredit(scid, a, 1, 0)
	if w.readU(scid, "carry") != gtAuditBond || w.readU(scid, "a0_forf") != gtAuditBond {
		t.Fatalf("carry %d forf %d, want B's bond", w.readU(scid, "carry"), w.readU(scid, "a0_forf"))
	}
	w.mustFail(scid, "Withdraw", "B", 0, nil, "no credit", gtU("a", a), gtU("j", 1))
	w.must(scid, "Withdraw", "A", 0, nil, gtU("a", a), gtU("j", 0))
	w.deroIs("A", 50000+gtAuditBond)
	w.deroIs("B", 0)
}

// a wrong answer. R32a forfeited the wrong auditor's bond to carry and paid the right one. R33 GT-A04 changes this on
// purpose: any revealed answer that differs from the sponsor's marks the round disputed (public), every bond is
// refunded and the bounty goes back to the sponsor (Reclaim, at once); a majority can grief but never profit.
// carry still joins the next Post (here nothing was carried).
func TestR32aAuditWrongAnswerCarry(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "other")
	w.at(200)
	a := w.auditPost(scid, 40000, "right", "z")
	w.at(210)
	w.auditEnter(scid, a, "A", "right")
	w.auditEnter(scid, a, "B", "wrong")
	w.at(230)
	w.auditSponsor(scid, a, "right", "z")
	w.auditReveal(scid, a, 0, "A", "right")
	w.auditReveal(scid, a, 1, "B", "wrong")
	w.at(241)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	w.auditCredit(scid, a, 0, gtAuditBond)
	w.auditCredit(scid, a, 1, gtAuditBond)
	if w.readU(scid, "carry") != 0 || w.readU(scid, "a0_disp") != 1 || w.readU(scid, "a0_sb") != 40000 {
		t.Fatalf("carry %d disp %d sb %d", w.readU(scid, "carry"), w.readU(scid, "a0_disp"), w.readU(scid, "a0_sb"))
	}
	w.mustFail(scid, "Reclaim", "A", 0, nil, "not the sponsor", gtU("a", a))
	w.must(scid, "Reclaim", "owner", 0, nil, gtU("a", a))
	w.mustFail(scid, "Reclaim", "owner", 0, nil, "reclaimed twice", gtU("a", a))
	w.deroIs("owner", 40000)
	w.at(300)
	a1 := w.auditPost(scid, 5000, "next", "y")
	if a1 != 1 || w.readU(scid, "a1_bounty") != 5000 || w.readU(scid, "a1_cin") != 0 || w.readU(scid, "carry") != 0 {
		t.Fatalf("round 1 bounty %d cin %d carry %d", w.readU(scid, "a1_bounty"), w.readU(scid, "a1_cin"), w.readU(scid, "carry"))
	}
	w.must(scid, "Withdraw", "A", 0, nil, gtU("a", a), gtU("j", 0))
	w.must(scid, "Withdraw", "B", 0, nil, gtU("a", a), gtU("j", 1))
	w.deroIs("A", gtAuditBond)
	w.deroIs("B", gtAuditBond)
	if got := w.held(scid, crypto.ZEROHASH); got != 5000 {
		t.Fatalf("SC holds %d, want round 1 bounty %d", got, 5000)
	}
}

// the sponsor's revealed digest is wrong; two of three auditors agree on another digest. R32a let that majority win.
// R33 GT-A04 changes this on purpose: the round is disputed = 1 (the public detection signal), but nobody wins:
// every bond is refunded and the bounty goes back to the sponsor (a Sybil majority could otherwise take it).
func TestR32aAuditMajorityDispute(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "C", "other")
	w.at(200)
	a := w.auditPost(scid, 60000, "bad", "q")
	w.at(220)
	w.auditEnter(scid, a, "A", "good")
	w.auditEnter(scid, a, "B", "good")
	w.auditEnter(scid, a, "C", "bad")
	w.at(221)
	w.auditSponsor(scid, a, "bad", "q")
	w.auditReveal(scid, a, 0, "A", "good")
	w.auditReveal(scid, a, 1, "B", "good")
	w.auditReveal(scid, a, 2, "C", "bad")
	w.at(241)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	if w.readU(scid, "a0_disp") != 1 || w.readU(scid, "a0_nw") != 0 || w.read(scid, "a0_win") != "" || w.readU(scid, "a0_refund") != 1 {
		t.Fatalf("disp %d nw %d win %v", w.readU(scid, "a0_disp"), w.readU(scid, "a0_nw"), w.read(scid, "a0_win"))
	}
	w.auditCredit(scid, a, 0, gtAuditBond)
	w.auditCredit(scid, a, 1, gtAuditBond)
	w.auditCredit(scid, a, 2, gtAuditBond)
	if w.readU(scid, "carry") != 0 || w.readU(scid, "a0_sb") != 60000 {
		t.Fatalf("carry %d sb %d, want 0 and the bounty", w.readU(scid, "carry"), w.readU(scid, "a0_sb"))
	}
}

// the sponsor withholds its reveal. R32a let a strict majority win (disputed = 1) and forfeited non-revealers' bonds
// when undecided. R33 GT-A04 changes this on purpose: with no sponsor reveal every bond is refunded (refund = 1) and
// the bounty is claimable by the sponsor only after the timeout (start + commitw + revealw + tmo).
func TestR32aAuditSponsorNoReveal(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "C", "other")
	w.at(200)
	a := w.auditPost(scid, 20000, "x", "q")
	w.at(205)
	w.auditEnter(scid, a, "A", "h1")
	w.auditEnter(scid, a, "B", "h1")
	w.auditEnter(scid, a, "C", "h2")
	w.at(225)
	w.auditReveal(scid, a, 0, "A", "h1")
	w.auditReveal(scid, a, 1, "B", "h1")
	w.auditReveal(scid, a, 2, "C", "h2")
	w.at(241)
	w.mustFail(scid, "RevealSponsor", "owner", 0, nil, "after the reveal window", gtU("a", a), gtS("answer", "x"), gtS("salt", "q"))
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	if w.readU(scid, "a0_disp") != 0 || w.readU(scid, "a0_nw") != 0 || w.readU(scid, "a0_refund") != 1 || w.readU(scid, "a0_sb") != 20000 {
		t.Fatalf("no sponsor reveal: disp %d nw %d refund %d", w.readU(scid, "a0_disp"), w.readU(scid, "a0_nw"), w.readU(scid, "a0_refund"))
	}
	for j := uint64(0); j < 3; j++ {
		w.auditCredit(scid, a, j, gtAuditBond)
	}
	dl := uint64(200 + 20 + 20 + 2000)
	w.at(dl)
	w.mustFail(scid, "Reclaim", "owner", 0, nil, "before the timeout", gtU("a", a))

	// round 1: no sponsor reveal, 1-1 split, C does not reveal: every bond back, carry untouched
	w.at(300)
	a1 := w.auditPost(scid, 7000, "x", "q")
	w.at(301)
	w.auditEnter(scid, a1, "A", "h1")
	w.auditEnter(scid, a1, "B", "h2")
	w.auditEnter(scid, a1, "C", "h1")
	w.at(330)
	w.auditReveal(scid, a1, 0, "A", "h1")
	w.auditReveal(scid, a1, 1, "B", "h2")
	w.at(341)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a1))
	if w.readU(scid, "a1_refund") != 1 || w.readU(scid, "a1_nw") != 0 || w.readU(scid, "carry") != 0 || w.readU(scid, "a1_forf") != 0 {
		t.Fatalf("undecided: refund %d nw %d carry %d", w.readU(scid, "a1_refund"), w.readU(scid, "a1_nw"), w.readU(scid, "carry"))
	}
	for j := uint64(0); j < 3; j++ {
		w.auditCredit(scid, a1, j, gtAuditBond)
	}

	// round 2: nobody reveals and no sponsor reveal: every bond back
	w.at(400)
	a2 := w.auditPost(scid, 1000, "x", "q")
	w.at(401)
	w.auditEnter(scid, a2, "A", "h1")
	w.auditEnter(scid, a2, "B", "h1")
	w.at(441)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a2))
	w.auditCredit(scid, a2, 0, gtAuditBond)
	w.auditCredit(scid, a2, 1, gtAuditBond)
	if w.readU(scid, "a2_refund") != 1 || w.readU(scid, "a2_forf") != 0 {
		t.Fatalf("refund %d forf %d", w.readU(scid, "a2_refund"), w.readU(scid, "a2_forf"))
	}
	w.must(scid, "Withdraw", "B", 0, nil, gtU("a", a2), gtU("j", 1))
	w.must(scid, "Withdraw", "B", 0, nil, gtU("a", a), gtU("j", 1))
	w.deroIs("B", 2*gtAuditBond)
	w.at(dl + 1)
	w.must(scid, "Reclaim", "owner", 0, nil, gtU("a", a))
	w.deroIs("owner", 20000)
}

func TestR32aAuditGuards(t *testing.T) {
	w := gtNew(t, "owner", "A", "B", "other")
	w.at(100)
	scid := w.install("gt_audit.bas", "owner")
	c := gtAuditSponsorCommit("d", "s")
	w.mustFail(scid, "SetParams", "other", 0, nil, "non-owner", gtU("bond", 5), gtU("commitw", 5), gtU("revealw", 5), gtU("maxn", 2))
	w.mustFail(scid, "SetParams", "owner", 0, nil, "maxn > 32", gtU("bond", 5), gtU("commitw", 5), gtU("revealw", 5), gtU("maxn", 33))
	w.mustFail(scid, "SetParams", "owner", 0, nil, "bond 0", gtU("bond", 0), gtU("commitw", 5), gtU("revealw", 5), gtU("maxn", 2))
	w.mustFail(scid, "Post", "owner", 1000, nil, "not frozen", gtU("task", 1), gtU("from", 1), gtU("upto", 2), gtS("commit", c))
	w.must(scid, "SetParams", "owner", 0, nil, gtU("bond", gtAuditBond), gtU("commitw", 20), gtU("revealw", 20), gtU("maxn", 2))
	w.mustFail(scid, "Freeze", "other", 0, nil, "non-owner freeze")
	w.must(scid, "Freeze", "owner", 0, nil)
	w.mustFail(scid, "SetParams", "owner", 0, nil, "frozen", gtU("bond", 5), gtU("commitw", 5), gtU("revealw", 5), gtU("maxn", 2))
	w.at(200)
	w.mustFail(scid, "Post", "other", 1000, nil, "non-owner Post", gtU("task", 1), gtU("from", 1), gtU("upto", 2), gtS("commit", c))
	w.mustFail(scid, "Post", "owner", 0, nil, "no bounty", gtU("task", 1), gtU("from", 1), gtU("upto", 2), gtS("commit", c))
	w.mustFail(scid, "Post", "owner", 1000, nil, "upto < from", gtU("task", 1), gtU("from", 3), gtU("upto", 2), gtS("commit", c))
	w.mustFail(scid, "Post", "owner", 1000, nil, "upto not in the past", gtU("task", 1), gtU("from", 1), gtU("upto", 200), gtS("commit", c))
	w.mustFail(scid, "Post", "owner", 1000, nil, "short commit", gtU("task", 1), gtU("from", 1), gtU("upto", 2), gtS("commit", "ab"))
	a := w.auditPost(scid, 1000, "d", "s")
	cA := gtAuditCommit("d", "s-A", w.gtAuditAddr("A"))
	w.mustFail(scid, "Enter", "A", gtAuditBond-1, nil, "bond mismatch (low)", gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "Enter", "A", gtAuditBond+1, nil, "bond mismatch (high)", gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "Enter", "owner", gtAuditBond, nil, "sponsor entry", gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "Enter", "A", gtAuditBond, nil, "no such round", gtU("a", 1), gtS("commit", cA))
	w.mustFail(scid, "Enter", "A", gtAuditBond, nil, "short commit", gtU("a", a), gtS("commit", "ab"))
	w.must(scid, "Enter", "A", gtAuditBond, nil, gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "Enter", "A", gtAuditBond, nil, "duplicate entry", gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "Reveal", "A", 0, nil, "inside the commit window", gtU("a", a), gtU("j", 0), gtS("answer", "d"), gtS("salt", "s-A"))
	w.mustFail(scid, "RevealSponsor", "owner", 0, nil, "inside the commit window", gtU("a", a), gtS("answer", "d"), gtS("salt", "s"))
	w.at(220)
	w.auditEnter(scid, a, "B", "d") // last block of the commit window
	w.mustFail(scid, "Enter", "other", gtAuditBond, nil, "maxn reached", gtU("a", a), gtS("commit", cA))
	w.at(221)
	w.mustFail(scid, "Enter", "other", gtAuditBond, nil, "after the commit window", gtU("a", a), gtS("commit", cA))
	w.mustFail(scid, "RevealSponsor", "other", 0, nil, "non-owner", gtU("a", a), gtS("answer", "d"), gtS("salt", "s"))
	w.mustFail(scid, "RevealSponsor", "owner", 0, nil, "wrong salt", gtU("a", a), gtS("answer", "d"), gtS("salt", "t"))
	w.mustFail(scid, "Reveal", "B", 0, nil, "A's entry", gtU("a", a), gtU("j", 0), gtS("answer", "d"), gtS("salt", "s-A"))
	w.mustFail(scid, "Reveal", "A", 0, nil, "wrong answer for the commit", gtU("a", a), gtU("j", 0), gtS("answer", "e"), gtS("salt", "s-A"))
	w.mustFail(scid, "Withdraw", "A", 0, nil, "not settled", gtU("a", a), gtU("j", 0))
	w.mustFail(scid, "Settle", "other", 0, nil, "reveal window open", gtU("a", a))
	w.auditSponsor(scid, a, "d", "s")
	w.mustFail(scid, "RevealSponsor", "owner", 0, nil, "revealed twice", gtU("a", a), gtS("answer", "d"), gtS("salt", "s"))
	w.auditReveal(scid, a, 0, "A", "d")
	w.mustFail(scid, "Reveal", "A", 0, nil, "revealed twice", gtU("a", a), gtU("j", 0), gtS("answer", "d"), gtS("salt", "s-A"))
	w.at(241)
	w.mustFail(scid, "Reveal", "B", 0, nil, "after the reveal window", gtU("a", a), gtU("j", 1), gtS("answer", "d"), gtS("salt", "s-B"))
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	w.mustFail(scid, "Settle", "A", 0, nil, "settled twice", gtU("a", a))
	w.mustFail(scid, "Settle", "A", 0, nil, "no such round", gtU("a", 7))
	w.auditCredit(scid, a, 0, 1000+gtAuditBond)
	w.auditCredit(scid, a, 1, 0)
	w.mustFail(scid, "Withdraw", "B", 0, nil, "wrong signer", gtU("a", a), gtU("j", 0))
	w.must(scid, "Withdraw", "A", 0, nil, gtU("a", a), gtU("j", 0))
	w.deroIs("A", 1000+gtAuditBond)
	w.deroIs("B", 0)
}
