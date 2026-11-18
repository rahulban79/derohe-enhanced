package dvm

// R33 (dero-game-theory-rft; D-21 non-consensus: tests only, no DVM semantics or gas change).
// Regression tests for the R33 independent contract audit (gametheory/audit/r33_contract_audit.md, findings
// GT-01..GT-17 = GT-A01..A17). Each test ports the audit's proof of concept and asserts the FIXED behaviour: the
// attack fails or gains nothing, and the funds are conserved (SC balance == what participants can still withdraw
// + treasury). The conservation tests run one honest round per contract and account for every atomic unit.
// Reuses the gtWorld harness of r32_gametheory_test.go and the audit helpers of r32a_audit_test.go.
// Simulator note (as in r32): deposits are credited to the SC but never debited from the sender, so a sender's
// balance shows what the SC SENT it (plus reverted deposits, gtWorld.refund); the SC's own balance (w.held) is exact.

import (
	"fmt"
	mrand "math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

var r33Contracts = []string{"gt_attest.bas", "gt_service.bas", "gt_prize.bas", "gt_audit.bas"}

func r33Names(prefix string, n int) []string {
	out := []string{}
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s%02d", prefix, i))
	}
	return out
}

func r33Args(entry string, scid crypto.Hash, args ...rpc.Argument) rpc.Arguments {
	return append(rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid}, {Name: "entrypoint", DataType: rpc.DataString, Value: entry}}, args...)
}

// anonymous call: signer_addr nil -> SIGNER() is 33 zero bytes (ring size > 2 on chain)
func (w *gtWorld) callAnon(scid crypto.Hash, entry string, dero uint64, args ...rpc.Argument) error {
	in := map[crypto.Hash]uint64{}
	if dero > 0 {
		in[crypto.ZEROHASH] = dero
	}
	_, _, err := w.s.RunSC(in, r33Args(entry, scid, args...), nil, 0)
	return err
}

// call with a fee (storage-gas limit = min(fee, 20000) as on mainnet)
func (w *gtWorld) callFee(scid crypto.Hash, entry, signer string, dero, fee uint64, args ...rpc.Argument) (uint64, uint64, error) {
	in := map[crypto.Hash]uint64{}
	if dero > 0 {
		in[crypto.ZEROHASH] = dero
	}
	gc, gs, err := w.s.RunSC(in, r33Args(entry, scid, args...), w.addr[signer], fee)
	w.note(w.owners[scid]+":"+entry, gc, gs)
	if err != nil {
		w.refund[signer] += dero
	}
	return gc, gs, err
}

// noDep: R33 GT-A13: an entrypoint that expects no DERO refuses a 1-atomic deposit, then succeeds without one.
func (w *gtWorld) noDep(scid crypto.Hash, entry, signer string, args ...rpc.Argument) {
	w.t.Helper()
	w.mustFail(scid, entry, signer, 1, nil, "R33 A13: no deposit expected", args...)
	w.must(scid, entry, signer, 0, nil, args...)
}

func (w *gtWorld) stakeOf(scid crypto.Hash, name string) uint64 {
	w.t.Helper()
	return w.readU(scid, "st"+string(w.addr[name].Compressed()))
}

func (w *gtWorld) vote(scid crypto.Hash, i uint64, name string, v uint64, salt string) {
	w.t.Helper()
	w.must(scid, "CommitVote", name, 0, nil, gtU("i", i), gtS("h", gtCommitVote(i, v, salt, w.gtAuditAddr(name))))
}

func (w *gtWorld) heldIs(scid crypto.Hash, want uint64, what string) {
	w.t.Helper()
	if got := w.held(scid, crypto.ZEROHASH); got != want {
		w.t.Fatalf("SC holds %d, want %d (%s)", got, want, what)
	}
}

// r33AuditReady installs gt_audit at 100 with maxn, freezes it.
func r33AuditReady(t *testing.T, maxn uint64, names ...string) (*gtWorld, crypto.Hash) {
	w := gtNew(t, append([]string{"owner"}, names...)...)
	w.at(100)
	scid := w.install("gt_audit.bas", "owner")
	w.must(scid, "SetParams", "owner", 0, nil, gtU("bond", gtAuditBond), gtU("commitw", 20), gtU("revealw", 20), gtU("maxn", maxn))
	w.must(scid, "Freeze", "owner", 0, nil)
	return w, scid
}

// ---------------------------------------------------------------- GT-A01 / GT-A12: Initialize

// A01: a second Initialize (by a stranger or by the owner) is refused on all four contracts after install.
func TestR33AuditA01ReinitByAnyone(t *testing.T) {
	w := gtNew(t, "owner", "mallory")
	w.at(100)
	for _, f := range r33Contracts {
		scid := w.install(f, "owner")
		w.must(scid, "Freeze", "owner", 0, nil)
		w.mustFail(scid, "Initialize", "mallory", 0, nil, "R33 A01: Initialize runs once")
		w.mustFail(scid, "Initialize", "owner", 0, nil, "R33 A01: not even the owner re-initializes")
		if w.read(scid, "owner").(string) != string(w.addr["owner"].Compressed()) || w.readU(scid, "frozen") != 1 {
			t.Fatalf("%s: owner or frozen changed", f)
		}
	}
}

// A01 impact (prize drain): mallory cannot re-Initialize, so a and b withdraw exactly what they put in.
func TestR33AuditA01PrizeReinitDrain(t *testing.T) {
	w, _, pz := gtPrizeReady(t, "a", "b", "mallory")
	rb := uint64(10000)
	w.must(pz, "Fund", "sponsor", 7000, nil)
	w.must(pz, "Enter", "a", 50000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(11, "sa")))
	w.must(pz, "Enter", "b", 30000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(22, "sb")))
	w.at(111)
	w.must(pz, "Reveal", "a", 0, nil, gtU("j", 0), gtU("num", 11), gtS("salt", "sa"))
	w.must(pz, "Reveal", "b", 0, nil, gtU("j", 1), gtU("num", 22), gtS("salt", "sb"))
	w.at(121)
	w.must(pz, "Draw", "sponsor", 0, nil)
	w.at(122)
	w.mustFail(pz, "Initialize", "mallory", 0, nil, "R33 A01")
	w.mustFail(pz, "SetParams", "mallory", 0, nil, "not the owner", gtU("rbond", 1), gtU("commitw", 1), gtU("revealw", 1),
		gtU("maxn", 32), gtU("boost", 0), gtU("minmat", 100))
	win := w.readU(pz, "win0")
	w.must(pz, "Withdraw", "a", 0, nil, gtU("r", 0), gtU("j", 0))
	w.must(pz, "Withdraw", "b", 0, nil, gtU("r", 0), gtU("j", 1))
	wa, wb := 50000+rb, 30000+rb
	if win == 0 {
		wa += 7000
	} else {
		wb += 7000
	}
	w.deroIs("a", wa)
	w.deroIs("b", wb)
	w.deroIs("mallory", 0)
	w.heldIs(pz, w.readU(pz, "treasury"), "only the treasury (2 entry fees) remains")
}

// A01 impact (service epoch drain): the attacker's Initialize and SetParams fail; u2's epoch-3 rebate pays in full.
func TestR33AuditA01ServiceReinitEpochDrain(t *testing.T) {
	w, _, svc := gtServiceReady(t)
	w.must(svc, "Freeze", "owner", 0, nil)
	w.at(200)
	for i := 0; i < 3; i++ {
		w.must(svc, "Notarize", "u1", 1000, nil, gtS("doc", "u1-"+strconv.Itoa(i)))
	}
	w.must(svc, "Sponsor", "sponsor", 100000, nil)
	w.at(300)
	w.must(svc, "ClaimRebate", "u1", 0, nil, gtU("e", 2))
	w.must(svc, "Notarize", "u2", 1000, nil, gtS("doc", "u2-0"))
	w.must(svc, "Sponsor", "sponsor", 50000, nil)
	w.at(310)
	w.mustFail(svc, "Initialize", "chal", 0, nil, "R33 A01")
	w.mustFail(svc, "SetParams", "chal", 0, nil, "not the owner", gtU("fee", 3000), gtU("rho", 100), gtU("boost", 0),
		gtU("epoch", 155), gtU("minmat", 100))
	w.at(400)
	w.must(svc, "ClaimRebate", "u2", 0, nil, gtU("e", 3))
	w.deroIs("u1", 101500)
	w.deroIs("u2", 50500)
	w.deroIs("chal", 0)
	if w.readU(svc, "treasury") != 2000 {
		t.Fatalf("treasury %d, want 2000", w.readU(svc, "treasury"))
	}
	w.must(svc, "WithdrawTreasury", "owner", 0, nil, gtU("amount", 2000))
	w.heldIs(svc, 0, "everything paid out")
}

// A12: an anonymous install fails (Initialize refuses the zero signer), so no contract can have an anonymous owner;
// anonymous callers fail every owner check of a normally installed contract.
func TestR33AuditA12AnonymousSigner(t *testing.T) {
	w := gtNew(t, "owner", "u")
	w.at(100)
	for _, f := range r33Contracts {
		if _, _, _, err := w.s.SCInstall(gtCode(t, f), map[crypto.Hash]uint64{}, rpc.Arguments{}, nil, 0); err == nil {
			t.Fatalf("%s: anonymous install accepted", f)
		}
	}
	svc := w.install("gt_service.bas", "owner")
	if err := w.callAnon(svc, "SetParams", 0, gtU("fee", 7), gtU("rho", 10), gtU("boost", 0), gtU("epoch", 5), gtU("minmat", 1)); err == nil {
		t.Fatalf("anonymous SetParams accepted")
	}
	if err := w.callAnon(svc, "Freeze", 0); err == nil {
		t.Fatalf("anonymous Freeze accepted")
	}
	if err := w.callAnon(svc, "Initialize", 0); err == nil {
		t.Fatalf("anonymous re-Initialize accepted")
	}
	at := w.install("gt_attest.bas", "owner")
	w.must(at, "Freeze", "owner", 0, nil)
	if err := w.callAnon(at, "Claim", 0, gtU("from", 90), gtU("upto", 90), gtU("k", 1)); err == nil {
		t.Fatalf("anonymous Claim accepted")
	}
}

// ---------------------------------------------------------------- GT-A02 / A07 / A08 / A11 / A17: gt_attest

// A02: a juror's whole free stake is escrowed per commit, so one stake backs one open dispute at a time; the
// coherent juror is paid only from what the losing side escrowed. The R33 PoC attacker (claimant C = miner,
// challenger X = chal, jurors L = j1, W = j2) now nets 0 and the honest staker H = j3 can always unstake.
func TestR33AuditA02StakeReuse(t *testing.T) {
	w, scid := gtAttestReady(t)
	const N = 20
	S := uint64(1000000)
	w.must(scid, "Stake", "j3", 5000000, nil)
	w.must(scid, "Stake", "j1", S, nil)
	w.must(scid, "Stake", "j2", 100000, nil)
	w.at(200)
	for i := uint64(0); i < N; i++ {
		w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 100+i), gtU("upto", 100+i), gtU("k", 1))
		w.must(scid, "Challenge", "chal", gtBond, nil, gtU("i", i))
	}
	w.vote(scid, 0, "j1", 0, "l")
	w.vote(scid, 0, "j2", 1, "w")
	if w.stakeOf(scid, "j1") != 0 || w.stakeOf(scid, "j2") != 0 {
		t.Fatalf("stake not escrowed at CommitVote")
	}
	for i := uint64(1); i < N; i++ {
		w.mustFail(scid, "CommitVote", "j1", 0, nil, "R33 A02: the stake is escrowed in dispute 0", gtU("i", i),
			gtS("h", gtCommitVote(i, 0, "l", w.gtAuditAddr("j1"))))
		w.mustFail(scid, "CommitVote", "j2", 0, nil, "R33 A02: the stake is escrowed in dispute 0", gtU("i", i),
			gtS("h", gtCommitVote(i, 1, "w", w.gtAuditAddr("j2"))))
	}
	w.at(231)
	w.must(scid, "RevealVote", "j2", 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "w"))
	w.at(241)
	for i := uint64(0); i < N; i++ {
		w.must(scid, "Finalize", "other", 0, nil, gtU("i", i))
	}
	w.must(scid, "ClaimJuror", "j2", 0, nil, gtU("i", 0))
	w.must(scid, "ClaimJuror", "j1", 0, nil, gtU("i", 0))
	if w.stakeOf(scid, "j1") != S-S/10 || w.stakeOf(scid, "j2") != 100000 {
		t.Fatalf("stakes after the dispute: j1 %d j2 %d", w.stakeOf(scid, "j1"), w.stakeOf(scid, "j2"))
	}
	w.must(scid, "Unstake", "j2", 0, nil, gtU("amount", 100000))
	w.must(scid, "Unstake", "j1", 0, nil, gtU("amount", S-S/10))
	// claim 0: upheld (C gets b + b/2); pot = b/2 + 10 % of L's escrow, all to W; claims 1..19: no reveal -> refunded
	pot := gtBond/2 + S/10
	w.deroIs("miner", gtBond+gtBond/2+(N-1)*gtBond)
	w.deroIs("chal", (N-1)*gtBond)
	w.deroIs("j2", pot+100000)
	w.deroIs("j1", S-S/10)
	in := uint64(N)*gtBond*2 + S + 100000
	out := (gtBond + gtBond/2 + (N-1)*gtBond) + (N-1)*gtBond + pot + 100000 + S - S/10
	if out > in {
		t.Fatalf("attacker took out %d > put in %d", out, in)
	}
	t.Logf("R33 A02: attacker put in %d and took out %d (net %d); one stake judged one dispute", in, out, int64(out)-int64(in))
	w.must(scid, "Unstake", "j3", 0, nil, gtU("amount", 5000000))
	w.heldIs(scid, w.readU(scid, "treasury"), "solvent: only the treasury remains")
}

// A07: several challengers per claim; an unresolved dispute never mints and refunds every bond. With honest
// jurors the false claim is rejected and both challengers are paid.
func TestR33AuditA07SelfChallenge(t *testing.T) {
	ch := r33Names("x", 8)
	w := gtNew(t, append([]string{"owner", "miner", "sybil", "chal", "j1", "j2", "other"}, ch...)...)
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	w.must(scid, "Freeze", "owner", 0, nil)
	w.at(200)
	b := 10 * gtBond
	w.must(scid, "Claim", "miner", b, nil, gtU("from", 190), gtU("upto", 199), gtU("k", 10)) // false claim
	w.must(scid, "Challenge", "sybil", b, nil, gtU("i", 0))                                  // the miner's own Sybil
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 0))                                   // R33 A07: not shut out
	w.mustFail(scid, "Challenge", "chal", b, nil, "one slot per challenger", gtU("i", 0))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	if w.readU(scid, "c0s") != 4 || w.readU(scid, "minted") != 0 {
		t.Fatalf("status %d minted %d, want 4 (refunded) and 0", w.readU(scid, "c0s"), w.readU(scid, "minted"))
	}
	w.deroIs("miner", b)
	w.deroIs("sybil", b)
	w.deroIs("chal", b)
	w.tokenIs(scid, "miner", 0)
	w.heldIs(scid, 0, "every bond refunded")

	// honest jurors vote no on a second false claim: rejected, each challenger gets b + b/4
	w.must(scid, "Stake", "j1", 300000, nil)
	w.must(scid, "Stake", "j2", 100000, nil)
	w.at(300)
	w.must(scid, "Claim", "other", b, nil, gtU("from", 280), gtU("upto", 299), gtU("k", 10))
	w.must(scid, "Challenge", "sybil", b, nil, gtU("i", 1))
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 1))
	w.vote(scid, 1, "j1", 0, "a")
	w.vote(scid, 1, "j2", 0, "b")
	w.at(331)
	w.must(scid, "RevealVote", "j1", 0, nil, gtU("i", 1), gtU("vote", 0), gtS("salt", "a"))
	w.must(scid, "RevealVote", "j2", 0, nil, gtU("i", 1), gtU("vote", 0), gtS("salt", "b"))
	w.at(341)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 1))
	if w.readU(scid, "c1s") != 3 {
		t.Fatalf("status %d, want 3 (rejected)", w.readU(scid, "c1s"))
	}
	w.deroIs("sybil", b+b+b/4)
	w.deroIs("chal", b+b+b/4)
	w.deroIs("other", 0)
	w.tokenIs(scid, "other", 0)
	w.must(scid, "ClaimJuror", "j1", 0, nil, gtU("i", 1))
	w.must(scid, "ClaimJuror", "j2", 0, nil, gtU("i", 1))
	w.deroIs("j1", (b/2)*3/4)
	w.deroIs("j2", (b/2)/4)
	w.heldIs(scid, 400000+w.readU(scid, "treasury"), "stakes + treasury")

	// maxch = 8 challenger slots
	w.at(400)
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 390), gtU("upto", 399), gtU("k", 1))
	for _, x := range ch {
		w.must(scid, "Challenge", x, gtBond, nil, gtU("i", 2))
	}
	w.mustFail(scid, "Challenge", "chal", gtBond, nil, "maxch slots full", gtU("i", 2))
}

// A08: a copied juror commit cannot be revealed by the copier (the commit binds ADDRESS_STRING(SIGNER())); the
// copier is an unrevealed juror and is slashed, the original juror takes the pot.
func TestR33AuditA08CommitCopy(t *testing.T) {
	w, scid := gtAttestReady(t)
	w.must(scid, "Stake", "j1", 200000, nil)
	w.must(scid, "Stake", "j2", 200000, nil)
	w.at(200)
	b := gtBond
	w.must(scid, "Claim", "miner", b, nil, gtU("from", 199), gtU("upto", 199), gtU("k", 1))
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 0))
	h := gtCommitVote(0, 1, "secret-j1", w.gtAuditAddr("j1"))
	w.must(scid, "CommitVote", "j1", 0, nil, gtU("i", 0), gtS("h", h))
	w.must(scid, "CommitVote", "j2", 0, nil, gtU("i", 0), gtS("h", h)) // copied from the chain
	w.at(231)
	w.must(scid, "RevealVote", "j1", 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "secret-j1"))
	w.mustFail(scid, "RevealVote", "j2", 0, nil, "R33 A08: the copied commit is bound to j1", gtU("i", 0), gtU("vote", 1), gtS("salt", "secret-j1"))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.must(scid, "ClaimJuror", "j2", 0, nil, gtU("i", 0))
	w.must(scid, "ClaimJuror", "j1", 0, nil, gtU("i", 0))
	w.deroIs("j2", 0)
	w.deroIs("j1", (b-b/2)+200000/10)
	if w.stakeOf(scid, "j2") != 180000 || w.stakeOf(scid, "j1") != 200000 {
		t.Fatalf("stakes j1 %d j2 %d", w.stakeOf(scid, "j1"), w.stakeOf(scid, "j2"))
	}
	w.heldIs(scid, 380000+w.readU(scid, "treasury"), "stakes + treasury")
}

// A11: minstake 0 is refused, and a zero-weight juror cannot commit, so ClaimJuror can never divide by zero.
func TestR33AuditA11ZeroWeightDivZero(t *testing.T) {
	w := gtNew(t, "owner", "miner", "chal", "j1", "other")
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	set := func(minstake uint64) []rpc.Argument {
		return []rpc.Argument{gtU("bond", gtBond), gtU("reward", 100), gtU("window", 20), gtU("commitw", 10),
			gtU("revealw", 10), gtU("maxmb", 10), gtU("slash", 10), gtU("minstake", minstake)}
	}
	w.mustFail(scid, "SetParams", "owner", 0, nil, "R33 A11: minstake 0", set(0)...)
	w.must(scid, "SetParams", "owner", 0, nil, set(1)...)
	w.must(scid, "Freeze", "owner", 0, nil)
	w.must(scid, "Stake", "j1", 1, nil)
	w.must(scid, "Unstake", "j1", 0, nil, gtU("amount", 1))
	w.at(200)
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 199), gtU("upto", 199), gtU("k", 1))
	w.must(scid, "Challenge", "chal", gtBond, nil, gtU("i", 0))
	w.mustFail(scid, "CommitVote", "j1", 0, nil, "R33 A11: zero weight", gtU("i", 0), gtS("h", gtCommitVote(0, 1, "z", w.gtAuditAddr("j1"))))
	w.must(scid, "Stake", "j1", 1, nil) // a 1-atomic juror is fine: weight > 0
	w.vote(scid, 0, "j1", 1, "z")
	w.at(231)
	w.must(scid, "RevealVote", "j1", 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "z"))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.must(scid, "ClaimJuror", "j1", 0, nil, gtU("i", 0))
	w.must(scid, "Unstake", "j1", 0, nil, gtU("amount", 1))
	w.deroIs("j1", gtBond/2+1+1)
	w.heldIs(scid, w.readU(scid, "treasury"), "only the treasury")
}

// A17 (design): the contract cannot bind a claim to real mining; any address may claim any past range. The
// defence is the bonded challenge: with honest jurors the unbound claim is rejected and its bond is lost.
func TestR33AuditA17ClaimsUnbound(t *testing.T) {
	w, scid := gtAttestReady(t)
	w.must(scid, "Stake", "j1", 100000, nil)
	w.at(200)
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 1))
	w.must(scid, "Claim", "other", gtBond, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 1)) // same range, Sybil
	w.must(scid, "Challenge", "chal", gtBond, nil, gtU("i", 1))
	w.vote(scid, 1, "j1", 0, "s")
	w.at(231)
	w.must(scid, "RevealVote", "j1", 0, nil, gtU("i", 1), gtU("vote", 0), gtS("salt", "s"))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 1))
	w.tokenIs(scid, "miner", 100)
	w.tokenIs(scid, "other", 0)
	w.deroIs("other", 0)
	w.deroIs("chal", gtBond+gtBond/2)
}

// A09 (design): an unchallenged claim mints after window blocks; window is a bounded parameter that a deployment
// sets long (playbooks: 200 blocks on mainnet). The bound refuses a window that could wrap h + window.
func TestR33AuditA09UnchallengedWindow(t *testing.T) {
	w := gtNew(t, "owner", "miner", "other")
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	set := func(window uint64) []rpc.Argument {
		return []rpc.Argument{gtU("bond", gtBond), gtU("reward", 100), gtU("window", window), gtU("commitw", 10),
			gtU("revealw", 10), gtU("maxmb", 10), gtU("slash", 10), gtU("minstake", 100000)}
	}
	w.mustFail(scid, "SetParams", "owner", 0, nil, "R33 A15: window over 10^6", set(1000001)...)
	w.must(scid, "SetParams", "owner", 0, nil, set(1000)...)
	w.must(scid, "Freeze", "owner", 0, nil)
	w.at(200)
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 1))
	w.at(1200)
	w.mustFail(scid, "Finalize", "other", 0, nil, "inside the long window", gtU("i", 0))
	w.at(1201)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.tokenIs(scid, "miner", 100)
}

// ---------------------------------------------------------------- GT-A03 / A04: gt_audit

// A03: Settle is O(n) with a small constant (answers are tallied at Reveal): at maxn = 32 it fits with distinct
// answers (disputed) and with all-agreeing answers (paid), far below the 10,000,000 compute limit.
func TestR33AuditA03SettleLineLimit(t *testing.T) {
	for _, agree := range []bool{false, true} {
		names := r33Names("e", 32)
		w, scid := r33AuditReady(t, 32, names...)
		w.at(200)
		a := w.auditPost(scid, 100000, "good", "pepper")
		ans := func(nm string) string {
			if agree {
				return "good"
			}
			return "ans-" + nm
		}
		for _, nm := range names {
			w.auditEnter(scid, a, nm, ans(nm))
		}
		w.at(221)
		w.auditSponsor(scid, a, "good", "pepper")
		for j, nm := range names {
			w.auditReveal(scid, a, uint64(j), nm, ans(nm))
		}
		w.at(241)
		w.must(scid, "Settle", "owner", 0, nil, gtU("a", a))
		g := w.gas["gt_audit.bas:Settle"]
		t.Logf("n=32 agree=%v: Settle compute gas %d storage gas %d (limit 10000000)", agree, g[0], g[1])
		if g[0] > 7000000 {
			t.Fatalf("Settle compute gas %d over the 7M target", g[0])
		}
		want := uint64(0)
		if agree {
			want = 100000/32 + gtAuditBond
		} else {
			want = gtAuditBond
		}
		for j := range names {
			w.auditCredit(scid, a, uint64(j), want)
		}
	}
}

// A03 grief sweep: k Sybils with distinct junk answers can no longer lock a round: Settle passes for every k; any
// k >= 1 disputes the round and every bond (the Sybils' too) comes back, so the Sybils gain nothing.
func TestR33AuditA03SettleGriefSweep(t *testing.T) {
	for k := 0; k <= 16; k += 4 {
		sy := r33Names("y", k)
		hon := r33Names("h", 16-k)
		w, scid := gtAuditReady(t, append(sy, hon...)...)
		w.at(200)
		a := w.auditPost(scid, 100000, "good", "pepper")
		for _, nm := range sy {
			w.auditEnter(scid, a, nm, "junk-"+nm)
		}
		for _, nm := range hon {
			w.auditEnter(scid, a, nm, "good")
		}
		w.at(221)
		w.auditSponsor(scid, a, "good", "pepper")
		for j, nm := range sy {
			w.auditReveal(scid, a, uint64(j), nm, "junk-"+nm)
		}
		for j, nm := range hon {
			w.auditReveal(scid, a, uint64(len(sy)+j), nm, "good")
		}
		w.at(241)
		w.must(scid, "Settle", "owner", 0, nil, gtU("a", a))
		disp := w.readU(scid, "a0_disp")
		if (k > 0) != (disp == 1) {
			t.Fatalf("k=%d disp %d", k, disp)
		}
		for j := range sy {
			w.auditCredit(scid, a, uint64(j), gtAuditBond) // a Sybil only ever gets its own bond back
		}
		t.Logf("k=%d Sybils + %d honest: Settle ok, disputed %d, gas %v", k, 16-k, disp, w.gas["gt_audit.bas:Settle"])
	}
}

// A03 storage gas: an answer is capped at 256 bytes (Reveal refuses longer), and Settle no longer LOADs answers,
// so a round of capped answers settles within the 20,000 storage-gas cap of one tx.
func TestR33AuditA03SettleStorageGas(t *testing.T) {
	names := []string{"A", "B", "C", "D", "E"}
	w, scid := gtAuditReady(t, names...)
	w.at(200)
	a := w.auditPost(scid, 100000, "good", "pepper")
	long := map[string]string{"E": "good"}
	for _, nm := range names[:4] {
		long[nm] = strings.Repeat("x", 255) + nm[:1] // 256 bytes: the cap
	}
	w.auditEnter(scid, a, "A", strings.Repeat("y", 257))
	for _, nm := range names[1:] {
		w.auditEnter(scid, a, nm, long[nm])
	}
	w.at(221)
	w.auditSponsor(scid, a, "good", "pepper")
	w.mustFail(scid, "Reveal", "A", 0, nil, "R33 A03: answer over 256 bytes", gtU("a", a), gtU("j", 0),
		gtS("answer", strings.Repeat("y", 257)), gtS("salt", "s-A"))
	for j, nm := range names[1:] {
		_, gs, err := w.callFee(scid, "Reveal", nm, 0, 20000, gtU("a", a), gtU("j", uint64(j+1)), gtS("answer", long[nm]), gtS("salt", "s-"+nm))
		if err != nil {
			t.Fatalf("reveal %s with fee 20000: %v", nm, err)
		}
		t.Logf("Reveal %s (%d bytes) storage gas %d", nm, len(long[nm]), gs)
	}
	w.at(241)
	_, gs, err := w.callFee(scid, "Settle", "owner", 0, 20000, gtU("a", a))
	if err != nil {
		t.Fatalf("Settle at the 20000 storage-gas cap: %v", err)
	}
	t.Logf("Settle storage gas %d (cap 20000)", gs)
	if w.readU(scid, "a0_disp") != 1 { // B..D's answers differ from the sponsor's: disputed, every bond back
		t.Fatalf("disp %d", w.readU(scid, "a0_disp"))
	}
	for j := range names {
		w.auditCredit(scid, a, uint64(j), gtAuditBond)
	}
}

// A03 timeout: a round nobody settles never locks funds: after start + commitw + revealw + tmo every entrant pulls
// its bond back and the sponsor pulls the bounty back; from the first timeout withdrawal on, Settle is refused.
func TestR33AuditA03Timeout(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "other")
	w.at(200)
	a := w.auditPost(scid, 30000, "good", "pepper")
	w.auditEnter(scid, a, "A", "good")
	w.auditEnter(scid, a, "B", "good")
	w.at(221)
	w.auditSponsor(scid, a, "good", "pepper")
	w.auditReveal(scid, a, 0, "A", "good")
	dl := uint64(200 + 20 + 20 + 2000)
	w.at(dl)
	w.mustFail(scid, "Withdraw", "A", 0, nil, "not settled, timeout not reached", gtU("a", a), gtU("j", 0))
	w.mustFail(scid, "Reclaim", "owner", 0, nil, "not settled, timeout not reached", gtU("a", a))
	w.at(dl + 1)
	w.mustFail(scid, "Reclaim", "A", 0, nil, "not the sponsor", gtU("a", a))
	w.must(scid, "Withdraw", "A", 0, nil, gtU("a", a), gtU("j", 0))
	w.mustFail(scid, "Settle", "other", 0, nil, "timed out", gtU("a", a))
	w.mustFail(scid, "Withdraw", "A", 0, nil, "twice", gtU("a", a), gtU("j", 0))
	w.must(scid, "Withdraw", "B", 0, nil, gtU("a", a), gtU("j", 1))
	w.must(scid, "Reclaim", "owner", 0, nil, gtU("a", a))
	w.mustFail(scid, "Reclaim", "owner", 0, nil, "twice", gtU("a", a))
	w.deroIs("A", gtAuditBond)
	w.deroIs("B", gtAuditBond)
	w.deroIs("owner", 30000)
	w.heldIs(scid, 0, "every unit returned")
}

// A04: a Sybil majority never overrides a revealed sponsor answer and never slashes the minority: the round is
// disputed, every bond is refunded, the bounty returns to the sponsor; the Sybils gain nothing.
func TestR33AuditA04SybilMajority(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "S1", "S2", "other")
	w.at(200)
	a := w.auditPost(scid, 100000, "good", "pepper")
	w.auditEnter(scid, a, "A", "good")
	w.auditEnter(scid, a, "S1", "junk")
	w.auditEnter(scid, a, "S2", "junk")
	w.at(221)
	w.auditSponsor(scid, a, "good", "pepper")
	w.auditReveal(scid, a, 0, "A", "good")
	w.auditReveal(scid, a, 1, "S1", "junk")
	w.auditReveal(scid, a, 2, "S2", "junk")
	w.at(241)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a))
	for j := uint64(0); j < 3; j++ {
		w.auditCredit(scid, a, j, gtAuditBond)
	}
	if w.readU(scid, "a0_disp") != 1 || w.readU(scid, "a0_nw") != 0 || w.readU(scid, "a0_sb") != 100000 {
		t.Fatalf("disp %d nw %d sb %d", w.readU(scid, "a0_disp"), w.readU(scid, "a0_nw"), w.readU(scid, "a0_sb"))
	}
	w.must(scid, "Reclaim", "owner", 0, nil, gtU("a", a)) // disputed: at once
	for j, n := range []string{"A", "S1", "S2"} {
		w.must(scid, "Withdraw", n, 0, nil, gtU("a", a), gtU("j", uint64(j)))
		w.deroIs(n, gtAuditBond)
	}
	w.deroIs("owner", 100000)
	w.heldIs(scid, 0, "every unit returned")
}

// ---------------------------------------------------------------- GT-A05 / A06 / A14: gt_prize

// A05: a forfeited reveal bond goes to the treasury, never into the prize the withholder can win. With
// rbond >= prize, withholding to pick the winner never pays: the best reveal strategy is to reveal everything.
func TestR33AuditA05PrizeWithhold(t *testing.T) {
	rng := mrand.New(mrand.NewSource(33))
	const T = 200000
	prize, rb := int64(7000), int64(10000)
	fair, best := 0, 0
	for k := 0; k < T; k++ {
		nums := []uint64{rng.Uint64(), rng.Uint64(), rng.Uint64()}
		wts := []uint64{1000, 1000, 1000}
		all := r33PrizeWinner(nums, wts, []bool{true, true, true}) != 0
		if all {
			fair++
		}
		// attacker payoff of a strategy: prize if a Sybil wins, minus rbond per withheld reveal (R33: to the treasury)
		bestV, bestWin := int64(-1<<62), false
		for _, s := range []struct {
			rev []bool
			k   int64
		}{{[]bool{true, true, true}, 0}, {[]bool{true, true, false}, 1}, {[]bool{true, false, true}, 1}} {
			win := r33PrizeWinner(nums, wts, s.rev) != 0
			v := -rb * s.k
			if win {
				v += prize
			}
			if v > bestV {
				bestV, bestWin = v, win
			}
		}
		if bestWin {
			best++
		}
	}
	t.Logf("attacker win rate with the reveal choice: %.3f, fair (reveal all) %.3f", float64(best)/T, float64(fair)/T)
	if best != fair {
		t.Fatalf("withholding still pays: %d wins vs fair %d", best, fair)
	}
	// on chain: the PoC round; a2 withholds; a1 wins only the sponsor prize, a2's bond goes to the treasury
	w, _, pz := gtPrizeReady(t, "h", "a1", "a2")
	urb := uint64(rb)
	w.must(pz, "Fund", "sponsor", 7000, nil)
	nH, n1, n2 := uint64(500), uint64(600), uint64(2000)
	w.must(pz, "Enter", "h", 1000+urb+gtPrizeFee, nil, gtS("commit", gtCommitNum(nH, "h")))
	w.must(pz, "Enter", "a1", 1000+urb+gtPrizeFee, nil, gtS("commit", gtCommitNum(n1, "a1")))
	w.must(pz, "Enter", "a2", 1000+urb+gtPrizeFee, nil, gtS("commit", gtCommitNum(n2, "a2")))
	w.at(111)
	w.must(pz, "Reveal", "h", 0, nil, gtU("j", 0), gtU("num", nH), gtS("salt", "h"))
	w.must(pz, "Reveal", "a1", 0, nil, gtU("j", 1), gtU("num", n1), gtS("salt", "a1"))
	w.at(121)
	w.must(pz, "Draw", "sponsor", 0, nil)
	if w.readU(pz, "win0") != 1 || w.readU(pz, "paid0") != 7000 || w.readU(pz, "treasury") != urb+3*gtPrizeFee {
		t.Fatalf("winner %d paid %d treasury %d", w.readU(pz, "win0"), w.readU(pz, "paid0"), w.readU(pz, "treasury"))
	}
	w.must(pz, "Withdraw", "a1", 0, nil, gtU("r", 0), gtU("j", 1))
	w.must(pz, "Withdraw", "a2", 0, nil, gtU("r", 0), gtU("j", 2))
	w.deroIs("a1", 1000+urb+7000)
	w.deroIs("a2", 1000)
	in := 2 * (1000 + urb + gtPrizeFee)
	out := uint64(1000+urb+7000) + 1000
	t.Logf("withholding attacker put in %d and took out %d: net %d (it was +7000 before R33)", in, out, int64(out)-int64(in))
	if int64(out)-int64(in) >= 0 {
		t.Fatalf("withholding still profits")
	}
}

// r33PrizeWinner mirrors gt_prize Draw: pick = sum of revealed nums mod total revealed weight.
func r33PrizeWinner(nums []uint64, wts []uint64, revealed []bool) int {
	var sd, tw uint64
	for i := range nums {
		if revealed[i] {
			sd += nums[i]
			tw += wts[i]
		}
	}
	if tw == 0 {
		return -1
	}
	pick, acc := sd%tw, uint64(0)
	for i := range nums {
		if revealed[i] {
			acc += wts[i]
			if pick < acc {
				return i
			}
		}
	}
	return -1
}

// A06: a 1-atomic principal is refused (minp), and every entry pays a non-refundable fee to the treasury, so 32
// Sybils filling the round pay 32 * fee > the 7000 prize: the fill loses money.
func TestR33AuditA06PrizeSybilFill(t *testing.T) {
	sy := r33Names("s", 32)
	w, _, pz := gtPrizeReady(t, append(sy, "honest")...)
	rb := uint64(10000)
	w.must(pz, "Fund", "sponsor", 7000, nil)
	w.mustFail(pz, "Enter", sy[0], 1+rb+gtPrizeFee, nil, "R33 A06: principal under minp", gtS("commit", gtCommitNum(0, sy[0])))
	minp := w.readU(pz, "minp")
	for i, n := range sy {
		w.must(pz, "Enter", n, minp+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(uint64(i), n)))
	}
	w.mustFail(pz, "Enter", "honest", 50000+rb+gtPrizeFee, nil, "round full", gtS("commit", gtCommitNum(9, "x")))
	w.at(111)
	for i, n := range sy {
		w.must(pz, "Reveal", n, 0, nil, gtU("j", uint64(i)), gtU("num", uint64(i)), gtS("salt", n))
	}
	w.at(121)
	w.must(pz, "Draw", "sponsor", 0, nil)
	var out uint64
	for i, n := range sy {
		w.must(pz, "Withdraw", n, 0, nil, gtU("r", 0), gtU("j", uint64(i)))
		want := minp + rb
		if uint64(i) == w.readU(pz, "win0") {
			want += 7000
		}
		w.deroIs(n, want)
		out += want
	}
	in := 32 * (minp + rb + gtPrizeFee)
	t.Logf("32 Sybils put in %d and took out %d: net %d (the fill now costs 32 * fee = %d)", in, out, int64(out)-int64(in), 32*gtPrizeFee)
	if out >= in {
		t.Fatalf("the Sybil fill still profits")
	}
	if w.readU(pz, "treasury") != 32*gtPrizeFee {
		t.Fatalf("treasury %d, want %d", w.readU(pz, "treasury"), 32*gtPrizeFee)
	}
	w.heldIs(pz, 32*gtPrizeFee, "only the treasury")
	// SetFees: owner only, before Freeze, bounded
	w2 := gtNew(t, "owner", "x")
	w2.at(100)
	p2 := w2.install("gt_prize.bas", "owner")
	w2.mustFail(p2, "SetFees", "x", 0, nil, "not the owner", gtU("fee", 5), gtU("minp", 5))
	w2.mustFail(p2, "SetFees", "owner", 0, nil, "minp 0", gtU("fee", 5), gtU("minp", 0))
	w2.mustFail(p2, "SetFees", "owner", 0, nil, "fee over 10^12", gtU("fee", 1000000000001), gtU("minp", 5))
	w2.noDep(p2, "SetFees", "owner", gtU("fee", 5000), gtU("minp", 2000))
	w2.must(p2, "Freeze", "owner", 0, nil)
	w2.mustFail(p2, "SetFees", "owner", 0, nil, "frozen", gtU("fee", 5), gtU("minp", 5))
	if w2.readU(p2, "fee") != 5000 || w2.readU(p2, "minp") != 2000 {
		t.Fatalf("SetFees did not store")
	}
}

// A14 (design): reveal censorship cannot be tested in the simulator. What the contracts guarantee: a censored
// (forfeited) reveal bond goes to the treasury, not to the prize of the censor's round, and every reveal window is a
// bounded parameter a deployment sets long (the playbooks size it from the measured confirmation latency).
func TestR33AuditA14RevealWindows(t *testing.T) {
	w := gtNew(t, "owner", "a", "b", "sponsor")
	w.at(100)
	pz := w.install("gt_prize.bas", "owner")
	set := func(rw uint64) []rpc.Argument {
		return []rpc.Argument{gtU("rbond", 10000), gtU("commitw", 10), gtU("revealw", rw), gtU("maxn", 32), gtU("boost", 100), gtU("minmat", 100)}
	}
	w.mustFail(pz, "SetParams", "owner", 0, nil, "R33 A15: window over 10^6", set(1000001)...)
	w.must(pz, "SetParams", "owner", 0, nil, set(1000)...)
	w.must(pz, "Freeze", "owner", 0, nil)
	w.must(pz, "Fund", "sponsor", 7000, nil)
	w.must(pz, "Enter", "a", 5000+10000+gtPrizeFee, nil, gtS("commit", gtCommitNum(1, "a")))
	w.must(pz, "Enter", "b", 5000+10000+gtPrizeFee, nil, gtS("commit", gtCommitNum(2, "b")))
	w.at(111)
	w.must(pz, "Reveal", "a", 0, nil, gtU("j", 0), gtU("num", 1), gtS("salt", "a")) // b's reveal "censored"
	w.at(1110)
	w.mustFail(pz, "Draw", "sponsor", 0, nil, "the long reveal window is still open")
	w.at(1111)
	w.must(pz, "Draw", "sponsor", 0, nil)
	if w.readU(pz, "paid0") != 7000 || w.readU(pz, "treasury") != 10000+2*gtPrizeFee {
		t.Fatalf("paid %d treasury %d", w.readU(pz, "paid0"), w.readU(pz, "treasury"))
	}
}

// TestR33PrizeDraw64 (safe check, kept from the audit): gt_prize Draw at maxn = 64 stays inside the 2000-line /
// 11000-eval limits and far below the compute limit.
func TestR33PrizeDraw64(t *testing.T) {
	sy := r33Names("p", 64)
	w := gtNew(t, append([]string{"owner"}, sy...)...)
	w.at(100)
	pz := w.install("gt_prize.bas", "owner")
	w.must(pz, "SetParams", "owner", 0, nil, gtU("rbond", 10000), gtU("commitw", 10), gtU("revealw", 10), gtU("maxn", 64), gtU("boost", 0), gtU("minmat", 1))
	w.must(pz, "SetFees", "owner", 0, nil, gtU("fee", gtPrizeFee), gtU("minp", 1))
	w.must(pz, "Freeze", "owner", 0, nil)
	for i, n := range sy {
		w.must(pz, "Enter", n, 1+10000+gtPrizeFee, nil, gtS("commit", gtCommitNum(63-uint64(i), n)))
	}
	w.at(111)
	for i, n := range sy {
		w.must(pz, "Reveal", n, 0, nil, gtU("j", uint64(i)), gtU("num", 63-uint64(i)), gtS("salt", n)) // pick = 2016 % (64 * 1) = 32
	}
	w.at(121)
	w.must(pz, "Draw", "owner", 0, nil)
	g := w.gas["gt_prize.bas:Draw"]
	t.Logf("Draw with 64 entries OK, winner %d, gas %v", w.readU(pz, "win0"), g)
	if w.readU(pz, "win0") != 32 || g[0] > 7000000 {
		t.Fatalf("winner %d gas %d", w.readU(pz, "win0"), g[0])
	}
}

// ---------------------------------------------------------------- GT-A10 / A16: gt_service

// A10: a sponsor subsidy in an epoch with no fee payer rolls into the next epoch with a payer (R + e records it).
func TestR33AuditA10ServiceSponsorStuck(t *testing.T) {
	w, _, svc := gtServiceReady(t)
	w.mustFail(svc, "Sponsor", "sponsor", 100000, nil, "R33: Sponsor only after Freeze")
	w.must(svc, "Freeze", "owner", 0, nil)
	w.at(200)
	w.must(svc, "Sponsor", "sponsor", 100000, nil)
	w.at(5000)
	w.mustFail(svc, "ClaimRebate", "sponsor", 0, nil, "no weight", gtU("e", 2))
	w.must(svc, "Notarize", "u1", 1000, nil, gtS("doc", "late"))
	if w.readU(svc, "R2") != 50 || w.readU(svc, "P2") != 0 || w.readU(svc, "P50") != 100500 {
		t.Fatalf("roll: R2 %d P2 %d P50 %d", w.readU(svc, "R2"), w.readU(svc, "P2"), w.readU(svc, "P50"))
	}
	w.at(5100)
	w.must(svc, "ClaimRebate", "u1", 0, nil, gtU("e", 50))
	w.deroIs("u1", 100500)
	w.heldIs(svc, w.readU(svc, "treasury"), "only the treasury")
	if w.readU(svc, "treasury") != 500 {
		t.Fatalf("treasury %d", w.readU(svc, "treasury"))
	}
}

// A16: each notarization records its submitter next to its height.
func TestR33AuditA16Submitter(t *testing.T) {
	w, _, svc := gtServiceReady(t)
	w.must(svc, "Freeze", "owner", 0, nil)
	w.at(200)
	w.must(svc, "Notarize", "u1", 1000, nil, gtS("doc", "digest-1"))
	if w.read(svc, "bydigest-1") != string(w.addr["u1"].Compressed()) || w.readU(svc, "ddigest-1") != 200 {
		t.Fatalf("submitter or height not recorded")
	}
	w.mustFail(svc, "Notarize", "u2", 1000, nil, "first writer wins", gtS("doc", "digest-1"))
}

// ---------------------------------------------------------------- GT-A13 / A15: deposits, remainders, bounds

// A13: every entrypoint that expects no DERO refuses a deposit (all four contracts, one call each), and remainders
// that used to be orphaned go to the treasury (gt_service rebate floor; gt_attest slash with no coherent juror is
// covered by TestR32GTAttestNoJurorsUpholds, gt_prize forfeits by A05).
func TestR33AuditA13Deposits(t *testing.T) {
	// gt_attest
	w, at := gtAttestReady(t)
	w2 := gtNew(t, "owner")
	w2.at(100)
	at2 := w2.install("gt_attest.bas", "owner")
	w2.noDep(at2, "SetParams", "owner", gtU("bond", gtBond), gtU("reward", 100), gtU("window", 20), gtU("commitw", 10),
		gtU("revealw", 10), gtU("maxmb", 10), gtU("slash", 10), gtU("minstake", 100000))
	w2.noDep(at2, "Freeze", "owner")
	w.must(at, "Stake", "j1", 200000, nil)
	w.must(at, "Stake", "j2", 100000, nil)
	w.noDep(at, "Unstake", "j2", gtU("amount", 50000))
	w.at(200)
	w.must(at, "Claim", "miner", gtBond, nil, gtU("from", 199), gtU("upto", 199), gtU("k", 1))
	w.must(at, "Challenge", "chal", gtBond, nil, gtU("i", 0))
	w.noDep(at, "CommitVote", "j1", gtU("i", 0), gtS("h", gtCommitVote(0, 1, "a", w.gtAuditAddr("j1"))))
	w.at(231)
	w.noDep(at, "RevealVote", "j1", gtU("i", 0), gtU("vote", 1), gtS("salt", "a"))
	w.at(241)
	w.noDep(at, "Finalize", "other", gtU("i", 0))
	w.noDep(at, "ClaimJuror", "j1", gtU("i", 0))
	// gt_service: 3 equal payers share a pool of 1500 + 1 sponsor unit: the floor remainder 1 goes to the treasury
	w, mat, svc := gtServiceReady(t)
	w.noDep(svc, "SetParams", "owner", gtU("fee", 1000), gtU("rho", 50), gtU("boost", 100), gtU("epoch", 100), gtU("minmat", 100))
	w.noDep(svc, "Freeze", "owner")
	w.must(mat, "Claim", "miner", gtBond, nil, gtU("from", 90), gtU("upto", 99), gtU("k", 1))
	w.at(121)
	w.must(mat, "Finalize", "u1", 0, nil, gtU("i", 0))
	w.mustFail(svc, "StakeMAT", "miner", 1, map[crypto.Hash]uint64{mat: 100}, "R33 A13: DERO with a MAT stake")
	w.must(svc, "StakeMAT", "miner", 0, map[crypto.Hash]uint64{mat: 100})
	w.at(200)
	for _, n := range []string{"u1", "u2", "sponsor"} {
		w.must(svc, "Notarize", n, 1000, nil, gtS("doc", "d-"+n))
	}
	w.must(svc, "Sponsor", "owner", 1, nil)
	w.at(300)
	for _, n := range []string{"u1", "u2", "sponsor"} {
		w.noDep(svc, "ClaimRebate", n, gtU("e", 2))
		w.deroIs(n, 500)
	}
	w.noDep(svc, "UnstakeMAT", "miner", gtU("amount", 100))
	if w.readU(svc, "treasury") != 1501 {
		t.Fatalf("service treasury %d, want 1500 + the remainder 1", w.readU(svc, "treasury"))
	}
	w.noDep(svc, "WithdrawTreasury", "owner", gtU("amount", 1501))
	w.heldIs(svc, 0, "service drained exactly")
	// gt_prize
	w = gtNew(t, "owner", "a", "b")
	w.at(100)
	pz := w.install("gt_prize.bas", "owner")
	w.noDep(pz, "SetParams", "owner", gtU("rbond", 10000), gtU("commitw", 10), gtU("revealw", 10), gtU("maxn", 32), gtU("boost", 100), gtU("minmat", 100))
	w.noDep(pz, "SetMAT", "owner", gtS("scidhex", strings.Repeat("ab", 32)))
	w.noDep(pz, "Freeze", "owner")
	w.must(pz, "Enter", "a", 5000+10000+gtPrizeFee, nil, gtS("commit", gtCommitNum(1, "a")))
	w.at(111)
	w.noDep(pz, "Reveal", "a", gtU("j", 0), gtU("num", 1), gtS("salt", "a"))
	w.at(121)
	w.noDep(pz, "Draw", "b")
	w.noDep(pz, "Withdraw", "a", gtU("r", 0), gtU("j", 0))
	w.noDep(pz, "WithdrawTreasury", "owner", gtU("amount", gtPrizeFee))
	w.heldIs(pz, 0, "prize drained exactly")
	// gt_audit
	w = gtNew(t, "owner", "A", "B")
	w.at(100)
	au := w.install("gt_audit.bas", "owner")
	w.noDep(au, "SetParams", "owner", gtU("bond", gtAuditBond), gtU("commitw", 20), gtU("revealw", 20), gtU("maxn", 8))
	w.noDep(au, "Freeze", "owner")
	w.at(200)
	a := w.auditPost(au, 1000, "d", "s")
	w.auditEnter(au, a, "A", "d")
	w.at(221)
	w.noDep(au, "RevealSponsor", "owner", gtU("a", a), gtS("answer", "d"), gtS("salt", "s"))
	w.noDep(au, "Reveal", "A", gtU("a", a), gtU("j", 0), gtS("answer", "d"), gtS("salt", "s-A"))
	w.at(241)
	w.noDep(au, "Settle", "B", gtU("a", a))
	w.noDep(au, "Withdraw", "A", gtU("a", a), gtU("j", 0))
	w.at(300)
	a1 := w.auditPost(au, 1000, "d", "s")
	w.at(2341 + 100)
	w.noDep(au, "Reclaim", "owner", gtU("a", a1))
	w.heldIs(au, 0, "audit drained exactly")
}

// A15: every owner-set parameter is bounded so no product can wrap Uint64, and pro-rata payouts are exact (or a
// 10^-6 / 10^-5 scaled share) when pool * weight does not fit in 64 bits.
func TestR33AuditA15Bounds(t *testing.T) {
	w := gtNew(t, "owner", "miner", "chal", "j1", "j2", "u1", "u2", "other")
	w.at(100)
	at := w.install("gt_attest.bas", "owner")
	att := func(bond, reward, maxmb uint64) []rpc.Argument {
		return []rpc.Argument{gtU("bond", bond), gtU("reward", reward), gtU("window", 20), gtU("commitw", 10),
			gtU("revealw", 10), gtU("maxmb", maxmb), gtU("slash", 10), gtU("minstake", 100000)}
	}
	w.mustFail(at, "SetParams", "owner", 0, nil, "bond 2^63 (k*bond wraps)", att(1<<63, 100, 10)...)
	w.mustFail(at, "SetParams", "owner", 0, nil, "reward over 10^6", att(gtBond, 1000001, 10)...)
	w.mustFail(at, "SetParams", "owner", 0, nil, "maxmb over 100", att(gtBond, 100, 101)...)
	w.mustFail(at, "SetParams", "owner", 0, nil, "minstake over maxstake", gtU("bond", gtBond), gtU("reward", 100),
		gtU("window", 20), gtU("commitw", 10), gtU("revealw", 10), gtU("maxmb", 10), gtU("slash", 10), gtU("minstake", 1000000001))
	big := uint64(1000000000000)
	w.must(at, "SetParams", "owner", 0, nil, gtU("bond", big), gtU("reward", 100), gtU("window", 20), gtU("commitw", 10),
		gtU("revealw", 10), gtU("maxmb", 10), gtU("slash", 10), gtU("minstake", 1000000000))
	w.must(at, "Freeze", "owner", 0, nil)
	// pot * w = 5e11 * 1e9 does not fit in 64 bits: the scaled share pays exactly half each
	w.must(at, "Stake", "j1", 1000000000, nil)
	w.must(at, "Stake", "j2", 1000000000, nil)
	w.at(200)
	w.must(at, "Claim", "miner", big, nil, gtU("from", 199), gtU("upto", 199), gtU("k", 1))
	w.must(at, "Challenge", "chal", big, nil, gtU("i", 0))
	w.vote(at, 0, "j1", 1, "a")
	w.vote(at, 0, "j2", 1, "b")
	w.at(231)
	w.must(at, "RevealVote", "j1", 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "a"))
	w.must(at, "RevealVote", "j2", 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "b"))
	w.at(241)
	w.must(at, "Finalize", "other", 0, nil, gtU("i", 0))
	w.must(at, "ClaimJuror", "j1", 0, nil, gtU("i", 0))
	w.must(at, "ClaimJuror", "j2", 0, nil, gtU("i", 0))
	w.deroIs("j1", big/4)
	w.deroIs("j2", big/4)
	w.heldIs(at, 2000000000+w.readU(at, "treasury"), "stakes + treasury")

	svc := w.install("gt_service.bas", "owner")
	w.mustFail(svc, "SetParams", "owner", 0, nil, "boost over 1000", gtU("fee", 1000), gtU("rho", 0), gtU("boost", 1001), gtU("epoch", 100), gtU("minmat", 1))
	w.mustFail(svc, "SetParams", "owner", 0, nil, "fee over 10^12", gtU("fee", big+1), gtU("rho", 50), gtU("boost", 0), gtU("epoch", 100), gtU("minmat", 1))
	w.mustFail(svc, "SetParams", "owner", 0, nil, "epoch over 10^7", gtU("fee", 1000), gtU("rho", 50), gtU("boost", 0), gtU("epoch", 10000001), gtU("minmat", 1))
	w.must(svc, "SetParams", "owner", 0, nil, gtU("fee", big), gtU("rho", 50), gtU("boost", 0), gtU("epoch", 100), gtU("minmat", 1))
	w.must(svc, "Freeze", "owner", 0, nil)
	w.at(300) // epoch 3; P * w = 1e12 * 1e12 does not fit: the scaled share pays exactly half each
	w.must(svc, "Notarize", "u1", big, nil, gtS("doc", "x1"))
	w.must(svc, "Notarize", "u2", big, nil, gtS("doc", "x2"))
	w.at(400)
	w.must(svc, "ClaimRebate", "u1", 0, nil, gtU("e", 3))
	w.must(svc, "ClaimRebate", "u2", 0, nil, gtU("e", 3))
	w.deroIs("u1", big/2)
	w.deroIs("u2", big/2)
	w.heldIs(svc, w.readU(svc, "treasury"), "only the treasury")

	pz := w.install("gt_prize.bas", "owner")
	pr := func(rbond, boost uint64) []rpc.Argument {
		return []rpc.Argument{gtU("rbond", rbond), gtU("commitw", 10), gtU("revealw", 10), gtU("maxn", 32), gtU("boost", boost), gtU("minmat", 1)}
	}
	w.mustFail(pz, "SetParams", "owner", 0, nil, "boost over 1000", pr(10000, 1001)...)
	w.mustFail(pz, "SetParams", "owner", 0, nil, "rbond over 10^12", pr(big+1, 100)...)
	au := w.install("gt_audit.bas", "owner")
	w.mustFail(au, "SetParams", "owner", 0, nil, "bond over 10^12", gtU("bond", big+1), gtU("commitw", 20), gtU("revealw", 20), gtU("maxn", 8))
	w.mustFail(au, "SetParams", "owner", 0, nil, "window over 10^6", gtU("bond", 1), gtU("commitw", 1000001), gtU("revealw", 20), gtU("maxn", 8))
}

// ---------------------------------------------------------------- conservation, one honest round per contract

// gt_attest: one unchallenged claim and one challenged claim (2 challengers, 3 jurors with uneven stakes so the
// shares leave dust). Every atomic unit is accounted for at each step; finally everyone unstakes, the owner takes
// the treasury and the SC holds 0. Minted MAT equals the claimants' token balances.
func TestR33AuditConservationAttest(t *testing.T) {
	w := gtNew(t, "owner", "m1", "m2", "x1", "x2", "j1", "j2", "j3", "other")
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	w.must(scid, "Freeze", "owner", 0, nil)
	st := map[string]uint64{"j1": 333333, "j2": 222221, "j3": 100003}
	for j, v := range st {
		w.must(scid, "Stake", j, v, nil)
	}
	stakes := st["j1"] + st["j2"] + st["j3"]
	w.at(200)
	w.must(scid, "Claim", "m1", 3*gtBond, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 3))
	b := 5 * gtBond
	w.must(scid, "Claim", "m2", b, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 5))
	w.must(scid, "Challenge", "x1", b, nil, gtU("i", 1))
	w.must(scid, "Challenge", "x2", b, nil, gtU("i", 1))
	w.heldIs(scid, stakes+3*gtBond+3*b, "stakes + 1 claim bond + 1 claim bond + 2 challenge bonds")
	votes := map[string]uint64{"j1": 0, "j2": 0, "j3": 1}
	for j, v := range votes {
		w.vote(scid, 1, j, v, "s"+j)
	}
	w.at(221)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.heldIs(scid, stakes+3*b, "claim 0 paid")
	w.at(231)
	for j, v := range votes {
		w.must(scid, "RevealVote", j, 0, nil, gtU("i", 1), gtU("vote", v), gtS("salt", "s"+j))
	}
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 1))
	half, each := b/2, b/2/2
	w.deroIs("x1", b+each)
	w.deroIs("x2", b+each)
	pool := b - half
	w.heldIs(scid, stakes+pool+w.readU(scid, "treasury"), "escrows + juror pool + treasury")
	for _, j := range []string{"j1", "j2", "j3"} {
		w.must(scid, "ClaimJuror", j, 0, nil, gtU("i", 1))
	}
	cwin := st["j1"] + st["j2"]
	pot := pool + st["j3"]*10/100
	p1, p2 := pot*st["j1"]/cwin, pot*st["j2"]/cwin
	cut := (st["j3"]*10 + 99) / 100
	w.deroIs("j1", p1)
	w.deroIs("j2", p2)
	tr := pool + cut - p1 - p2
	if w.readU(scid, "treasury") != tr {
		t.Fatalf("treasury %d, want the swept dust %d", w.readU(scid, "treasury"), tr)
	}
	free := uint64(0)
	for _, j := range []string{"j1", "j2", "j3"} {
		free += w.stakeOf(scid, j)
	}
	if free != stakes-cut {
		t.Fatalf("free stakes %d, want %d", free, stakes-cut)
	}
	w.heldIs(scid, free+tr, "free stakes + treasury")
	for _, j := range []string{"j1", "j2", "j3"} {
		w.noDep(scid, "Unstake", j, gtU("amount", w.stakeOf(scid, j)))
	}
	w.noDep(scid, "WithdrawTreasury", "owner", gtU("amount", tr))
	w.heldIs(scid, 0, "every atomic unit paid out")
	w.deroIs("m1", 3*gtBond)
	w.deroIs("m2", 0)
	w.tokenIs(scid, "m1", 300)
	if w.readU(scid, "minted") != 300 {
		t.Fatalf("minted %d", w.readU(scid, "minted"))
	}
}

// gt_service: two epochs (one with a boosted payer, uneven weights, a sponsor; one empty sponsored epoch that rolls).
func TestR33AuditConservationService(t *testing.T) {
	w, mat, svc := gtServiceReady(t)
	w.must(svc, "SetParams", "owner", 0, nil, gtU("fee", 1001), gtU("rho", 33), gtU("boost", 50), gtU("epoch", 100), gtU("minmat", 100))
	w.must(svc, "Freeze", "owner", 0, nil)
	w.must(mat, "Claim", "miner", gtBond, nil, gtU("from", 90), gtU("upto", 99), gtU("k", 1))
	w.at(121)
	w.must(mat, "Finalize", "u1", 0, nil, gtU("i", 0))
	w.at(200)
	w.must(svc, "StakeMAT", "miner", 0, map[crypto.Hash]uint64{mat: 100})
	w.must(svc, "Notarize", "miner", 1001, nil, gtS("doc", "m-1"))
	w.must(svc, "Notarize", "u1", 1001, nil, gtS("doc", "u1-1"))
	w.must(svc, "Notarize", "u1", 1001, nil, gtS("doc", "u1-2"))
	w.must(svc, "Notarize", "u2", 1001, nil, gtS("doc", "u2-1"))
	w.must(svc, "Sponsor", "sponsor", 7777, nil)
	r := uint64(1001 * 33 / 100)
	P := 4*r + 7777
	w.heldIs(svc, P+w.readU(svc, "treasury"), "pool + treasury")
	w.at(300) // epoch 3: sponsored but nobody pays a fee
	w.must(svc, "Sponsor", "sponsor", 5000, nil)
	w.at(400)
	wm, w1, w2 := uint64(1001*150/100), uint64(2*1001), uint64(1001)
	W := wm + w1 + w2
	pays := map[string]uint64{"miner": P * wm / W, "u1": P * w1 / W, "u2": P * w2 / W}
	for _, n := range []string{"miner", "u1", "u2"} {
		w.noDep(svc, "ClaimRebate", n, gtU("e", 2))
	}
	w.deroIs("miner", gtBond+pays["miner"])
	w.deroIs("u1", pays["u1"])
	w.deroIs("u2", pays["u2"])
	dust := P - pays["miner"] - pays["u1"] - pays["u2"]
	tr := 4*(1001-r) + dust
	if w.readU(svc, "treasury") != tr {
		t.Fatalf("treasury %d, want fees %d + dust %d", w.readU(svc, "treasury"), 4*(1001-r), dust)
	}
	w.heldIs(svc, tr+5000, "treasury + the empty epoch's pool")
	w.must(svc, "Notarize", "u2", 1001, nil, gtS("doc", "u2-2")) // epoch 4: the epoch-3 pool rolls in
	w.at(500)
	w.must(svc, "ClaimRebate", "u2", 0, nil, gtU("e", 4))
	w.deroIs("u2", pays["u2"]+5000+r)
	tr += 1001 - r
	w.heldIs(svc, tr, "only the treasury")
	w.must(svc, "UnstakeMAT", "miner", 0, nil, gtU("amount", 100))
	w.must(svc, "WithdrawTreasury", "owner", 0, nil, gtU("amount", tr))
	w.heldIs(svc, 0, "every atomic unit paid out")
}

// gt_prize: one round, three entrants (one boosted by MAT), one withholds its reveal, a sponsor prize.
func TestR33AuditConservationPrize(t *testing.T) {
	w, mat, pz := gtPrizeReady(t, "a", "b", "c")
	rb := uint64(10000)
	w.must(mat, "Claim", "b", gtBond, nil, gtU("from", 90), gtU("upto", 99), gtU("k", 1))
	w.at(121)
	w.must(mat, "Finalize", "a", 0, nil, gtU("i", 0))
	w.must(pz, "Draw", "sponsor", 0, nil) // close round 0 (empty)
	w.must(pz, "StakeMAT", "b", 0, map[crypto.Hash]uint64{mat: 100})
	w.must(pz, "Fund", "sponsor", 9999, nil)
	dep := map[string]uint64{"a": 30000, "b": 15000, "c": 12345}
	for i, n := range []string{"a", "b", "c"} {
		w.must(pz, "Enter", n, dep[n]+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(uint64(77+i), n)))
	}
	w.heldIs(pz, 9999+30000+15000+12345+3*rb+3*gtPrizeFee, "prize + principals + bonds + fees")
	w.at(132)
	w.must(pz, "Reveal", "a", 0, nil, gtU("j", 0), gtU("num", 77), gtS("salt", "a"))
	w.must(pz, "Reveal", "b", 0, nil, gtU("j", 1), gtU("num", 78), gtS("salt", "b"))
	w.at(142)
	w.noDep(pz, "Draw", "sponsor")
	win := w.readU(pz, "win1")
	tr := 3*gtPrizeFee + rb
	if w.readU(pz, "treasury") != tr || w.readU(pz, "paid1") != 9999 {
		t.Fatalf("treasury %d paid %d", w.readU(pz, "treasury"), w.readU(pz, "paid1"))
	}
	w.heldIs(pz, 30000+15000+12345+2*rb+tr, "unwithdrawn principals + revealed bonds + treasury")
	for i, n := range []string{"a", "b", "c"} {
		w.must(pz, "Withdraw", n, 0, nil, gtU("r", 1), gtU("j", uint64(i)))
		want := dep[n]
		if n != "c" {
			want += rb
		}
		if uint64(i) == win {
			want += 9999
		}
		if n == "b" {
			want += gtBond // b's gt_attest claim bond came back at Finalize
		}
		w.deroIs(n, want)
	}
	w.heldIs(pz, tr, "only the treasury")
	w.must(pz, "WithdrawTreasury", "owner", 0, nil, gtU("amount", tr))
	w.heldIs(pz, 0, "every atomic unit paid out")
}

// gt_audit: an honest paid round with a remainder and a non-revealer, then a second round that joins the carry.
func TestR33AuditConservationAudit(t *testing.T) {
	w, scid := gtAuditReady(t, "A", "B", "C", "D", "other")
	w.at(200)
	a := w.auditPost(scid, 100001, "dg", "pp")
	for _, n := range []string{"A", "B", "C", "D"} {
		w.auditEnter(scid, a, n, "dg")
	}
	w.heldIs(scid, 100001+4*gtAuditBond, "bounty + bonds")
	w.at(221)
	w.auditSponsor(scid, a, "dg", "pp")
	for j, n := range []string{"A", "B", "C"} { // D never reveals
		w.auditReveal(scid, a, uint64(j), n, "dg")
	}
	w.at(241)
	w.noDep(scid, "Settle", "other", gtU("a", a))
	share := uint64(100001 / 3)
	rem := uint64(100001) - 3*share
	if w.readU(scid, "carry") != rem+gtAuditBond || w.readU(scid, "a0_disp") != 0 {
		t.Fatalf("carry %d disp %d", w.readU(scid, "carry"), w.readU(scid, "a0_disp"))
	}
	w.heldIs(scid, 3*(share+gtAuditBond)+w.readU(scid, "carry"), "credits + carry")
	for j, n := range []string{"A", "B", "C"} {
		w.must(scid, "Withdraw", n, 0, nil, gtU("a", a), gtU("j", uint64(j)))
		w.deroIs(n, share+gtAuditBond)
	}
	w.mustFail(scid, "Withdraw", "D", 0, nil, "forfeited", gtU("a", a), gtU("j", 3))
	carry := rem + gtAuditBond
	w.heldIs(scid, carry, "only the carry")
	w.at(300)
	a1 := w.auditPost(scid, 5000, "dg2", "pp")
	w.auditEnter(scid, a1, "A", "dg2")
	w.at(321)
	w.auditSponsor(scid, a1, "dg2", "pp")
	w.auditReveal(scid, a1, 0, "A", "dg2")
	w.at(341)
	w.must(scid, "Settle", "other", 0, nil, gtU("a", a1))
	w.must(scid, "Withdraw", "A", 0, nil, gtU("a", a1), gtU("j", 0))
	w.deroIs("A", share+gtAuditBond+5000+carry+gtAuditBond)
	w.heldIs(scid, 0, "every atomic unit paid out")
}
