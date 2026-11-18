package dvm

// R33-W4 / W6 / W7 (dero-game-theory-rft §7 rows GT-B4, GT-B6, GT-B7; D-21 non-consensus: tests only, no contract,
// DVM semantics or gas change). Reuses gtWorld (r32_gametheory_test.go), runAt (r33_blockproof_test.go), the
// gt_audit helpers (r32a_audit_test.go, r33_audit_test.go) and the gt_pool helpers (r33_pool_test.go).
//   W4 GT-B4: a briber controlling k Sybil auditors of gt_audit v2 reveals a wrong answer against an honest sponsor
//      and honest auditors, k = 1..maxn-1: the round is disputed, every bond and the bounty are returned, and the
//      briber's net is <= 0 (it pays at least the storage gas of its 3k calls, plus any bribe paid to real people).
//   W6 GT-B6: copied ProveBlock/ProveParent arguments move only the prover fee; Register derives the tag from the
//      signer; gt_beacon Publish is owner-only; a copied gt_audit commit cannot be revealed by another address.
//   W7 GT-B7: SanityCheckExternalTransfers (dvm/simulator.go:203-232) + StoreSCValue (dvm/sc.go:395-398): an SC's own-asset
//      over-send never reverts; the wrapped difference is computed but never stored (the counter stays 0).
// Simulator note (as in r32/r33): deposits are credited to the SC but never debited from the sender, so a sender's
// balance shows what the SC SENT it (plus reverted deposits, gtWorld.refund); the SC's own balance (w.held) is exact.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// ---------------------------------------------------------------- W4 / GT-B4: auditor bribery in gt_audit v2

// TestR33WBAuditBriberyW4: for every k = 1..maxn-1 the briber's Sybils reveal "evil" against the sponsor's and the
// honest auditors' "good". gt_audit.bas Settle lines 175-185 set disp = 1 whenever a revealed answer differs from
// the sponsor's, md = 2 refunds every bond (lines 250/255) and line 320 owes the bounty back to the sponsor, who
// reclaims at once (Reclaim line 140). The bribed side never receives the bounty.
func TestR33WBAuditBriberyW4(t *testing.T) {
	const maxn = uint64(8)
	const fund = uint64(100000)
	const fee = uint64(20000) // storage-gas limit min(fee, 20000), as on mainnet
	for k := uint64(1); k < maxn; k++ {
		nh := maxn - k
		honest, sybil := r33Names("H", int(nh)), r33Names("B", int(k))
		names := append(append(append([]string{}, honest...), sybil...), "other")
		w, sc := r33AuditReady(t, maxn, names...)
		w.at(200)
		a := w.auditPost(sc, fund, "good", "pepper")
		// entry order interleaved so the Sybils are not all at the end
		order := []string{}
		for i := 0; i < int(maxn); i++ {
			if i%2 == 0 && len(honest) > 0 || len(sybil) == 0 {
				order, honest = append(order, honest[0]), honest[1:]
			} else {
				order, sybil = append(order, sybil[0]), sybil[1:]
			}
		}
		isSybil := func(n string) bool { return strings.HasPrefix(n, "B") }
		var briberGas uint64 // storage gas of the briber's calls: the fee floor (fees pay storage gas, dvm/sc.go:247-252)
		brCall := func(entry, n string, dep uint64, args ...rpc.Argument) {
			t.Helper()
			_, gs, err := w.callFee(sc, entry, n, dep, fee, args...)
			if err != nil {
				t.Fatalf("k=%d %s by %s: %v", k, entry, n, err)
			}
			briberGas += gs
		}
		for _, n := range order {
			if isSybil(n) {
				brCall("Enter", n, gtAuditBond, gtU("a", a), gtS("commit", gtAuditCommit("evil", "s-"+n, w.gtAuditAddr(n))))
			} else {
				w.auditEnter(sc, a, n, "good")
			}
		}
		w.heldIs(sc, fund+maxn*gtAuditBond, "bounty + bonds")
		w.at(221)
		w.auditSponsor(sc, a, "good", "pepper")
		for j, n := range order {
			if isSybil(n) {
				brCall("Reveal", n, 0, gtU("a", a), gtU("j", uint64(j)), gtS("answer", "evil"), gtS("salt", "s-"+n))
			} else {
				w.auditReveal(sc, a, uint64(j), n, "good")
			}
		}
		w.at(241)
		w.must(sc, "Settle", "other", 0, nil, gtU("a", a))
		p := fmt.Sprintf("a%d_", a)
		if w.readU(sc, p+"disp") != 1 || w.readU(sc, p+"refund") != 1 || w.readU(sc, p+"nw") != 0 ||
			w.read(sc, p+"win") != "" || w.readU(sc, p+"sb") != fund || w.readU(sc, p+"share") != 0 || w.readU(sc, "carry") != 0 {
			t.Fatalf("k=%d: disp %d refund %d nw %d win %v sb %d share %d carry %d", k, w.readU(sc, p+"disp"), w.readU(sc, p+"refund"),
				w.readU(sc, p+"nw"), w.read(sc, p+"win"), w.readU(sc, p+"sb"), w.readU(sc, p+"share"), w.readU(sc, "carry"))
		}
		for j := range order {
			w.auditCredit(sc, a, uint64(j), gtAuditBond) // every bond refunded, nobody gets a share of the bounty
		}
		w.must(sc, "Reclaim", "owner", 0, nil, gtU("a", a)) // disputed: at once, no timeout wait
		var briberIn uint64
		for j, n := range order {
			if isSybil(n) {
				brCall("Withdraw", n, 0, gtU("a", a), gtU("j", uint64(j)))
				briberIn += gtAuditBond
			} else {
				w.must(sc, "Withdraw", n, 0, nil, gtU("a", a), gtU("j", uint64(j)))
			}
			w.deroIs(n, gtAuditBond) // honest and bribed alike: exactly the bond back (deposit not debited, see header)
			w.mustFail(sc, "Withdraw", n, 0, nil, "a credit is paid once", gtU("a", a), gtU("j", uint64(j)))
		}
		w.deroIs("owner", fund) // the whole bounty back to the sponsor
		w.mustFail(sc, "Reclaim", "owner", 0, nil, "reclaimed once", gtU("a", a))
		w.heldIs(sc, 0, "every unit returned")
		briberOut := k * gtAuditBond
		netFlows := int64(briberIn) - int64(briberOut) // DERO the briber got from the SC minus DERO it sent to the SC
		net := netFlows - int64(briberGas)             // minus the storage-gas floor of its 3k fees
		if netFlows != 0 || net > 0 || briberGas == 0 {
			t.Fatalf("k=%d: briber net flows %d, net %d (gas %d)", k, netFlows, net, briberGas)
		}
		// honest auditors' forgone share: what an undisputed round would have paid them (grief cost, not a fund loss)
		t.Logf("W4 k=%d honest=%d: disputed=1 bounty->sponsor %d, bonds refunded %d/%d; briber flows %+d, fee floor %d -> net <= %d atomic units (minus any bribe paid to real auditors); honest forgone share %d each",
			k, nh, fund, maxn, maxn, netFlows, briberGas, net, fund/nh)
	}
}

// ---------------------------------------------------------------- W6 / GT-B6: front-running public arguments

// poolSnap reads the credit, forensics and pool state a proof of block h (epoch e) writes for the given tags
func poolSnap(w *gtWorld, sc crypto.Hash, e uint64, hs []uint64, tags []string) map[string]interface{} {
	keys := []string{fmt.Sprintf("TW%d", e), fmt.Sprintf("P%d", e), fmt.Sprintf("kn%d", e), fmt.Sprintf("km%d", e), "burned"}
	for _, tg := range tags {
		keys = append(keys, fmt.Sprintf("w%d_%s", e, tg), fmt.Sprintf("W%d_%s", e, tg))
	}
	for _, h := range hs {
		keys = append(keys, fmt.Sprintf("pr%d", h), fmt.Sprintf("tip%d", h), fmt.Sprintf("t%d", h))
	}
	out := map[string]interface{}{"__held": w.held(sc, crypto.ZEROHASH)}
	for _, k := range keys {
		out[k] = w.read(sc, k)
	}
	return out
}

func snapEq(t *testing.T, what string, a, b map[string]interface{}) {
	t.Helper()
	for k, v := range a {
		if fmt.Sprint(b[k]) != fmt.Sprint(v) {
			t.Fatalf("%s: %s = %v, reference %v", what, k, b[k], v)
		}
	}
}

// TestR33WBFrontRunProveBlockW6a: eve copies prover's pending ProveBlock(h, hx, ntx) and executes first. Credits
// are a function of the authentic bytes only (gt_pool.bas pproc lines 190-280), so they equal the honest run's;
// the signer only selects who gets pfee (line 330). prover's call then hits "pr<h>" (ProveBlock line 40) and
// reverts with no state or DERO moved (on chain prover still pays its tx fee: a reverted SC tx keeps the fee).
func TestR33WBFrontRunProveBlockW6a(t *testing.T) {
	setup := func() (*r33Pool, string, string, string, crypto.Hash, uint64) {
		p := r33PoolReady(t)
		w, sc := p.w, p.scid
		ta, tb := w.poolTag("alice"), w.poolTag("bob")
		w.at(r33E1*r33Len + 10)
		w.must(sc, "Register", "alice", 1000, nil)
		w.must(sc, "Register", "bob", 1000, nil)
		w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
		hx, blid, _ := r33Tagged(t, p.blk[0], []string{ta, ta, ta, tb, tb})
		if _, _, err := w.runAt(sc, blid, p.blk[0].Height, "Anchor", "prover", 0); err != nil {
			t.Fatalf("anchor: %v", err)
		}
		return p, ta, tb, hx, blid, p.blk[0].Height
	}
	var later crypto.Hash
	later[0], later[1] = 0x5a, 0xa5
	prove := func(p *r33Pool, who, hx string, h uint64) error {
		_, _, err := p.w.runAt(p.scid, later, h+1, "ProveBlock", who, 20000, gtU("h", h), gtS("hx", hx), gtU("ntx", p.blk[0].Txcount))
		return err
	}
	// reference: prover proves
	ref, ta, tb, hx, _, h := setup()
	if err := prove(ref, "prover", hx, h); err != nil {
		t.Fatalf("reference proof: %v", err)
	}
	want := poolSnap(ref.w, ref.scid, r33E1, []uint64{h}, []string{ta, tb})
	pfee := ref.w.readU(ref.scid, "pfee")
	ref.w.deroIs("prover", pfee)
	// attack: eve submits the same arguments first
	atk, _, _, hx2, _, _ := setup()
	if hx2 != hx {
		t.Fatalf("setups differ")
	}
	if err := prove(atk, "eve", hx, h); err != nil {
		t.Fatalf("copied proof: %v", err)
	}
	snapEq(t, "copied proof vs honest proof", want, poolSnap(atk.w, atk.scid, r33E1, []uint64{h}, []string{ta, tb}))
	before := poolSnap(atk.w, atk.scid, r33E1, []uint64{h}, []string{ta, tb})
	if err := prove(atk, "prover", hx, h); err == nil {
		t.Fatalf("the original proof succeeded after the copy (double credit)")
	}
	snapEq(t, "after the original's revert", before, poolSnap(atk.w, atk.scid, r33E1, []uint64{h}, []string{ta, tb}))
	atk.w.deroIs("eve", pfee)
	atk.w.deroIs("prover", 0)
	if atk.w.readU(atk.scid, fmt.Sprintf("w%d_%s", r33E1, ta)) != 3 || atk.w.readU(atk.scid, fmt.Sprintf("w%d_%s", r33E1, tb)) != 2 {
		t.Fatalf("member credits moved")
	}
	// the members are paid the same either way
	for _, x := range []*r33Pool{ref, atk} {
		x.w.at(r33ClaimOpen(r33E1))
		x.w.must(x.scid, "Claim", "alice", 0, nil, gtU("e", r33E1))
		x.w.must(x.scid, "Claim", "bob", 0, nil, gtU("e", r33E1))
		x.w.mustFail(x.scid, "Claim", "eve", 0, nil, "the copier is not a member", gtU("e", r33E1))
	}
	for _, k := range []string{fmt.Sprintf("c%d_%s", r33E1, ta), fmt.Sprintf("c%d_%s", r33E1, tb)} {
		if ref.w.readU(ref.scid, k) != atk.w.readU(atk.scid, k) {
			t.Fatalf("claim %s differs: %d vs %d", k, ref.w.readU(ref.scid, k), atk.w.readU(atk.scid, k))
		}
	}
	atk.conserve(t, []uint64{r33E1}, nil)
	t.Logf("W6a ProveBlock copy: credits identical (alice 3, bob 2), copier got pfee %d, original reverted with state unchanged", pfee)
}

// TestR33WBFrontRunProveParentW6a: the same for ProveParent (ProveParent line 30 refuses a proven parent).
func TestR33WBFrontRunProveParentW6a(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta := w.poolTag("alice")
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
	raw2, _ := hex.DecodeString(p.blk[1].Blob)
	q2 := len(raw2) - 1 - 48*10 - 1
	phx, pid, _ := r33Tagged(t, p.blk[0], []string{ta, ta, ta})
	copy(raw2[q2-32:q2], pid[:])
	chx, cid, _ := r33Tagged(t, r33Block{Height: p.blk[1].Height, Blob: hex.EncodeToString(raw2)}, []string{ta, ta})
	h := p.blk[1].Height
	if _, _, err := w.runAt(sc, cid, h, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	var later crypto.Hash
	later[0] = 0x6b
	if _, _, err := w.runAt(sc, later, h+1, "ProveBlock", "prover", 20000, gtU("h", h), gtS("hx", chx), gtU("ntx", 0)); err != nil {
		t.Fatalf("prove child: %v", err)
	}
	pfee := w.readU(sc, "pfee")
	pp := func(who string) error {
		_, _, err := w.runAt(sc, later, h+1, "ProveParent", who, 20000, gtU("h", h-1), gtS("hx", phx), gtU("ntx", 0))
		return err
	}
	if err := pp("eve"); err != nil {
		t.Fatalf("copied ProveParent: %v", err)
	}
	before := poolSnap(w, sc, r33E1, []uint64{h, h - 1}, []string{ta})
	if pp("prover") == nil {
		t.Fatalf("the original ProveParent succeeded after the copy")
	}
	snapEq(t, "after the original's revert", before, poolSnap(w, sc, r33E1, []uint64{h, h - 1}, []string{ta}))
	if got := w.readU(sc, fmt.Sprintf("w%d_%s", r33E1, ta)); got != 5 {
		t.Fatalf("credits %d, want 5", got)
	}
	w.deroIs("eve", pfee)
	w.deroIs("prover", pfee) // its own child proof only
	p.conserve(t, []uint64{r33E1}, nil)
}

// TestR33WBRegisterRaceW6b: Register has no arguments; its tag is mytag() = HEX(SUBSTR(SHA3256(SIGNER()), 0, 8))
// (gt_pool.bas mytag line 10), so a copier that races alice's Register registers ITS OWN tag; tag_<t> holds one
// signer (Register line 50 refuses an existing tag); Lock/Unlock/Claim resolve the tag from the signer again, so the
// copier can never act on alice's tag. Two keys sharing an 8-byte tag need ~2^64 work (GT-B32).
func TestR33WBRegisterRaceW6b(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta, te := w.poolTag("alice"), w.poolTag("eve")
	if ta == te {
		t.Fatalf("test keys share a tag")
	}
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "eve", 1000, nil) // the "copy" of alice's pending Register lands first
	if w.read(sc, "tag_"+te) != string(w.addr["eve"].Compressed()) || w.read(sc, "tag_"+ta) != nil {
		t.Fatalf("eve's Register wrote %v / %v", w.read(sc, "tag_"+te), w.read(sc, "tag_"+ta))
	}
	w.must(sc, "Register", "alice", 1000, nil) // alice is not blocked
	if w.read(sc, "tag_"+ta) != string(w.addr["alice"].Compressed()) || w.readU(sc, "nm") != 2 {
		t.Fatalf("alice's tag")
	}
	w.mustFail(sc, "Register", "eve", 1000, nil, "a tag registers once")
	w.mustFail(sc, "Register", "alice", 1000, nil, "a tag registers once")
	if w.read(sc, "tag_"+ta) != string(w.addr["alice"].Compressed()) || w.read(sc, "tag_"+te) != string(w.addr["eve"].Compressed()) {
		t.Fatalf("a tag changed holder")
	}
	w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
	if err := p.proveAt(t, 0, []string{ta, ta, ta}, "prover"); err != nil {
		t.Fatalf("prove: %v", err)
	}
	w.at(r33ClaimOpen(r33E1))
	w.mustFail(sc, "Claim", "eve", 0, nil, "eve's own tag has no credit; alice's is not hers", gtU("e", r33E1))
	w.must(sc, "Claim", "alice", 0, nil, gtU("e", r33E1))
	w.deroIs("eve", 0)
	if w.readU(sc, fmt.Sprintf("c%d_%s", r33E1, ta)) == 0 {
		t.Fatalf("alice paid nothing")
	}
	p.conserve(t, []uint64{r33E1}, nil)
}

// TestR33WBBeaconPublishW6c: gt_beacon Publish is owner-only (gt_beacon.bas Publish line 20); a copied Publish by
// anyone else reverts and writes nothing, so neither the owner's value nor the key can be pre-empted.
func TestR33WBBeaconPublishW6c(t *testing.T) {
	w := gtNew(t, "owner", "eve")
	w.at(1000)
	sc := w.install("gt_beacon.bas", "owner")
	args := []rpc.Argument{gtS("k", "pool_scid"), gtS("v", strings.Repeat("ab", 32)), gtU("from", 900), gtU("upto", 1000)}
	w.mustFail(sc, "Publish", "eve", 0, nil, "owner only: a copied Publish", args...)
	w.mustFail(sc, "Publish", "eve", 0, nil, "owner only: a squatted key", gtS("k", "pool_scid"), gtS("v", "fake"), gtU("from", 900), gtU("upto", 1000))
	if w.readU(sc, "nent") != 0 || w.read(sc, "v_pool_scid") != nil || w.read(sc, "h_pool_scid") != nil {
		t.Fatalf("a non-owner wrote an entry")
	}
	w.must(sc, "Publish", "owner", 0, nil, args...)
	if w.readU(sc, "nent") != 1 || w.read(sc, "v_pool_scid") != strings.Repeat("ab", 32) || w.readU(sc, "h_pool_scid") != 1000 {
		t.Fatalf("owner publish")
	}
	w.mustFail(sc, "Publish", "eve", 0, nil, "owner only: an overwrite", gtS("k", "pool_scid"), gtS("v", "fake"), gtU("from", 900), gtU("upto", 1000))
	if w.read(sc, "v_pool_scid") != strings.Repeat("ab", 32) {
		t.Fatalf("entry overwritten")
	}
	w.heldIs(sc, 0, "the beacon holds nothing")
}

// TestR33WBAuditCommitCopyW6d: eve copies A's commit from the chain and enters with it (the commit string itself is
// accepted, Enter line 120 checks only its length). Reveal line 120 hashes ADDRESS_STRING(SIGNER()) into the commit,
// so eve cannot open it with A's (answer, salt) once A reveals; eve is a non-revealer on path 1 and forfeits her
// bond to carry (Settle line 275), and A's reward is untouched.
func TestR33WBAuditCommitCopyW6d(t *testing.T) {
	w, sc := gtAuditReady(t, "A", "eve", "other")
	w.at(200)
	a := w.auditPost(sc, 100000, "good", "pepper")
	w.auditEnter(sc, a, "A", "good")
	copied := w.read(sc, fmt.Sprintf("a%d_0_c", a)).(string)
	w.must(sc, "Enter", "eve", gtAuditBond, nil, gtU("a", a), gtS("commit", copied))
	w.at(221)
	w.auditSponsor(sc, a, "good", "pepper")
	w.auditReveal(sc, a, 0, "A", "good") // A's answer and salt are now public
	w.mustFail(sc, "Reveal", "eve", 0, nil, "the copied commit is bound to A's address", gtU("a", a), gtU("j", 1), gtS("answer", "good"), gtS("salt", "s-A"))
	w.mustFail(sc, "Reveal", "eve", 0, nil, "and not revealable at A's index", gtU("a", a), gtU("j", 0), gtS("answer", "good"), gtS("salt", "s-A"))
	w.at(241)
	w.must(sc, "Settle", "other", 0, nil, gtU("a", a))
	w.auditCredit(sc, a, 0, 100000+gtAuditBond)
	w.auditCredit(sc, a, 1, 0)
	if w.readU(sc, "carry") != gtAuditBond || w.readU(sc, fmt.Sprintf("a%d_disp", a)) != 0 {
		t.Fatalf("carry %d disp %d", w.readU(sc, "carry"), w.readU(sc, fmt.Sprintf("a%d_disp", a)))
	}
	w.must(sc, "Withdraw", "A", 0, nil, gtU("a", a), gtU("j", 0))
	w.mustFail(sc, "Withdraw", "eve", 0, nil, "the copier forfeited its bond", gtU("a", a), gtU("j", 1))
	w.deroIs("A", 100000+gtAuditBond)
	w.deroIs("eve", 0)
	w.heldIs(sc, gtAuditBond, "the forfeited bond waits in carry for the next Post")
}

// ---------------------------------------------------------------- W7 / GT-B7: the SC's own-asset counter

const r33OwnTokenCode = `Function Initialize() Uint64
10 RETURN 0
End Function

Function Mint(amt Uint64) Uint64
10 SEND_ASSET_TO_ADDRESS(SIGNER(), amt, SCID())
20 RETURN 0
End Function

Function Mint2(a1 Uint64, a2 Uint64) Uint64
10 SEND_ASSET_TO_ADDRESS(SIGNER(), a1, SCID())
20 SEND_ASSET_TO_ADDRESS(SIGNER(), a2, SCID())
30 RETURN 0
End Function

Function SendDero(amt Uint64) Uint64
10 SEND_DERO_TO_ADDRESS(SIGNER(), amt)
20 RETURN 0
End Function
`

// TestR33WBOwnAssetCounterW7 pins dvm/simulator.go:203-232 (the same function decides on chain,
// blockchain/transaction_execute.go:409). OBSERVED: a contract that sends more of its OWN asset than it holds
// (it holds none: sending is minting) neither reverts nor errors: the overflow check (simulator.go:211) and the
// underflow check (simulator.go:223) both skip asset == scid. simulator.go:229 computes the wrapped uint64
// difference stored_value - value, but simulator.go:230 hands it to StoreSCValue, which DISCARDS every write whose
// key equals the SCID (dvm/sc.go:395-398, "an scid can mint its assets infinitely"). So nothing wraps in state: the
// own-asset counter is never written and reads 0 forever. Deposits of the own token back into the SC are discarded
// the same way (dvm/sc.go:209-213 also goes through StoreSCValue): returned tokens leave circulation. The recipient
// is credited the full amount in the SC's token tree (ProcessExternal, simulator.go:308ff). Two sends in one call
// whose sum exceeds 2^64 wrap the per-asset total (simulator.go:215), which is unused for the own asset, while the
// recipient's homomorphic balance gets the unwrapped big-integer sum.
// SAFE: the own token is unbounded by design, so a "held" counter for it would mean nothing and none is kept; no
// DVM builtin reads it (DEROVALUE/ASSETVALUE read only this call's deposit, dvm_functions.go:435-457); DERO and
// foreign assets keep the underflow revert (asserted below); DERO.GetSC lists only 32-byte keys with 8-byte values as
// balances (cmd/derod/rpc/rpc_dero_getsc.go:123-124), so it shows no own-asset balance at all. The rft text
// "stores stored_value - value" (GT-B7) is therefore corrected: the value is computed but never stored. Residual
// footgun, not a supply or consensus issue: a contract that mints >= 2^64 to one holder in total leaves that holder a
// balance no wallet can decode (its brute-force range is uint64).
func TestR33WBOwnAssetCounterW7(t *testing.T) {
	w := gtNew(t, "owner", "alice", "bob")
	w.at(1000)
	sc, _, _, err := w.s.SCInstall(r33OwnTokenCode, map[crypto.Hash]uint64{}, rpc.Arguments{}, w.addr["owner"], 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	counter := func(want uint64, what string) {
		t.Helper()
		if got := w.held(sc, sc); got != want {
			t.Fatalf("%s: own-asset counter %d, want %d", what, got, want)
		}
		if _, err := w.data(sc).Get(sc[:]); err == nil {
			t.Fatalf("%s: an own-asset counter key was written to the SC tree", what)
		}
	}
	counter(0, "fresh SC")
	// 1. mint 100 while holding 0: no revert; alice gets 100; 0 - 100 wraps in simulator.go:229 but is never stored
	w.must(sc, "Mint", "alice", 0, nil, gtU("amt", 100))
	w.tokenIs(sc, "alice", 100)
	counter(0, "after sending 100 it never held")
	// 2. a deposit of the own token back into the SC is discarded as well (dvm/sc.go:213 -> sc.go:396)
	w.must(sc, "Mint", "bob", 0, map[crypto.Hash]uint64{sc: 30}, gtU("amt", 0))
	counter(0, "after a 30-token deposit")
	// 3. send again: still no revert, no counter
	w.must(sc, "Mint", "alice", 0, nil, gtU("amt", 50))
	w.tokenIs(sc, "alice", 150)
	counter(0, "after a second send")
	// 4. per-asset total wrap: 2^63 + 2^63 -> total 0 (simulator.go:215); bob is credited 2^64 in his ElGamal
	//    balance (beyond any uint64 a wallet can decode)
	half := uint64(1) << 63
	w.must(sc, "Mint2", "bob", 0, nil, gtU("a1", half), gtU("a2", half))
	counter(0, "after two 2^63 sends")
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	e := crypto.ConstructElGamal((*bn256.G1)(w.addr["bob"].PublicKey), crypto.ElGamal_BASE_G).Plus(two64)
	if got := r27_balance(t, w.data(sc).Tree, w.addr["bob"].Compressed()); string(got) != string((&crypto.NonceBalance{Balance: e}).Serialize()) {
		t.Fatalf("bob's own-token balance is not 2^64")
	}
	// 5. contrast: DERO keeps the underflow check (simulator.go:223): sending 1 DERO the SC does not hold reverts
	if err := w.call(sc, "SendDero", "alice", 0, nil, gtU("amt", 1)); err == nil || !strings.Contains(err.Error(), "underflow") {
		t.Fatalf("DERO send beyond holdings: %v, want the underflow revert", err)
	}
	w.must(sc, "SendDero", "alice", 5, nil, gtU("amt", 5)) // what it holds is fine
	w.deroIs("alice", 5)
	w.heldIs(sc, 0, "DERO exact")
	t.Logf("W7: own-asset send beyond holdings -> success, no error, wrapped difference computed (simulator.go:229) but discarded (sc.go:395-398), counter stays 0; DERO -> underflow revert")
}
