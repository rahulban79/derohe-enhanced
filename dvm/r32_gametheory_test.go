package dvm

// R32 (dero-game-theory-rft; D-GT-3; D-21 non-consensus: tests only, no DVM semantics or gas change).
// Executes the three R32 mechanism contracts (gametheory/contracts/*.bas) in the in-process DVM simulator
// with several signers and a controlled block height, and checks every DERO and token flow exactly:
//   M1 gt_attest.bas  optimistic miner-attested token (bonded claim, challenge, commit-reveal jurors)
//   M2 gt_service.bas notary service with a bounded fee rebate and a MAT boost (no-wash rule)
//   M3 gt_prize.bas   no-loss prize pool with a commit-reveal draw
// Simulator artefact (dvm/simulator.go common/ErrorRevert): deposits are not debited from the sender, and a
// reverted call credits the deposit back to the signer. The checks therefore count what the contracts SEND and
// what the SC HOLDS; a revert is asserted by its error and by the SC balance staying unchanged.
// GT_GAS_OUT=<file> writes the measured gas per entrypoint as JSON (read by harness/gametheory).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"sort"
	"strconv"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

type gtWorld struct {
	t      *testing.T
	s      *Simulator
	addr   map[string]*rpc.Address
	gas    map[string][2]uint64 // entry -> max (compute, storage)
	owners map[crypto.Hash]string
	refund map[string]uint64 // simulator artefact: a reverted call credits its DERO deposit back to the signer
}

func gtNew(t *testing.T, names ...string) *gtWorld {
	t.Helper()
	w := &gtWorld{t: t, s: SimulatorInitialize(nil, 100), addr: map[string]*rpc.Address{}, gas: map[string][2]uint64{},
		owners: map[crypto.Hash]string{}, refund: map[string]uint64{}}
	for _, n := range names {
		sum := sha256.Sum256([]byte("r32-gt-test-key:" + n))
		seed := new(crypto.BNRed).SetBytes(sum[:])
		a := rpc.NewAddressFromKeys(crypto.GPoint.ScalarMult(seed))
		a.Mainnet = false
		w.addr[n] = a
		w.s.AccountAddBalance(*a, crypto.ZEROHASH, 0)
	}
	return w
}

func gtCode(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile("../gametheory/contracts/" + file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return string(b)
}

func (w *gtWorld) install(file, owner string) crypto.Hash {
	w.t.Helper()
	scid, gc, gs, err := w.s.SCInstall(gtCode(w.t, file), map[crypto.Hash]uint64{}, rpc.Arguments{}, w.addr[owner], 0)
	if err != nil {
		w.t.Fatalf("install %s: %v", file, err)
	}
	w.note(file+":Initialize", gc, gs)
	w.owners[scid] = file
	return scid
}

func (w *gtWorld) note(k string, gc, gs uint64) {
	g := w.gas[k]
	if gc > g[0] {
		g[0] = gc
	}
	if gs > g[1] {
		g[1] = gs
	}
	w.gas[k] = g
}

func (w *gtWorld) at(h uint64) { w.s.height = h }

func gtU(n string, v uint64) rpc.Argument {
	return rpc.Argument{Name: n, DataType: rpc.DataUint64, Value: v}
}
func gtS(n, v string) rpc.Argument { return rpc.Argument{Name: n, DataType: rpc.DataString, Value: v} }

// call runs entry as signer with a DERO deposit and optional asset deposits; it returns the SC error.
func (w *gtWorld) call(scid crypto.Hash, entry, signer string, dero uint64, assets map[crypto.Hash]uint64, args ...rpc.Argument) error {
	w.t.Helper()
	in := map[crypto.Hash]uint64{}
	if dero > 0 {
		in[crypto.ZEROHASH] = dero
	}
	for k, v := range assets {
		in[k] = v
	}
	a := append(rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid}, {Name: "entrypoint", DataType: rpc.DataString, Value: entry}}, args...)
	before := w.held(scid, crypto.ZEROHASH)
	gc, gs, err := w.s.RunSC(in, a, w.addr[signer], 0)
	w.note(w.owners[scid]+":"+entry, gc, gs)
	if err != nil {
		if got := w.held(scid, crypto.ZEROHASH); got != before {
			w.t.Fatalf("%s by %s reverted but the SC DERO balance moved %d -> %d", entry, signer, before, got)
		}
		w.refund[signer] += dero
		return err
	}
	return nil
}

func (w *gtWorld) must(scid crypto.Hash, entry, signer string, dero uint64, assets map[crypto.Hash]uint64, args ...rpc.Argument) {
	w.t.Helper()
	if err := w.call(scid, entry, signer, dero, assets, args...); err != nil {
		w.t.Fatalf("%s by %s: %v", entry, signer, err)
	}
}

func (w *gtWorld) mustFail(scid crypto.Hash, entry, signer string, dero uint64, assets map[crypto.Hash]uint64, why string, args ...rpc.Argument) {
	w.t.Helper()
	if err := w.call(scid, entry, signer, dero, assets, args...); err == nil {
		w.t.Fatalf("%s by %s succeeded, want a revert (%s)", entry, signer, why)
	}
}

func (w *gtWorld) data(scid crypto.Hash) *Tree_Wrapper { return Wrapped_tree(w.s.cache, w.s.ss, scid) }
func (w *gtWorld) read(scid crypto.Hash, key string) interface{} {
	return ReadSCValue(w.data(scid), scid, key)
}
func (w *gtWorld) readU(scid crypto.Hash, key string) uint64 {
	w.t.Helper()
	v, ok := w.read(scid, key).(uint64)
	if !ok {
		w.t.Fatalf("%s: not a uint64 (%#v)", key, w.read(scid, key))
	}
	return v
}
func (w *gtWorld) held(scid, asset crypto.Hash) uint64 {
	v, _ := LoadSCAssetValue(w.data(scid), scid, asset)
	return v
}

// deroIs checks the encrypted DERO balance of name equals exactly v (a zero-registered key plus v).
func (w *gtWorld) deroIs(name string, v uint64) {
	w.t.Helper()
	got := r27_balance(w.t, w.s.balance_tree, w.addr[name].Compressed())
	if string(got) != string(r27_expect(w.addr[name], v+w.refund[name])) {
		w.t.Fatalf("DERO balance of %s is not %d (+ %d reverted deposits credited back)", name, v, w.refund[name])
	}
}

// tokenIs checks the encrypted balance of asset (an SC's own token, kept in that SC's tree) of name equals v.
func (w *gtWorld) tokenIs(asset crypto.Hash, name string, v uint64) {
	w.t.Helper()
	tree := w.data(asset).Tree
	got := r27_balance(w.t, tree, w.addr[name].Compressed())
	if v == 0 && got == nil {
		return
	}
	if string(got) != string(r27_expect(w.addr[name], v)) {
		w.t.Fatalf("token balance of %s is not %d", name, v)
	}
}

// gtCommitVote is the gt_attest juror commit. R33 GT-A08: the commit is bound to the juror's
// ADDRESS_STRING(SIGNER()) (addr, see gtAuditAddr), so a copied commit cannot be revealed by another juror.
func gtCommitVote(i, vote uint64, salt, addr string) string {
	h := sha256.Sum256([]byte(strconv.FormatUint(i, 10) + ":" + strconv.FormatUint(vote, 10) + ":" + salt + ":" + addr))
	return hex.EncodeToString(h[:])
}

func gtCommitNum(n uint64, salt string) string {
	h := sha256.Sum256([]byte(strconv.FormatUint(n, 10) + ":" + salt))
	return hex.EncodeToString(h[:])
}

func (w *gtWorld) dumpGas() {
	out := os.Getenv("GT_GAS_OUT")
	if out == "" {
		return
	}
	prev := map[string][2]uint64{}
	if b, err := os.ReadFile(out); err == nil {
		_ = json.Unmarshal(b, &prev)
	}
	for k, v := range w.gas {
		p := prev[k]
		if v[0] > p[0] {
			p[0] = v[0]
		}
		if v[1] > p[1] {
			p[1] = v[1]
		}
		prev[k] = p
	}
	keys := make([]string, 0, len(prev))
	for k := range prev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.MarshalIndent(prev, "", " ")
	_ = os.WriteFile(out, b, 0o644)
}

const gtBond = uint64(100000) // gt_attest default bond per miniblock (1 DERO = 100000 atomic units)

func gtAttestReady(t *testing.T) (*gtWorld, crypto.Hash) {
	w := gtNew(t, "owner", "miner", "chal", "j1", "j2", "j3", "other")
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	w.must(scid, "Freeze", "owner", 0, nil)
	return w, scid
}

func TestR32GTAttestHonestUnchallenged(t *testing.T) {
	w, scid := gtAttestReady(t)
	defer w.dumpGas()
	w.at(200)
	w.must(scid, "Claim", "miner", 5*gtBond, nil, gtU("from", 150), gtU("upto", 160), gtU("k", 5))
	if got := w.held(scid, crypto.ZEROHASH); got != 5*gtBond {
		t.Fatalf("SC holds %d after the claim, want the bond %d", got, 5*gtBond)
	}
	w.at(220) // window 20: finalize only after 200+20
	w.mustFail(scid, "Finalize", "other", 0, nil, "inside the window", gtU("i", 0))
	w.at(221)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	w.deroIs("miner", 5*gtBond)
	w.tokenIs(scid, "miner", 5*100)
	if got := w.held(scid, crypto.ZEROHASH); got != 0 {
		t.Fatalf("SC holds %d after the payout, want 0", got)
	}
	if w.readU(scid, "minted") != 500 || w.readU(scid, "c0s") != 2 {
		t.Fatalf("minted %d status %d", w.readU(scid, "minted"), w.readU(scid, "c0s"))
	}
	w.mustFail(scid, "Finalize", "other", 0, nil, "already paid", gtU("i", 0))
}

// a false claim, challenged, rejected by a juror majority: challenger wins b + b/2, coherent jurors split b/2 plus
// the incoherent juror's slash (ceil 10 %), the incoherent juror keeps 90 % of its stake.
func TestR32GTAttestFalseClaimRejected(t *testing.T) {
	w, scid := gtAttestReady(t)
	defer w.dumpGas()
	stake := map[string]uint64{"j1": 300000, "j2": 100000, "j3": 200000}
	for _, j := range []string{"j1", "j2", "j3"} {
		w.must(scid, "Stake", j, stake[j], nil)
	}
	w.at(200)
	b := 4 * gtBond
	w.must(scid, "Claim", "miner", b, nil, gtU("from", 190), gtU("upto", 199), gtU("k", 4))
	w.mustFail(scid, "Challenge", "chal", b-1, nil, "wrong bond", gtU("i", 0))
	w.mustFail(scid, "Challenge", "miner", b, nil, "self challenge", gtU("i", 0))
	w.at(210)
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 0))
	votes := map[string]uint64{"j1": 0, "j2": 0, "j3": 1}
	for j, v := range votes {
		w.must(scid, "CommitVote", j, 0, nil, gtU("i", 0), gtS("h", gtCommitVote(0, v, "salt-"+j, w.gtAuditAddr(j))))
	}
	w.mustFail(scid, "CommitVote", "miner", 0, nil, "a party cannot vote", gtU("i", 0), gtS("h", gtCommitVote(0, 1, "x", w.gtAuditAddr("miner"))))
	w.mustFail(scid, "Unstake", "j1", 0, nil, "pending vote", gtU("amount", 1))
	w.mustFail(scid, "RevealVote", "j1", 0, nil, "commit phase", gtU("i", 0), gtU("vote", 0), gtS("salt", "salt-j1"))
	// R33 GT-A07: challenges stay open until claim height + window (220), so the commit phase now ends at 220 + 10
	// and the reveal phase at 240 (it was anchored at the single challenge's height before)
	w.at(230)
	w.mustFail(scid, "RevealVote", "j1", 0, nil, "commit phase (R33 A07 windows)", gtU("i", 0), gtU("vote", 0), gtS("salt", "salt-j1"))
	w.at(231)
	w.mustFail(scid, "RevealVote", "j1", 0, nil, "wrong salt", gtU("i", 0), gtU("vote", 0), gtS("salt", "nope"))
	w.mustFail(scid, "RevealVote", "j1", 0, nil, "flipped vote", gtU("i", 0), gtU("vote", 1), gtS("salt", "salt-j1"))
	for j, v := range votes {
		w.must(scid, "RevealVote", j, 0, nil, gtU("i", 0), gtU("vote", v), gtS("salt", "salt-"+j))
	}
	w.at(240)
	w.mustFail(scid, "Finalize", "other", 0, nil, "reveal phase open", gtU("i", 0))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	if w.readU(scid, "c0s") != 3 {
		t.Fatalf("status %d, want 3 (rejected)", w.readU(scid, "c0s"))
	}
	half := b / 2
	w.deroIs("chal", b+half)
	w.deroIs("miner", 0)
	w.tokenIs(scid, "miner", 0)
	for _, j := range []string{"j1", "j2", "j3"} {
		w.must(scid, "ClaimJuror", j, 0, nil, gtU("i", 0))
	}
	w.mustFail(scid, "ClaimJuror", "j1", 0, nil, "claimed twice", gtU("i", 0))
	inc := stake["j3"]
	slashPool := inc * 10 / 100
	cwin := stake["j1"] + stake["j2"]
	pay1 := (half + slashPool) * stake["j1"] / cwin
	pay2 := (half + slashPool) * stake["j2"] / cwin
	w.deroIs("j1", pay1)
	w.deroIs("j2", pay2)
	cut3 := (stake["j3"]*10 + 99) / 100
	if got := w.readU(scid, "st"+string(w.addr["j3"].Compressed())); got != stake["j3"]-cut3 {
		t.Fatalf("j3 stake %d, want %d", got, stake["j3"]-cut3)
	}
	for _, j := range []string{"j1", "j2", "j3"} {
		left := w.readU(scid, "st"+string(w.addr[j].Compressed()))
		w.must(scid, "Unstake", j, 0, nil, gtU("amount", left))
	}
	w.deroIs("j1", pay1+stake["j1"])
	w.deroIs("j3", stake["j3"]-cut3)
	// conservation: in = bonds 2b + stakes; out = chal (b+half) + juror pays + unstakes; the SC keeps the dust
	in := 2*b + stake["j1"] + stake["j2"] + stake["j3"]
	out := b + half + pay1 + pay2 + stake["j1"] + stake["j2"] + stake["j3"] - cut3
	if got := w.held(scid, crypto.ZEROHASH); got != in-out {
		t.Fatalf("SC holds %d, want in-out = %d", got, in-out)
	}
	if in-out > 2 { // rounding dust only: ceil(slash) - floor-shares
		t.Fatalf("dust %d too large", in-out)
	}
	// R33 GT-A13: the last juror's claim swept the dust to the treasury, so every atomic unit is accounted for
	if got := w.readU(scid, "treasury"); got != in-out {
		t.Fatalf("treasury %d, want the dust %d", got, in-out)
	}
}

func TestR32GTAttestHonestChallengedUpheld(t *testing.T) {
	w, scid := gtAttestReady(t)
	defer w.dumpGas()
	for _, j := range []string{"j1", "j2"} {
		w.must(scid, "Stake", j, 200000, nil)
	}
	w.at(200)
	b := 2 * gtBond
	w.must(scid, "Claim", "miner", b, nil, gtU("from", 195), gtU("upto", 199), gtU("k", 2))
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 0))
	for _, j := range []string{"j1", "j2"} {
		w.must(scid, "CommitVote", j, 0, nil, gtU("i", 0), gtS("h", gtCommitVote(0, 1, "s"+j, w.gtAuditAddr(j))))
	}
	w.at(231) // R33 GT-A07: the reveal phase is (200+20+10, 200+20+10+10]
	for _, j := range []string{"j1", "j2"} {
		w.must(scid, "RevealVote", j, 0, nil, gtU("i", 0), gtU("vote", 1), gtS("salt", "s"+j))
	}
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	half := b / 2
	w.deroIs("miner", b+half)
	w.tokenIs(scid, "miner", 200)
	w.deroIs("chal", 0)
	for _, j := range []string{"j1", "j2"} {
		w.must(scid, "ClaimJuror", j, 0, nil, gtU("i", 0))
		w.deroIs(j, (b-half)/2)
	}
	if got := w.held(scid, crypto.ZEROHASH); got != 400000 { // the two stakes remain
		t.Fatalf("SC holds %d, want the stakes 400000", got)
	}
	for _, j := range []string{"j1", "j2"} { // R33 GT-A02: the escrow went back to the free stake
		if got := w.readU(scid, "st"+string(w.addr[j].Compressed())); got != 200000 {
			t.Fatalf("%s free stake %d, want 200000", j, got)
		}
	}
}

// no juror reveals. R32 upheld the claim by default (miner got 2b and minted). R33 GT-A07 changes this on purpose: an
// unresolved dispute (yes == no, here 0 : 0) never mints, both bonds are refunded, and the unrevealed juror is still
// slashed; with no coherent juror to pay, R33 GT-A13 sends the slash to the treasury (it was orphaned before).
func TestR32GTAttestNoJurorsUpholds(t *testing.T) {
	w, scid := gtAttestReady(t)
	defer w.dumpGas()
	w.must(scid, "Stake", "j1", 100000, nil)
	w.at(200)
	b := gtBond
	w.must(scid, "Claim", "miner", b, nil, gtU("from", 199), gtU("upto", 199), gtU("k", 1))
	w.must(scid, "Challenge", "chal", b, nil, gtU("i", 0))
	w.must(scid, "CommitVote", "j1", 0, nil, gtU("i", 0), gtS("h", gtCommitVote(0, 0, "q", w.gtAuditAddr("j1"))))
	w.at(241)
	w.must(scid, "Finalize", "other", 0, nil, gtU("i", 0))
	if w.readU(scid, "c0s") != 4 {
		t.Fatalf("status %d, want 4 (undecided, refunded)", w.readU(scid, "c0s"))
	}
	w.deroIs("miner", b)
	w.deroIs("chal", b)
	w.tokenIs(scid, "miner", 0)
	w.must(scid, "ClaimJuror", "j1", 0, nil, gtU("i", 0))
	if got := w.readU(scid, "st"+string(w.addr["j1"].Compressed())); got != 90000 {
		t.Fatalf("unrevealed juror stake %d, want 90000", got)
	}
	if w.readU(scid, "treasury") != 10000 || w.held(scid, crypto.ZEROHASH) != 100000 {
		t.Fatalf("treasury %d held %d, want 10000 and 100000", w.readU(scid, "treasury"), w.held(scid, crypto.ZEROHASH))
	}
}

func TestR32GTAttestGuards(t *testing.T) {
	w := gtNew(t, "owner", "miner", "x")
	defer w.dumpGas()
	w.at(100)
	scid := w.install("gt_attest.bas", "owner")
	w.mustFail(scid, "Claim", "miner", gtBond, nil, "not frozen", gtU("from", 90), gtU("upto", 90), gtU("k", 1))
	w.mustFail(scid, "SetParams", "x", 0, nil, "not the owner", gtU("bond", 1), gtU("reward", 1), gtU("window", 1),
		gtU("commitw", 1), gtU("revealw", 1), gtU("maxmb", 1), gtU("slash", 1), gtU("minstake", 1))
	w.mustFail(scid, "SetParams", "owner", 0, nil, "slash > 100", gtU("bond", 1), gtU("reward", 1), gtU("window", 1),
		gtU("commitw", 1), gtU("revealw", 1), gtU("maxmb", 1), gtU("slash", 101), gtU("minstake", 1))
	w.must(scid, "Freeze", "owner", 0, nil)
	w.mustFail(scid, "SetParams", "owner", 0, nil, "frozen", gtU("bond", 1), gtU("reward", 1), gtU("window", 1),
		gtU("commitw", 1), gtU("revealw", 1), gtU("maxmb", 1), gtU("slash", 1), gtU("minstake", 1))
	w.mustFail(scid, "Claim", "miner", gtBond, nil, "future height", gtU("from", 90), gtU("upto", 100), gtU("k", 1))
	w.mustFail(scid, "Claim", "miner", gtBond, nil, "k over maxmb per height", gtU("from", 90), gtU("upto", 90), gtU("k", 11))
	w.mustFail(scid, "Claim", "miner", 2*gtBond, nil, "wrong bond", gtU("from", 90), gtU("upto", 90), gtU("k", 1))
	w.mustFail(scid, "Claim", "miner", 0, nil, "k zero", gtU("from", 90), gtU("upto", 90), gtU("k", 0))
	w.at(2000)
	w.mustFail(scid, "Claim", "miner", gtBond, nil, "span over maxspan", gtU("from", 0), gtU("upto", 1000), gtU("k", 1))
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 90), gtU("upto", 95), gtU("k", 1))
	w.mustFail(scid, "Claim", "miner", gtBond, nil, "overlapping epoch", gtU("from", 95), gtU("upto", 99), gtU("k", 1))
	w.must(scid, "Claim", "miner", gtBond, nil, gtU("from", 96), gtU("upto", 99), gtU("k", 1))
	w.at(2021)
	w.mustFail(scid, "Challenge", "x", gtBond, nil, "after the window", gtU("i", 0))
	w.mustFail(scid, "Unstake", "x", 0, nil, "no stake", gtU("amount", 1))
	w.mustFail(scid, "Stake", "x", 0, nil, "zero stake")
}

func gtServiceReady(t *testing.T) (*gtWorld, crypto.Hash, crypto.Hash) {
	w := gtNew(t, "owner", "miner", "u1", "u2", "sponsor", "chal")
	w.at(100)
	mat := w.install("gt_attest.bas", "owner")
	w.must(mat, "Freeze", "owner", 0, nil)
	svc := w.install("gt_service.bas", "owner")
	w.must(svc, "SetMAT", "owner", 0, nil, gtS("scidhex", hex.EncodeToString(mat[:])))
	return w, mat, svc
}

func TestR32GTServiceRebate(t *testing.T) {
	w, mat, svc := gtServiceReady(t)
	defer w.dumpGas()
	// the no-wash rule: rho * (100 + boost) <= 10000
	w.mustFail(svc, "SetParams", "owner", 0, nil, "rebate could exceed the fee", gtU("fee", 1000), gtU("rho", 60),
		gtU("boost", 100), gtU("epoch", 100), gtU("minmat", 100))
	w.must(svc, "SetParams", "owner", 0, nil, gtU("fee", 1000), gtU("rho", 50), gtU("boost", 100), gtU("epoch", 100), gtU("minmat", 100))
	w.mustFail(svc, "Notarize", "u1", 1000, nil, "not frozen", gtS("doc", "a"))
	w.must(svc, "Freeze", "owner", 0, nil)
	// the miner earns MAT in gt_attest first (honest, unchallenged)
	w.must(mat, "Claim", "miner", gtBond, nil, gtU("from", 90), gtU("upto", 99), gtU("k", 1))
	w.at(121)
	w.must(mat, "Finalize", "u1", 0, nil, gtU("i", 0))
	w.tokenIs(mat, "miner", 100)
	w.at(200) // epoch 2
	w.must(svc, "StakeMAT", "miner", 0, map[crypto.Hash]uint64{mat: 100})
	w.must(svc, "Notarize", "miner", 1000, nil, gtS("doc", "doc-miner-1"))
	w.must(svc, "Notarize", "u1", 1000, nil, gtS("doc", "doc-u1-1"))
	w.must(svc, "Notarize", "u1", 1000, nil, gtS("doc", "doc-u1-2"))
	w.mustFail(svc, "Notarize", "u2", 1000, nil, "first writer wins", gtS("doc", "doc-u1-2"))
	w.mustFail(svc, "Notarize", "u2", 999, nil, "wrong fee", gtS("doc", "doc-u2"))
	w.must(svc, "Sponsor", "sponsor", 3000, nil)
	w.mustFail(svc, "ClaimRebate", "u1", 0, nil, "epoch not over", gtU("e", 2))
	w.mustFail(svc, "UnstakeMAT", "miner", 0, nil, "locked in the epoch", gtU("amount", 100))
	w.at(300)
	// pool = 3 fees * 50 % + 3000 sponsor = 4500; weights miner 2000 (boosted), u1 2000
	w.must(svc, "ClaimRebate", "miner", 0, nil, gtU("e", 2))
	w.must(svc, "ClaimRebate", "u1", 0, nil, gtU("e", 2))
	w.mustFail(svc, "ClaimRebate", "u1", 0, nil, "claimed twice", gtU("e", 2))
	w.mustFail(svc, "ClaimRebate", "u2", 0, nil, "no weight", gtU("e", 2))
	w.deroIs("miner", gtBond+2250)
	w.deroIs("u1", 2250)
	if w.readU(svc, "treasury") != 1500 {
		t.Fatalf("treasury %d, want 1500", w.readU(svc, "treasury"))
	}
	w.must(svc, "UnstakeMAT", "miner", 0, nil, gtU("amount", 100))
	w.mustFail(svc, "WithdrawTreasury", "u1", 0, nil, "not the owner", gtU("amount", 1))
	w.must(svc, "WithdrawTreasury", "owner", 0, nil, gtU("amount", 1500))
	if got := w.held(svc, crypto.ZEROHASH); got != 0 {
		t.Fatalf("service holds %d, want 0", got)
	}
}

// gtPrizeFee is the gt_prize default entry fee (R33 GT-A06): non-refundable, paid to the treasury by every Enter
// (deposit = principal + rbond + fee).
const gtPrizeFee = uint64(1000)

func gtPrizeReady(t *testing.T, names ...string) (*gtWorld, crypto.Hash, crypto.Hash) {
	w := gtNew(t, append([]string{"owner", "miner", "sponsor"}, names...)...)
	w.at(100)
	mat := w.install("gt_attest.bas", "owner")
	w.must(mat, "Freeze", "owner", 0, nil)
	pz := w.install("gt_prize.bas", "owner")
	w.must(pz, "SetMAT", "owner", 0, nil, gtS("scidhex", hex.EncodeToString(mat[:])))
	w.must(pz, "Freeze", "owner", 0, nil) // round 0 starts at 100
	return w, mat, pz
}

func TestR32GTPrizeRound(t *testing.T) {
	w, _, pz := gtPrizeReady(t, "a", "b", "c", "d")
	defer w.dumpGas()
	rb := uint64(10000)
	dep := map[string]uint64{"a": 50000, "b": 30000, "c": 20000, "d": 40000}
	order := []string{"a", "b", "c", "d"}
	w.must(pz, "Fund", "sponsor", 7000, nil)
	for i, n := range order {
		w.must(pz, "Enter", n, dep[n]+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(uint64(1000+i), "salt"+n)))
	}
	w.mustFail(pz, "Enter", "a", 1+rb, nil, "one entry per round", gtS("commit", gtCommitNum(1, "x")))
	w.mustFail(pz, "Reveal", "a", 0, nil, "commit phase", gtU("j", 0), gtU("num", 1000), gtS("salt", "salta"))
	w.at(111)
	w.mustFail(pz, "Enter", "owner", 1+rb, nil, "commit phase over", gtS("commit", gtCommitNum(1, "x")))
	w.mustFail(pz, "Reveal", "b", 0, nil, "not its entry", gtU("j", 0), gtU("num", 1000), gtS("salt", "salta"))
	for i, n := range order[:3] { // d withholds its reveal
		w.must(pz, "Reveal", n, 0, nil, gtU("j", uint64(i)), gtU("num", uint64(1000+i)), gtS("salt", "salt"+n))
	}
	w.mustFail(pz, "Draw", "sponsor", 0, nil, "reveal phase open")
	w.at(121)
	w.must(pz, "Draw", "sponsor", 0, nil)
	win := w.readU(pz, "win0")
	if win > 2 {
		t.Fatalf("winner %d is not a revealed entry", win)
	}
	prize := uint64(7000) // R33 GT-A05: sponsor funds only; d's forfeited reveal bond goes to the treasury
	if w.readU(pz, "paid0") != prize || w.readU(pz, "forf0") != rb || w.readU(pz, "treasury") != rb+4*gtPrizeFee {
		t.Fatalf("paid %d forf %d", w.readU(pz, "paid0"), w.readU(pz, "forf0"))
	}
	for i, n := range order {
		w.must(pz, "Withdraw", n, 0, nil, gtU("r", 0), gtU("j", uint64(i)))
	}
	w.mustFail(pz, "Withdraw", "a", 0, nil, "twice", gtU("r", 0), gtU("j", 0))
	for i, n := range order {
		want := dep[n] + rb
		if n == "d" {
			want = dep[n] // the non-revealer gets its principal, not its bond
		}
		if uint64(i) == win {
			want += prize
		}
		w.deroIs(n, want)
	}
	if got := w.held(pz, crypto.ZEROHASH); got != rb+4*gtPrizeFee { // R33 GT-A05/A06: forfeit + entry fees
		t.Fatalf("prize SC holds %d after all withdrawals, want the treasury %d", got, rb+4*gtPrizeFee)
	}
	w.must(pz, "WithdrawTreasury", "owner", 0, nil, gtU("amount", rb+4*gtPrizeFee))
	if got := w.held(pz, crypto.ZEROHASH); got != 0 {
		t.Fatalf("prize SC holds %d after the treasury withdrawal, want 0", got)
	}
	if w.readU(pz, "rd") != 1 {
		t.Fatalf("round %d, want 1", w.readU(pz, "rd"))
	}
}

// frequency check of the draw: a deposits 30000, b deposits 15000 but stakes MAT (boost 100 %), so the weights are
// 30000 : 30000 and b must win about 1/2 of 400 draws (binomial 5 sigma = +- 0.125); then b unstakes and the
// control phase (weights 30000 : 15000) must give b about 1/3 (5 sigma = +- 0.118)
func TestR32GTPrizeFairnessAndBoost(t *testing.T) {
	w, mat, pz := gtPrizeReady(t, "a", "b")
	defer w.dumpGas()
	// b gets MAT: one honest claim in gt_attest
	w.must(mat, "Claim", "b", gtBond, nil, gtU("from", 90), gtU("upto", 99), gtU("k", 1))
	w.at(121)
	w.must(mat, "Finalize", "a", 0, nil, gtU("i", 0))
	w.must(pz, "Draw", "sponsor", 0, nil) // closes round 0 (empty)
	w.must(pz, "StakeMAT", "b", 0, map[crypto.Hash]uint64{mat: 100})
	rb := uint64(10000)
	h := uint64(121)
	wins := 0
	rng := mrand.New(mrand.NewSource(32)) // each entrant reveals a uniform 64-bit number, as an honest entrant would
	na, nb := make(map[uint64]uint64), make(map[uint64]uint64)
	for r := uint64(1); r <= 800; r++ {
		na[r], nb[r] = rng.Uint64(), rng.Uint64()
	}
	const N = 400
	for r := uint64(1); r <= N; r++ {
		w.at(h)
		w.must(pz, "Enter", "a", 30000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(na[r], "a")))
		w.must(pz, "Enter", "b", 15000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(nb[r], "b")))
		w.at(h + 11)
		w.must(pz, "Reveal", "a", 0, nil, gtU("j", 0), gtU("num", na[r]), gtS("salt", "a"))
		w.must(pz, "Reveal", "b", 0, nil, gtU("j", 1), gtU("num", nb[r]), gtS("salt", "b"))
		h += 21
		w.at(h)
		w.must(pz, "Draw", "sponsor", 0, nil)
		if w.readU(pz, "win"+strconv.FormatUint(r, 10)) == 1 {
			wins++
		}
		w.must(pz, "Withdraw", "a", 0, nil, gtU("r", r), gtU("j", 0))
		w.must(pz, "Withdraw", "b", 0, nil, gtU("r", r), gtU("j", 1))
	}
	// weights: a 30000, b 15000 * 2 = 30000 -> 1 : 1 with the boost; without it 2 : 1
	f := float64(wins) / N
	t.Logf("boosted entrant won %d of %d draws (%.3f; equal weights 30000 : 30000 expected 0.5)", wins, N, f)
	if f < 0.5-0.125 || f > 0.5+0.125 {
		t.Fatalf("boosted share %.3f outside 0.5 +- 0.125 (5 sigma)", f)
	}
	w.must(pz, "UnstakeMAT", "b", 0, nil, gtU("amount", 100))
	wins = 0
	for r := uint64(N + 1); r <= 2*N; r++ {
		w.at(h)
		w.must(pz, "Enter", "a", 30000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(na[r], "a")))
		w.must(pz, "Enter", "b", 15000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(nb[r], "b")))
		w.at(h + 11)
		w.must(pz, "Reveal", "a", 0, nil, gtU("j", 0), gtU("num", na[r]), gtS("salt", "a"))
		w.must(pz, "Reveal", "b", 0, nil, gtU("j", 1), gtU("num", nb[r]), gtS("salt", "b"))
		h += 21
		w.at(h)
		w.must(pz, "Draw", "sponsor", 0, nil)
		if w.readU(pz, "win"+strconv.FormatUint(r, 10)) == 1 {
			wins++
		}
		w.must(pz, "Withdraw", "a", 0, nil, gtU("r", r), gtU("j", 0))
		w.must(pz, "Withdraw", "b", 0, nil, gtU("r", r), gtU("j", 1))
	}
	f = float64(wins) / N
	t.Logf("unboosted control: b won %d of %d draws (%.3f; weights 30000 : 15000 expected 0.333)", wins, N, f)
	if f < 1.0/3-0.118 || f > 1.0/3+0.118 {
		t.Fatalf("unboosted share %.3f outside 0.333 +- 0.118 (5 sigma)", f)
	}
	if got, fees := w.held(pz, crypto.ZEROHASH), uint64(2*2*N)*gtPrizeFee; got != fees || w.readU(pz, "treasury") != fees {
		t.Fatalf("prize SC holds %d, want only the treasury of entry fees %d (R33 GT-A06)", got, fees)
	}
	w.tokenIs(mat, "b", 200) // 100 minted + 100 returned by UnstakeMAT (the simulator never debits the deposit)
}

// gas census: the most expensive path of every entrypoint stays far below the fixed 10,000,000 compute limit
// (dvm/sc.go); the full 32-entry draw is the bound case (gas DoS: maxn caps it)
func TestR32GTGasBound(t *testing.T) {
	names := []string{}
	for i := 0; i < 32; i++ {
		names = append(names, fmt.Sprintf("p%02d", i))
	}
	w, _, pz := gtPrizeReady(t, names...)
	defer w.dumpGas()
	rb := uint64(10000)
	for i, n := range names {
		w.must(pz, "Enter", n, 1000+rb+gtPrizeFee, nil, gtS("commit", gtCommitNum(uint64(i), n)))
	}
	w.mustFail(pz, "Enter", "owner", 1000+rb+gtPrizeFee, nil, "maxn reached", gtS("commit", gtCommitNum(1, "o")))
	w.at(111)
	for i, n := range names {
		w.must(pz, "Reveal", n, 0, nil, gtU("j", uint64(i)), gtU("num", uint64(i)), gtS("salt", n))
	}
	w.at(121)
	w.must(pz, "Draw", "owner", 0, nil)
	g := w.gas["gt_prize.bas:Draw"]
	t.Logf("Draw with 32 revealed entries: compute gas %d (limit 10000000)", g[0])
	if g[0] == 0 || g[0] > 5000000 {
		t.Fatalf("Draw compute gas %d outside (0, 5000000]", g[0])
	}
	for k, v := range w.gas {
		if v[0] > 10000000 {
			t.Fatalf("%s compute gas %d over the limit", k, v[0])
		}
	}
}
