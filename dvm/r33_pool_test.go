package dvm

// R33 M5 gt_pool.bas (dero-game-theory-rft §8.1, D-GT-23, GT-B27; D-21 non-consensus: tests only).
// Blocks are real mainnet blocks (testdata/r33_mainnet_blocks.json) with chosen non-final miniblocks' Flags rewritten
// to members' tags; the rewritten bytes get a new sha3 id, which the test anchors (on chain an anchor exists only for
// a block that executed the Anchor call, blockchain/blockchain.go:1021). Every DERO the pool holds is accounted for:
// balance == burned + the epoch pools left + locked stakes.

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"golang.org/x/crypto/sha3"
)

func (w *gtWorld) poolTag(name string) string {
	h := sha3.Sum256(w.addr[name].Compressed())
	return hex.EncodeToString(h[:8])
}

// r33Tagged returns a copy of a real block's bytes where non-final miniblock i carries tags[i] ("" keeps its Flags),
// and the new block id
func r33Tagged(t *testing.T, rb r33Block, tags []string) (string, crypto.Hash, uint64) {
	t.Helper()
	raw, _ := hex.DecodeString(rb.Blob)
	p := len(raw) - 32*int(rb.Txcount) - 1
	m := 10
	q := p - 48*m - 1
	if int(raw[q]) != m {
		t.Fatalf("height %d: miniblock count byte %d", rb.Height, raw[q])
	}
	for i, tg := range tags {
		if tg == "" {
			continue
		}
		off := q + 1 + 48*i
		if raw[off]&0x20 != 0 {
			t.Fatalf("miniblock %d is final", i)
		}
		b, _ := hex.DecodeString(tg)
		copy(raw[off+32:off+40], b)
	}
	id := sha3.Sum256(raw)
	var blid crypto.Hash
	copy(blid[:], id[:])
	return hex.EncodeToString(raw), blid, uint64(m)
}

type r33Pool struct {
	w    *gtWorld
	scid crypto.Hash
	blk  []r33Block
}

func r33PoolReady(t *testing.T) *r33Pool {
	w := gtNew(t, "owner", "alice", "bob", "carol", "prover", "sponsor", "eve")
	w.at(7911000)
	scid := w.install("gt_pool.bas", "owner")
	return &r33Pool{w: w, scid: scid, blk: r33LoadBlocks(t)}
}

// anchor and prove block k of the test data at its real height with the given tags; returns the Prove error
// (gt_pool checks that every miniblock's height field equals the proven height)
func (p *r33Pool) proveAt(t *testing.T, k int, tags []string, prover string) error {
	t.Helper()
	h := p.blk[k].Height
	hx, blid, _ := r33Tagged(t, p.blk[k], tags)
	if _, _, err := p.w.runAt(p.scid, blid, h, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor %d: %v", h, err)
	}
	var later crypto.Hash
	later[0], later[1] = byte(h), 0x77
	_, _, err := p.w.runAt(p.scid, later, h+1, "ProveBlock", prover, 20000,
		gtU("h", h), gtS("hx", hx), gtU("ntx", p.blk[k].Txcount))
	return err
}

func (p *r33Pool) conserve(t *testing.T, epochs []uint64, stakers []string) {
	t.Helper()
	sum := p.w.readU(p.scid, "burned")
	for _, e := range epochs {
		if v := p.w.read(p.scid, fmt.Sprintf("P%d", e)); v != nil {
			sum += v.(uint64)
		}
	}
	for _, n := range stakers {
		sum += p.w.readU(p.scid, "s_"+p.w.poolTag(n))
	}
	if held := p.w.held(p.scid, crypto.ZEROHASH); held != sum {
		t.Fatalf("conservation: SC holds %d, burned + pools + stakes = %d", held, sum)
	}
}

// epochs of the real test blocks (epochlen 400): 7,915,141-143 -> 19787, 7,911,096 -> 19777
const (
	r33E1  = uint64(7915141 / 400)
	r33E0  = uint64(7911096 / 400)
	r33Len = uint64(400)
)

func r33ClaimOpen(e uint64) uint64    { return (e+1)*r33Len + 100 }
func r33RolloverOpen(e uint64) uint64 { return (e+5)*r33Len + 100 }

func TestR33PoolHonestEpoch(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta, tb := w.poolTag("alice"), w.poolTag("bob")
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Register", "bob", 1000, nil)
	w.mustFail(sc, "Register", "alice", 1000, nil, "a tag registers once")
	w.mustFail(sc, "Register", "carol", 999, nil, "the entry fee is exact")
	w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
	w.mustFail(sc, "Fund", "sponsor", 1000, nil, "a past epoch cannot be funded", gtU("e", r33E1-1))
	if got := w.readU(sc, "burned"); got != 2000*20/100+1000000*20/100 {
		t.Fatalf("burned %d", got)
	}
	pe := fmt.Sprintf("P%d", r33E1)
	p0 := w.readU(sc, pe)
	// block 7,915,141: alice 6 miniblocks, bob 3; block 7,915,142: alice 1, bob 2, an unregistered tag 1
	if err := p.proveAt(t, 0, []string{ta, ta, ta, ta, ta, ta, tb, tb, tb}, "prover"); err != nil {
		t.Fatalf("prove 0: %v", err)
	}
	if err := p.proveAt(t, 1, []string{ta, tb, tb, "deadbeefdeadbeef"}, "carol"); err != nil {
		t.Fatalf("prove 1: %v", err)
	}
	k := func(pre, tag string) string { return fmt.Sprintf("%s%d_%s", pre, r33E1, tag) }
	if w.readU(sc, k("w", ta)) != 7 || w.readU(sc, k("w", tb)) != 5 {
		t.Fatalf("credits alice %d bob %d", w.readU(sc, k("w", ta)), w.readU(sc, k("w", tb)))
	}
	if w.readU(sc, fmt.Sprintf("TW%d", r33E1)) != 1200 {
		t.Fatalf("TW %d", w.readU(sc, fmt.Sprintf("TW%d", r33E1)))
	}
	pfee := w.readU(sc, "pfee")
	if got := w.readU(sc, pe); got != p0-2*pfee {
		t.Fatalf("pool after two prover fees %d, want %d", got, p0-2*pfee)
	}
	// forensics: the timestamp and the KeyHash census are public
	if w.read(sc, fmt.Sprintf("t%d", p.blk[0].Height)) == nil || w.readU(sc, fmt.Sprintf("kn%d", r33E1)) != 18 || w.readU(sc, fmt.Sprintf("km%d", r33E1)) == 0 {
		t.Fatalf("forensics missing")
	}
	w.at(r33ClaimOpen(r33E1) - 1)
	w.mustFail(sc, "Claim", "alice", 0, nil, "the proof window is still open", gtU("e", r33E1))
	w.at(r33ClaimOpen(r33E1))
	pool := w.readU(sc, pe)
	w.must(sc, "Claim", "alice", 0, nil, gtU("e", r33E1))
	w.must(sc, "Claim", "bob", 0, nil, gtU("e", r33E1))
	w.mustFail(sc, "Claim", "alice", 0, nil, "a claim is paid once", gtU("e", r33E1))
	w.mustFail(sc, "Claim", "carol", 0, nil, "not a member", gtU("e", r33E1))
	ca, cb := w.readU(sc, k("c", ta)), w.readU(sc, k("c", tb))
	capv := pool * 30 / 100
	wantA, wantB := pool*700/1200, pool*500/1200
	if wantA > capv {
		wantA = capv
	}
	if wantB > capv {
		wantB = capv
	}
	if ca != wantA || cb != wantB {
		t.Fatalf("claims alice %d bob %d, want %d %d (pool %d, cap %d)", ca, cb, wantA, wantB, pool, capv)
	}
	w.deroIs("alice", ca)
	w.deroIs("bob", cb)
	w.deroIs("prover", pfee)
	w.deroIs("carol", pfee)
	cur := r33RolloverOpen(r33E1) / r33Len
	p.conserve(t, []uint64{r33E1, cur}, nil)
	// the capped excess rolls into a later epoch, never to anyone's pocket
	w.at(r33RolloverOpen(r33E1) - 1)
	w.mustFail(sc, "Rollover", "eve", 0, nil, "4 epochs of claim time first", gtU("e", r33E1))
	w.at(r33RolloverOpen(r33E1))
	left := w.readU(sc, pe)
	w.must(sc, "Rollover", "eve", 0, nil, gtU("e", r33E1))
	if w.readU(sc, pe) != 0 || w.readU(sc, fmt.Sprintf("P%d", cur)) != left {
		t.Fatalf("rollover: left %d moved %d", left, w.readU(sc, fmt.Sprintf("P%d", cur)))
	}
	w.deroIs("eve", 0)
	p.conserve(t, []uint64{r33E1, cur}, nil)
}

func TestR33PoolProofGuards(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta := w.poolTag("alice")
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Fund", "sponsor", 100000, nil, gtU("e", r33E1))
	h := p.blk[0].Height
	hx, blid, _ := r33Tagged(t, p.blk[0], []string{ta, ta})
	var later crypto.Hash
	later[0] = 0x55
	prove := func(at, hh uint64, x string, ntx uint64) error {
		_, _, err := w.runAt(sc, later, at, "ProveBlock", "prover", 20000, gtU("h", hh), gtS("hx", x), gtU("ntx", ntx))
		return err
	}
	if prove(h+1, h, hx, 0) == nil {
		t.Fatalf("a block that was never anchored was accepted")
	}
	if _, _, err := w.runAt(sc, blid, h, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	forged, _, _ := r33Tagged(t, p.blk[0], []string{ta, ta, ta})
	if prove(h+1, h, forged, 0) == nil {
		t.Fatalf("forged bytes accepted")
	}
	if prove(h+1, h, hx, 1) == nil {
		t.Fatalf("a wrong tx count accepted")
	}
	if prove(h, h, hx, 0) == nil {
		t.Fatalf("a proof in the anchored block itself accepted")
	}
	if err := prove(h+1, h, hx, 0); err != nil {
		t.Fatalf("honest proof: %v", err)
	}
	if prove(h+1, h, hx, 0) == nil {
		t.Fatalf("the same block proven twice")
	}
	if got := w.readU(sc, fmt.Sprintf("w%d_%s", r33E1, ta)); got != 2 {
		t.Fatalf("credit %d", got)
	}
	// a block anchored at a height its miniblocks do not carry is refused (RA-P3: the height field must match)
	hx1, blid1, _ := r33Tagged(t, p.blk[1], []string{ta})
	if _, _, err := w.runAt(sc, blid1, h+5, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if prove(h+6, h+5, hx1, 0) == nil {
		t.Fatalf("miniblocks of another height accepted")
	}
	// after the proof window of an epoch closes, no more proofs for it
	b3 := p.blk[3]
	hx3, blid3, _ := r33Tagged(t, b3, []string{ta})
	if _, _, err := w.runAt(sc, blid3, b3.Height, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if prove(r33ClaimOpen(r33E0), b3.Height, hx3, b3.Txcount) == nil {
		t.Fatalf("a proof after the window accepted")
	}
	if err := prove(r33ClaimOpen(r33E0)-1, b3.Height, hx3, b3.Txcount); err != nil {
		t.Fatalf("a proof of a block with 3 txs inside its window: %v", err)
	}
	w.mustFail(sc, "Anchor", "eve", 5, nil, "no deposit on Anchor")
	w.mustFail(sc, "Claim", "alice", 5, nil, "no deposit on Claim", gtU("e", r33E1))
	w.mustFail(sc, "Initialize", "eve", 0, nil, "Initialize runs once")
	if got := w.read(sc, "owner"); got != string(w.addr["owner"].Compressed()) {
		t.Fatalf("owner changed")
	}
	p.conserve(t, []uint64{r33E0, r33E1}, nil)
}

func TestR33PoolStakeBoostAndLock(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta, tb := w.poolTag("alice"), w.poolTag("bob")
	w.at(7911000)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Register", "bob", 1000, nil)
	w.mustFail(sc, "Lock", "carol", 5000, nil, "only members lock stake")
	w.must(sc, "Lock", "alice", 50000, nil) // S = 100000: half the full boost
	w.must(sc, "Lock", "bob", 900000, nil)  // far above S: the boost is capped at 100
	// 7,911,096 is 96 heights after the lock: not matured (one epoch, 400): no boost
	if err := p.proveAt(t, 3, []string{ta, tb}, "prover"); err != nil {
		t.Fatalf("prove: %v", err)
	}
	if w.readU(sc, fmt.Sprintf("W%d_%s", r33E0, ta)) != 100 || w.readU(sc, fmt.Sprintf("W%d_%s", r33E0, tb)) != 100 {
		t.Fatalf("unmatured boost")
	}
	// 7,915,141: matured
	if err := p.proveAt(t, 0, []string{ta, tb}, "prover"); err != nil {
		t.Fatalf("prove: %v", err)
	}
	if a, b := w.readU(sc, fmt.Sprintf("W%d_%s", r33E1, ta)), w.readU(sc, fmt.Sprintf("W%d_%s", r33E1, tb)); a != 150 || b != 200 {
		t.Fatalf("matured boost: alice %d (want 150) bob %d (want 200)", a, b)
	}
	w.at(7911000 + 1999)
	w.mustFail(sc, "Unlock", "alice", 0, nil, "the lock is 2000 heights")
	w.at(7911000 + 2000)
	w.must(sc, "Unlock", "alice", 0, nil)
	w.deroIs("alice", 50000)
	w.mustFail(sc, "Unlock", "alice", 0, nil, "nothing left to unlock")
	p.conserve(t, []uint64{r33E0, r33E1}, []string{"alice", "bob"})
}

// the weight rule W = w(1 + min(s/S, 1)) never rewards splitting work or stake over identities
func TestR33PoolSplitNeutral(t *testing.T) {
	const S = 100000
	weight := func(w, s uint64) uint64 {
		b := 100 * s / S
		if b > 100 {
			b = 100
		}
		return w * (100 + b)
	}
	for _, w := range []uint64{1, 7, 90, 1000} {
		for _, s := range []uint64{0, 1, 30000, 99999, 100000, 250000, 10000000} {
			one := weight(w, s)
			for k := uint64(2); k <= 5; k++ {
				split := uint64(0)
				for i := uint64(0); i < k; i++ { // the most favourable split: work divided, ALL stake copied is impossible; stake divided
					wi := w / k
					if i < w%k {
						wi++
					}
					split += weight(wi, s/k)
				}
				if split > one {
					t.Fatalf("split gains: w %d s %d k %d: %d > %d", w, s, k, split, one)
				}
			}
		}
	}
}

// R33 GT-B31: one anchor covers earlier main-chain blocks through the single tip; real consecutive mainnet blocks link
func TestR33PoolChainBack(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	raw2, _ := hex.DecodeString(p.blk[1].Blob)
	if p.blk[1].Height != p.blk[0].Height+1 {
		t.Fatalf("test data not consecutive")
	}
	q2 := len(raw2) - 1 - 48*10 - 1
	if raw2[q2-33] != 1 || hex.EncodeToString(raw2[q2-32:q2]) != p.blk[0].Blid {
		t.Fatalf("real tip of %d is not the id of %d", p.blk[1].Height, p.blk[0].Height)
	}
	ta := w.poolTag("alice")
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
	// parent' carries alice's tag in 3 miniblocks; child' points at parent' and carries 2
	phx, pid, _ := r33Tagged(t, p.blk[0], []string{ta, ta, ta})
	c := r33Block{Height: p.blk[1].Height, Txcount: 0}
	copy(raw2[q2-32:q2], pid[:])
	c.Blob = hex.EncodeToString(raw2)
	chx, cid, _ := r33Tagged(t, c, []string{ta, ta})
	h := p.blk[1].Height
	if _, _, err := w.runAt(sc, cid, h, "Anchor", "prover", 0); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	var later crypto.Hash
	later[0] = 0x31
	pp := func(x string) error {
		_, _, err := w.runAt(sc, later, h+1, "ProveParent", "prover", 20000, gtU("h", h-1), gtS("hx", x), gtU("ntx", 0))
		return err
	}
	if pp(phx) == nil {
		t.Fatalf("a parent proven before its child")
	}
	if _, _, err := w.runAt(sc, later, h+1, "ProveBlock", "prover", 20000, gtU("h", h), gtS("hx", chx), gtU("ntx", 0)); err != nil {
		t.Fatalf("prove child: %v", err)
	}
	if pp(p.blk[0].Blob) == nil {
		t.Fatalf("a parent that is not the tip accepted")
	}
	if err := pp(phx); err != nil {
		t.Fatalf("prove parent: %v", err)
	}
	if pp(phx) == nil {
		t.Fatalf("a parent proven twice")
	}
	if got := w.readU(sc, fmt.Sprintf("w%d_%s", r33E1, ta)); got != 5 {
		t.Fatalf("credits %d, want 5 (2 in the anchored block, 3 in its parent)", got)
	}
	p.conserve(t, []uint64{r33E1}, nil)
}

// R33 research finding 4 / re-audit RA-P1: a claim after Rollover opened is refused (no payment from other funds)
func TestR33PoolLateClaimRefused(t *testing.T) {
	p := r33PoolReady(t)
	w, sc := p.w, p.scid
	ta := w.poolTag("alice")
	w.at(r33E1*r33Len + 10)
	w.must(sc, "Register", "alice", 1000, nil)
	w.must(sc, "Fund", "sponsor", 1000000, nil, gtU("e", r33E1))
	if err := p.proveAt(t, 0, []string{ta}, "prover"); err != nil {
		t.Fatalf("prove: %v", err)
	}
	w.at(r33RolloverOpen(r33E1))
	w.must(sc, "Rollover", "eve", 0, nil, gtU("e", r33E1))
	w.mustFail(sc, "Claim", "alice", 0, nil, "claims close when Rollover opens", gtU("e", r33E1))
	w.deroIs("alice", 0)
	p.conserve(t, []uint64{r33E1, r33RolloverOpen(r33E1) / r33Len}, nil)
}
