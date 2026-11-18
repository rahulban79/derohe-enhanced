package dvm

// R33 pre-deployment invariants for gametheory/contracts/gt_pool.bas (M5 verified mining pool). See r33_verify_common_test.go.
// Liability derived from the contract's variables (checked after every call): burned + sum P<e> + sum s_<tag>.
// Blocks: a main chain is synthesized from the real mainnet blocks (dvm/testdata/r33_mainnet_blocks.json): every
// height gets one block whose 10 miniblocks carry that height (RA-P3), chosen KeyHashes, chosen Flags (member tags,
// unregistered tags, 0) and chosen Final bits, and whose single tip is the id of the block one height below, so
// ProveParent can walk back from any anchor. A block is anchored by an Anchor call executed at its own height
// with its own id as BLID (runAt), as on chain. The Go decoder (block.Block.Deserialize) is the reference for
// which miniblocks are non-final and what their Flags are.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"golang.org/x/crypto/sha3"
)

const (
	plLen    = uint64(400)
	plGrace  = uint64(100)
	plFee    = uint64(1000)
	plBeta   = uint64(20)
	plS      = uint64(100000)
	plCap    = uint64(30)
	plPfee   = uint64(2000)
	plLockh  = uint64(2000)
	plPmax   = uint64(10000000000000)
	plBase   = uint64(40000) // epoch 100
	plProver = 20000         // fee of a proof call: storage gas limit min(fee, 20000) as on mainnet
)

type plBlock struct {
	hx  string
	id  crypto.Hash
	ntx uint64
	raw []byte
}

type plChain struct {
	t    *testing.T
	base []r33Block
	b    map[uint64]*plBlock
	top  uint64
}

func plBE5(h uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], h)
	return x[3:]
}

// synth builds the block of height h from real block base with the given tags, keyhash indices and final bits
func (c *plChain) synth(base r33Block, h uint64, tags []string, kh []int, final []bool, tip []byte, extraTx int) *plBlock {
	raw, _ := hex.DecodeString(base.Blob)
	ntx := int(base.Txcount)
	p := len(raw) - 32*ntx - 1
	q := p - 48*10 - 1
	if raw[q] != 10 || raw[q-33] != 1 {
		c.t.Fatalf("base block layout")
	}
	copy(raw[q-32:q], tip)
	for i := 0; i < 10; i++ {
		off := q + 1 + 48*i
		raw[off] = 0x41
		if final[i] {
			raw[off] |= 0x20
		}
		copy(raw[off+3:off+8], plBE5(h))
		k := sha3.Sum256([]byte(fmt.Sprintf("keyhash-%d", kh[i])))
		copy(raw[off+16:off+32], k[:16])
		tg, _ := hex.DecodeString(tags[i])
		copy(raw[off+32:off+40], tg) // the 8-byte tag: Flags + Nonce[0]
	}
	if extraTx > 0 { // grow the tx list (count byte < 128) with fresh hashes
		raw[p] = byte(ntx + extraTx)
		for i := 0; i < extraTx; i++ {
			x := sha3.Sum256([]byte(fmt.Sprintf("tx-%d-%d", h, i)))
			raw = append(raw, x[:]...)
		}
		ntx += extraTx
	}
	id := sha3.Sum256(raw)
	var blid crypto.Hash
	copy(blid[:], id[:])
	return &plBlock{hx: hex.EncodeToString(raw), id: blid, ntx: uint64(ntx), raw: raw}
}

// decode is the Go reference: non-final miniblock tags (Flags + Nonce[0], 16 hex) and keyhashes (32 hex) of a block
func plDecode(t *testing.T, raw []byte) (flags, kh []string) {
	var bl block.Block
	if err := bl.Deserialize(raw); err != nil {
		t.Fatalf("Go decoder refused a synthesized block: %v", err)
	}
	for _, mb := range bl.MiniBlocks {
		if mb.Final {
			continue
		}
		var f [8]byte
		binary.BigEndian.PutUint32(f[:4], mb.Flags)
		binary.BigEndian.PutUint32(f[4:], mb.Nonce[0])
		flags = append(flags, hex.EncodeToString(f[:]))
		kh = append(kh, hex.EncodeToString(mb.KeyHash[:16]))
	}
	return
}

type plMember struct {
	name, tag string
	s, since  uint64
}

type plRun struct {
	t       *testing.T
	w       *gtWorld
	sc      crypto.Hash
	l       *vLedger
	ch      *plChain
	H       uint64
	names   []string
	mem     map[string]*plMember // by tag
	byName  map[string]*plMember
	P       map[uint64]uint64
	P0      map[uint64]uint64
	burned  uint64
	W, wc   map[string]uint64 // e_tag
	TW      map[uint64]uint64
	claimed map[string]bool
	anch    map[uint64]bool
	pr      map[uint64]bool
	kcount  map[string]uint64 // e_kh
	kn, km  map[uint64]uint64
	rng     *mrand.Rand
	credits uint64
}

func plStart(t *testing.T, seed int64, names ...string) *plRun {
	all := append([]string{"owner", "prover", "sponsor"}, names...)
	w := gtNew(t, all...)
	w.at(plBase)
	sc := w.install("gt_pool.bas", "owner")
	r := &plRun{t: t, w: w, sc: sc, l: vNewLedger(t, w, sc), H: plBase, names: all,
		ch:  &plChain{t: t, base: r33LoadBlocks(t), b: map[uint64]*plBlock{}, top: plBase - 1},
		mem: map[string]*plMember{}, byName: map[string]*plMember{}, P: map[uint64]uint64{}, P0: map[uint64]uint64{},
		W: map[string]uint64{}, wc: map[string]uint64{}, TW: map[uint64]uint64{}, claimed: map[string]bool{},
		anch: map[uint64]bool{}, pr: map[uint64]bool{}, kcount: map[string]uint64{}, kn: map[uint64]uint64{}, km: map[uint64]uint64{},
		rng: mrand.New(mrand.NewSource(seed))}
	return r
}

func (r *plRun) at(h uint64) { r.H = h; r.w.at(h) }

func plKey(e uint64, tag string) string { return fmt.Sprintf("%d_%s", e, tag) }

func (r *plRun) check() {
	r.t.Helper()
	w, sc := r.w, r.sc
	L := w.readU(sc, "burned")
	if L != r.burned {
		r.t.Fatalf("burned %d, model %d", L, r.burned)
	}
	for e := plBase/plLen - 1; e <= r.H/plLen+10; e++ {
		if v, ok := w.vOptU(sc, fmt.Sprintf("P%d", e)); ok {
			L += v
			if v != r.P[e] {
				r.t.Fatalf("P%d = %d, model %d", e, v, r.P[e])
			}
		} else if r.P[e] != 0 {
			r.t.Fatalf("P%d missing, model %d", e, r.P[e])
		}
	}
	for tag := range r.mem {
		L += w.readU(sc, "s_"+tag)
	}
	r.l.conserve(L, "burned + epoch pools + stakes")
	if held := w.held(sc, crypto.ZEROHASH); held < r.burned {
		r.t.Fatalf("SC holds %d < burned %d", held, r.burned)
	}
}

func (r *plRun) inflow(e, v uint64) {
	b := v * plBeta / 100
	r.burned += b
	r.P[e] += v - b
}

func (r *plRun) register(u string, dep uint64) {
	tag := r.w.poolTag(u)
	ok := dep == plFee && r.mem[tag] == nil && tag != "0000000000000000" && tag != "ffffffffffffffff"
	r.l.do(ok, "Register", u, dep, nil, nil)
	if ok {
		m := &plMember{name: u, tag: tag}
		r.mem[tag], r.byName[u] = m, m
		r.inflow(r.H/plLen, dep)
		r.l.loss[u] += dep
	}
	r.check()
}

func (r *plRun) fund(s string, e, dep uint64) {
	ok := dep > 0 && e >= r.H/plLen && r.P[e]+dep <= plPmax
	r.l.do(ok, "Fund", s, dep, nil, nil, gtU("e", e))
	if ok {
		r.inflow(e, dep)
		r.l.loss[s] += dep
	}
	r.check()
}

func (r *plRun) lock(u string, dep uint64) {
	m := r.byName[u]
	ok := dep > 0 && m != nil && m.s+dep <= plPmax
	r.l.do(ok, "Lock", u, dep, nil, nil)
	if ok {
		m.s += dep
		m.since = r.H
	}
	r.check()
}

func (r *plRun) unlock(u string) {
	m := r.byName[u]
	ok := m != nil && m.s > 0 && r.H >= m.since+plLockh
	var pay map[string]uint64
	if ok {
		pay = map[string]uint64{u: m.s}
		m.s = 0
	}
	r.l.do(ok, "Unlock", u, 0, nil, pay)
	r.check()
}

// gen extends the main chain to height h
func (r *plRun) gen(h uint64, tagPool []string) {
	c := r.ch
	for x := c.top + 1; x <= h; x++ {
		tip := make([]byte, 32)
		if pb := c.b[x-1]; pb != nil {
			copy(tip, pb.id[:])
		} else {
			r.rng.Read(tip)
		}
		tags := make([]string, 10)
		kh := make([]int, 10)
		final := make([]bool, 10)
		for i := range tags {
			tags[i] = tagPool[r.rng.Intn(len(tagPool))]
			kh[i] = r.rng.Intn(6)
		}
		switch r.rng.Intn(10) {
		case 0: // the final miniblock elsewhere, and a tagged one
			final[r.rng.Intn(10)] = true
		case 1: // two finals
			final[9], final[r.rng.Intn(9)] = true, true
		default:
			final[9] = true
		}
		base := c.base[0]
		if r.rng.Intn(8) == 0 {
			base = c.base[3]
		}
		c.b[x] = c.synth(base, x, tags, kh, final, tip, 0)
	}
	if h > c.top {
		c.top = h
	}
}

// doAt is vLedger.do for a call under a chosen block id (runAt): no deposit, storage gas limited by plProver
func (r *plRun) doAt(want bool, blid crypto.Hash, entry, signer string, pay map[string]uint64, args ...rpc.Argument) error {
	r.t.Helper()
	r.l.calls++
	before := r.w.held(r.sc, crypto.ZEROHASH)
	_, _, err := r.w.runAt(r.sc, blid, r.H, entry, signer, plProver, args...)
	if (err == nil) != want {
		r.t.Fatalf("call %d %s by %s at %d (%s): model predicted success=%v, got err=%v", r.l.calls, entry, signer, r.H, vArgs(args), want, err)
	}
	if err != nil {
		if r.w.held(r.sc, crypto.ZEROHASH) != before {
			r.t.Fatalf("%s reverted but the balance moved", entry)
		}
		return err
	}
	var sum uint64
	for n, a := range pay {
		sum += a
		r.l.recv[n] += a
	}
	if after := r.w.held(r.sc, crypto.ZEROHASH); before-sum != after {
		r.t.Fatalf("call %d %s: SC balance %d - payouts %d != %d", r.l.calls, entry, before, sum, after)
	}
	for n := range pay {
		r.w.deroIs(n, r.l.recv[n])
	}
	return nil
}

// anchor: an Anchor call executed in the block of the current height
func (r *plRun) anchor(caller string) {
	b := r.ch.b[r.H]
	r.doAt(true, b.id, "Anchor", caller, nil)
	r.anch[r.H] = true
	if got := r.w.read(r.sc, fmt.Sprintf("b%d", r.H)); got != string(b.id[:]) {
		r.t.Fatalf("anchor of %d not stored", r.H)
	}
	r.check()
}

// prove runs ProveBlock (parent=false) or ProveParent of height h; wrongNtx feeds a wrong tx count
func (r *plRun) prove(prover string, h uint64, parent, wrongNtx bool) {
	b := r.ch.b[h]
	e := h / plLen
	ok := !r.pr[h] && r.H < (e+1)*plLen+plGrace && !wrongNtx
	entry := "ProveBlock"
	if parent {
		entry = "ProveParent"
		ok = ok && r.pr[h+1]
	} else {
		ok = ok && h < r.H && r.anch[h]
	}
	ntx := b.ntx
	if wrongNtx {
		ntx++
	}
	pay := map[string]uint64{}
	before := map[string]uint64{}
	if ok {
		flags, khs := plDecode(r.t, b.raw)
		n := 0
		exp := map[string]uint64{}
		for i, f := range flags {
			r.kcount[plKey(e, khs[i])]++
			r.kn[e]++
			if c := r.kcount[plKey(e, khs[i])]; c > r.km[e] {
				r.km[e] = c
			}
			m := r.mem[f]
			if m == nil {
				continue
			}
			wt := uint64(100)
			if m.s > 0 && m.since+plLen <= h {
				wt += vMin(100*m.s/plS, 100)
			}
			k := plKey(e, f)
			if _, seen := before[k]; !seen {
				before[k] = r.wc[k]
			}
			r.W[k] += wt
			r.wc[k]++
			r.TW[e] += wt
			exp[k]++
			n++
		}
		r.credits += uint64(n)
		if n > 0 && r.P[e] >= plPfee {
			r.P[e] -= plPfee
			pay[prover] = plPfee
			r.l.award[prover] += plPfee
		}
		r.pr[h] = true
		defer func() {
			// credits equal exactly the Go decoder's count of non-final miniblocks with each member's tag
			for k, c := range exp {
				if got := r.w.readU(r.sc, "w"+k); got != before[k]+c {
					r.t.Fatalf("credit w%s = %d, Go decoder count %d + %d", k, got, before[k], c)
				}
			}
		}()
	}
	var blid crypto.Hash
	blid[0], blid[1], blid[2] = 0x77, byte(r.H), byte(r.H>>8)
	r.doAt(ok, blid, entry, prover, pay, gtU("h", h), gtS("hx", b.hx), gtU("ntx", ntx))
	if ok {
		for k := range before {
			if got := r.w.readU(r.sc, "W"+k); got != r.W[k] {
				r.t.Fatalf("W%s = %d, model (100 + min(100 s / S, 100) per matured credit) %d", k, got, r.W[k])
			}
		}
		if got, _ := r.w.vOptU(r.sc, fmt.Sprintf("TW%d", e)); got != r.TW[e] {
			r.t.Fatalf("TW%d = %d, model %d", e, got, r.TW[e])
		}
		if r.kn[e] > 0 && (r.w.readU(r.sc, fmt.Sprintf("kn%d", e)) != r.kn[e] || r.w.readU(r.sc, fmt.Sprintf("km%d", e)) != r.km[e]) {
			r.t.Fatalf("census kn/km %d/%d, model %d/%d", r.w.readU(r.sc, fmt.Sprintf("kn%d", e)), r.w.readU(r.sc, fmt.Sprintf("km%d", e)), r.kn[e], r.km[e])
		}
	}
	r.check()
}

func (r *plRun) claim(u string, e uint64) {
	m := r.byName[u]
	ok := r.H >= (e+1)*plLen+plGrace && r.H < (e+5)*plLen+plGrace && m != nil
	var pay map[string]uint64
	if ok {
		k := plKey(e, m.tag)
		_, has := r.W[k]
		ok = has && !r.claimed[k]
		if ok {
			if _, snap := r.P0[e]; !snap {
				r.P0[e] = r.P[e]
			}
			P0 := r.P0[e]
			amt := vMin(P0*r.W[k]/r.TW[e], P0*plCap/100)
			r.P[e] -= amt
			r.claimed[k] = true
			if amt > 0 {
				pay = map[string]uint64{u: amt}
			}
			r.l.award[u] += amt
		}
	}
	r.l.do(ok, "Claim", u, 0, nil, pay, gtU("e", e))
	r.check()
}

func (r *plRun) rollover(who string, e uint64) {
	cur := r.H / plLen
	ok := r.H >= (e+5)*plLen+plGrace && r.P[e] > 0 && r.P[cur]+r.P[e] <= plPmax
	r.l.do(ok, "Rollover", who, 0, nil, nil, gtU("e", e))
	if ok {
		r.P[cur] += r.P[e]
		r.P[e] = 0
	}
	r.check()
}

// drain: every open claim is claimed, every closed pool rolled into the current epoch, every stake unlocked; what
// stays is exactly burned + the current epoch's pool (it carries to future members, never to anyone else)
func (r *plRun) drain() {
	r.t.Helper()
	for k := range r.W {
		var e uint64
		var tag string
		fmt.Sscanf(k, "%d_%s", &e, &tag)
		if r.H < (e+1)*plLen+plGrace {
			r.at((e+1)*plLen + plGrace)
		}
	}
	for k := range r.W {
		var e uint64
		var tag string
		fmt.Sscanf(k, "%d_%s", &e, &tag)
		if !r.claimed[k] && r.H < (e+5)*plLen+plGrace {
			r.claim(r.mem[tag].name, e)
		}
	}
	r.at((r.H/plLen+6)*plLen + plLockh)
	for _, m := range r.mem {
		if m.s > 0 {
			r.unlock(m.name)
		}
	}
	for e, v := range r.P {
		if v > 0 && r.H >= (e+5)*plLen+plGrace {
			r.rollover("x", e)
		}
	}
	cur := r.H / plLen
	var open uint64
	for e, v := range r.P {
		if v > 0 && r.H >= (e+5)*plLen+plGrace {
			r.t.Errorf("INVARIANT FAILS (liveness): pool of closed epoch %d (%d) could not be rolled", e, v)
		}
		open += v
	}
	if got := r.w.held(r.sc, crypto.ZEROHASH); got != r.burned+open || open != r.P[cur]+func() (f uint64) {
		for e, v := range r.P {
			if e != cur {
				f += v
			}
		}
		return
	}() {
		r.t.Errorf("INVARIANT FAILS (liveness): SC holds %d, burned %d + pools not yet closed %d", got, r.burned, open)
	}
	r.l.balances(r.names...)
}

// randomized: members register, lock and unlock stake, sponsors fund, a main chain is mined and proven by Anchor +
// ProveBlock + ProveParent at varying heights, members claim, anyone rolls over; all checks after every call
func TestR33VerifyPoolRandom(t *testing.T) {
	for _, seed := range []int64{33, 3301} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			members := []string{"alice", "bob", "carol", "dave"}
			r := plStart(t, seed, append(members, "eve", "x")...)
			rng := r.rng
			pick := func(s ...string) string { return s[rng.Intn(len(s))] }
			tagPool := []string{"0000000000000000", "01000000" + "00000000", "deadbeefdeadbeef", r.w.poolTag("eve")}
			for _, m := range members {
				// the full 8-byte tag twice, and a 4-byte prefix match with another nonce word (must never be credited)
				tagPool = append(tagPool, r.w.poolTag(m), r.w.poolTag(m), r.w.poolTag(m)[:8]+"00000000")
			}
			r.gen(r.H, tagPool)
			for step := 0; step < 900; step++ {
				r.at(r.H + uint64(rng.Intn(14)))
				r.gen(r.H, tagPool)
				cur := r.H / plLen
				switch a := rng.Intn(100); {
				case a < 5:
					dep := plFee
					if rng.Intn(6) == 0 {
						dep--
					}
					r.register(pick(append(members, "x")...), dep)
				case a < 10:
					e := cur + uint64(rng.Intn(3))
					if rng.Intn(8) == 0 && cur > 0 {
						e = cur - 1
					}
					r.fund(pick("sponsor", "x"), e, uint64(1+rng.Intn(300000)))
				case a < 15:
					r.lock(pick(append(members, "x")...), uint64(1+rng.Intn(150000)))
				case a < 19:
					r.unlock(pick(append(members, "x")...))
				case a < 34:
					r.anchor(pick("prover", "x"))
				case a < 54: // prove an anchored block
					hs := []uint64{}
					for h := range r.anch {
						if !r.pr[h] {
							hs = append(hs, h)
						}
					}
					if len(hs) > 0 {
						h := hs[rng.Intn(len(hs))]
						if rng.Intn(25) == 0 {
							h = r.H // the anchored block itself: refused
						}
						if r.ch.b[h] != nil {
							r.prove(pick("prover", "carol"), h, false, rng.Intn(20) == 0)
						}
					}
				case a < 72: // walk back one block from a proven one
					hs := []uint64{}
					for h := range r.pr {
						if !r.pr[h-1] && r.ch.b[h-1] != nil {
							hs = append(hs, h-1)
						}
					}
					if len(hs) > 0 {
						h := hs[rng.Intn(len(hs))]
						if rng.Intn(15) == 0 { // any height: refused unless its child is proven
							h = r.H - uint64(rng.Intn(60))
						}
						if r.ch.b[h] != nil {
							r.prove(pick("prover", "carol"), h, true, rng.Intn(20) == 0)
						}
					}
				case a < 88:
					e := cur - uint64(rng.Intn(7))
					r.claim(pick(append(members, "x")...), e)
				case a < 95:
					e := cur - 5 - uint64(rng.Intn(4))
					r.rollover(pick("x", "eve"), e)
				default:
					switch rng.Intn(3) {
					case 0:
						r.l.do(false, "Initialize", pick("owner", "x"), 0, nil, nil)
					case 1:
						r.l.do(len(r.mem) == 0, "SetMcount", "owner", 0, nil, nil, gtU("n", 10)) // refused once a member exists
					default:
						r.l.do(false, "Anchor", "x", 1, nil, nil)
					}
					r.check()
				}
			}
			t.Logf("seed %d: %d calls, %d members, %d blocks proven, %d credits, burned %d, height %d (epochs %d..%d)",
				seed, r.l.calls, len(r.mem), len(r.pr), r.credits, r.burned, r.H, plBase/plLen, r.H/plLen)
			if r.credits == 0 {
				t.Fatalf("no credits: the sequence did not exercise the pool")
			}
			r.drain()
			vGas(t, r.w, "gt_pool.bas")
		})
	}
}

// the burn: monotone, never sent, the SC never holds less than it
func TestR33VerifyPoolBurn(t *testing.T) {
	r := plStart(t, 7, "alice", "x")
	last := uint64(0)
	steps := []func(){
		func() { r.register("alice", plFee) },
		func() { r.fund("x", r.H/plLen, 999999) },
		func() { r.fund("x", r.H/plLen+3, 12345) },
		func() { r.lock("alice", 50000) },
	}
	for i := 0; i < 40; i++ {
		steps[i%len(steps)]()
		if b := r.w.readU(r.sc, "burned"); b < last {
			t.Errorf("INVARIANT FAILS: burned decreased %d -> %d", last, b)
		} else {
			last = b
		}
		r.at(r.H + 37)
	}
	r.gen(r.H, []string{r.w.poolTag("alice")})
	r.drain()
	if r.w.held(r.sc, crypto.ZEROHASH) < r.burned {
		t.Fatalf("held < burned")
	}
}

// Regression of the r33 verify finding: Initialize accepted a deposit (no DEROVALUE() check), which the SC then held
// in no pool, no stake and not burned, owed by nobody forever. Now an install with a deposit is refused, and an
// install without one starts with a zero balance.
func TestR33VerifyPoolInitializeDeposit(t *testing.T) {
	w := gtNew(t, "owner")
	w.at(plBase)
	if _, _, _, err := w.s.SCInstall(gtCode(t, "gt_pool.bas"), map[crypto.Hash]uint64{crypto.ZEROHASH: 50000}, rpc.Arguments{}, w.addr["owner"], 0); err == nil {
		t.Errorf("INVARIANT FAILS (conservation): install of gt_pool.bas with a 50000 deposit succeeded; it is owed by nobody")
	}
	scid, _, _, err := w.s.SCInstall(gtCode(t, "gt_pool.bas"), map[crypto.Hash]uint64{}, rpc.Arguments{}, w.addr["owner"], 0)
	if err != nil {
		t.Fatalf("install without a deposit: %v", err)
	}
	if held := w.held(scid, crypto.ZEROHASH); held != 0 || w.readU(scid, "burned") != 0 {
		t.Fatalf("fresh pool holds %d", held)
	}
}

// bounds: the largest proofs. (a) 9 distinct members credited and 9 distinct KeyHashes in one block (most new
// keys per proof); (b) a block with 127 transactions (the parse maximum, ~9.3 KB of hex argument); (c) the same
// as a ProveParent. Every proof must fit the 10M compute and the 20,000 storage gas a mainnet call can buy.
func TestR33VerifyPoolBounds(t *testing.T) {
	names := []string{}
	for i := 0; i < 9; i++ {
		names = append(names, fmt.Sprintf("m%d", i))
	}
	r := plStart(t, 9, names...)
	tags := make([]string, 10)
	for i, n := range names {
		r.register(n, plFee)
		r.lock(n, 1000000)
		tags[i] = r.w.poolTag(n)
	}
	tags[9] = "0000000000000000"
	kh := []int{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	final := make([]bool, 10)
	final[9] = true
	h := plBase + plLen + 10 // stakes matured
	r.fund("sponsor", h/plLen, 1000000)
	r.at(h)
	tip := make([]byte, 32)
	r.ch.b[h-1] = r.ch.synth(r.ch.base[0], h-1, tags, kh, final, tip, 127)
	r.ch.b[h] = r.ch.synth(r.ch.base[0], h, tags, []int{20, 21, 22, 23, 24, 25, 26, 27, 28, 29}, final, r.ch.b[h-1].id[:], 127)
	r.ch.top = h
	r.anchor("prover")
	r.at(h + 1)
	r.prove("prover", h, false, false)
	g1 := r.w.gas["proof:ProveBlock"]
	r.prove("prover", h-1, true, false)
	g2 := r.w.gas["proof:ProveParent"]
	t.Logf("ProveBlock, 127 txs, 9 members, 9 new KeyHashes: compute %d storage %d; ProveParent: compute %d storage %d (limits %d / %d)",
		g1[0], g1[1], g2[0], g2[1], vComputeLimit, vStorageLimit)
	for _, n := range names {
		if got := r.w.readU(r.sc, "w"+plKey(h/plLen, r.w.poolTag(n))); got != 2 {
			t.Fatalf("%s credits %d, want 2", n, got)
		}
	}
	r.at((h/plLen+1)*plLen + plGrace)
	for _, n := range names {
		r.claim(n, h/plLen)
	}
	r.drain()
	vGas(t, r.w, "gt_pool.bas")
}

// weights and payouts at the edges of the maturity rule and the cap: exact table
func TestR33VerifyPoolWeightsAndCap(t *testing.T) {
	r := plStart(t, 5, "a", "b", "c")
	ta, tb, tc := r.w.poolTag("a"), r.w.poolTag("b"), r.w.poolTag("c")
	r.register("a", plFee)
	r.register("b", plFee)
	r.register("c", plFee)
	r.lock("a", 1)       // boost 100*1/S = 0
	r.lock("b", 99999)   // boost 99
	r.lock("c", 5000000) // capped at 100
	e := r.H/plLen + 1
	start := e * plLen
	r.fund("sponsor", e, 1000000)
	r.fund("sponsor", e-1, 1000000)
	// stakes locked at plBase mature at plBase + 400 = start: the block at start - 1 (epoch e - 1) earns no boost,
	// the blocks start .. start + 3 (epoch e) earn it
	r.at(start + 3)
	r.gen(start+3, []string{ta, tb, tc})
	r.anchor("prover")
	r.at(start + 4)
	r.prove("prover", start+3, false, false)
	for h := start + 2; h >= start-1; h-- {
		r.prove("prover", h, true, false)
	}
	for _, n := range []string{"a", "b", "c"} {
		k := plKey(e-1, r.w.poolTag(n))
		if r.wc[k] > 0 && r.W[k] != 100*r.wc[k] {
			t.Fatalf("unmatured credits of %s weighted %d", n, r.W[k])
		}
	}
	r.at((e+1)*plLen + plGrace)
	for _, n := range []string{"a", "b", "c"} {
		r.claim(n, e)
		r.claim(n, e) // once
	}
	for _, n := range []string{"a", "b", "c"} {
		k := plKey(e, r.w.poolTag(n))
		t.Logf("%s: credits %d, W %d, claimed %d (P0 %d, TW %d, cap %d)", n, r.wc[k], r.W[k], r.w.readU(r.sc, "c"+k), r.P0[e], r.TW[e], r.P0[e]*plCap/100)
	}
	r.drain()
}

// access control and one-time actions: Initialize once, SetMcount owner-only and only before the first member,
// Register once per tag, no deposit where none is expected
func TestR33VerifyPoolAccess(t *testing.T) {
	r := plStart(t, 11, "alice", "x")
	r.l.do(false, "Initialize", "owner", 0, nil, nil)
	r.l.do(false, "Initialize", "x", 0, nil, nil)
	r.l.do(false, "SetMcount", "x", 0, nil, nil, gtU("n", 10))
	r.l.do(false, "SetMcount", "owner", 0, nil, nil, gtU("n", 0))
	r.l.do(false, "SetMcount", "owner", 0, nil, nil, gtU("n", 11))
	r.l.do(false, "SetMcount", "owner", 5, nil, nil, gtU("n", 10))
	r.l.do(true, "SetMcount", "owner", 0, nil, nil, gtU("n", 10))
	r.register("alice", plFee)
	r.register("alice", plFee)
	r.l.do(false, "SetMcount", "owner", 0, nil, nil, gtU("n", 10))
	r.l.do(false, "Unlock", "alice", 3, nil, nil)
	r.l.do(false, "Rollover", "x", 3, nil, nil, gtU("e", 1))
	r.l.do(false, "Claim", "alice", 3, nil, nil, gtU("e", 1))
	r.lock("x", 5000) // not a member
	r.unlock("x")
	r.check()
	if r.w.read(r.sc, "owner") != r.w.raw("owner") {
		t.Fatalf("owner changed")
	}
	vGas(t, r.w, "gt_pool.bas")
}
