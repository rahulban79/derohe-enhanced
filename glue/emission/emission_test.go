// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package emission

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// The fake chain applies block effects with the same ElGamal operations consensus uses (transaction_execute.go,
// dvm ProcessExternal), so an honest block must audit clean and every deviation must be named.

type fakeChain struct {
	store    *graviton.Store
	blocks   map[crypto.Hash]*block.Block
	txs      map[crypto.Hash]*transaction.Transaction
	versions map[crypto.Hash]uint64
}

func (f *fakeChain) Block(h crypto.Hash) (*block.Block, error) {
	if b, ok := f.blocks[h]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("no block %s", h)
}
func (f *fakeChain) Tx(h crypto.Hash) (*transaction.Transaction, error) {
	if t, ok := f.txs[h]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("no tx %s", h)
}
func (f *fakeChain) State(h crypto.Hash) (*graviton.Snapshot, error) {
	v, ok := f.versions[h]
	if !ok {
		return nil, fmt.Errorf("no state %s", h)
	}
	return f.store.LoadSnapshot(v)
}

func rnd() *big.Int {
	var b [32]byte
	rand.Read(b[:])
	return new(big.Int).Mod(new(big.Int).SetBytes(b[:]), bn256.Order)
}
func rndPoint() *bn256.G1 { return new(bn256.G1).ScalarBaseMult(rnd()) }

type acct struct {
	y   *bn256.G1
	key []byte
}

func newAcct() acct {
	y := rndPoint()
	return acct{y: y, key: y.EncodeCompressed()}
}
func hashOf(s string) crypto.Hash { return crypto.Keccak256([]byte(s)) }

var scid = func() crypto.Hash { h := hashOf("sc"); h[0], h[31] = 0x80, 0x80; return h }()

const H = 7700000 // mainnet height after HF3: base reward 30750

type world struct {
	t                    *testing.T
	f                    *fakeChain
	parent               crypto.Hash
	A, B, C, M1, M2, Pay acct
}

func newWorld(t *testing.T) *world {
	st, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, f: &fakeChain{store: st, blocks: map[crypto.Hash]*block.Block{}, txs: map[crypto.Hash]*transaction.Transaction{}, versions: map[crypto.Hash]uint64{}}}
	w.A, w.B, w.C, w.M1, w.M2, w.Pay = newAcct(), newAcct(), newAcct(), newAcct(), newAcct(), newAcct()
	ss, _ := st.LoadSnapshot(0)
	bt, _ := ss.GetTree(config.BALANCE_TREE)
	for i, a := range []acct{w.A, w.B, w.C, w.M1, w.M2, w.Pay} {
		e := crypto.CommitElGamal(a.y, new(big.Int).SetUint64(uint64(1000*(i+1))))
		bt.Put(a.key, (&crypto.NonceBalance{Balance: e}).Serialize())
	}
	meta, _ := ss.GetTree(config.SC_META)
	meta.Put(scid[:], []byte("meta0"))
	sct, _ := ss.GetTree(string(scid[:]))
	var z crypto.Hash
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], 5000)
	sct.Put(z[:], v[:])
	ver, err := graviton.Commit(bt, meta, sct)
	if err != nil {
		t.Fatal(err)
	}
	w.parent = hashOf("parent")
	w.f.versions[w.parent] = ver
	return w
}

// child holds the trees a test block mutates, opened on the parent's state.
type child struct {
	w        *world
	ss       *graviton.Snapshot
	bt, meta *graviton.Tree
	sct      *graviton.Tree
	bl       *block.Block
	id       crypto.Hash
}

func (w *world) child(name string) *child {
	ss, _ := w.f.State(w.parent)
	c := &child{w: w, ss: ss, id: hashOf(name)}
	c.bt, _ = ss.GetTree(config.BALANCE_TREE)
	c.meta, _ = ss.GetTree(config.SC_META)
	c.sct, _ = ss.GetTree(string(scid[:]))
	c.bl = &block.Block{Height: H, Tips: []crypto.Hash{w.parent}}
	copy(c.bl.Miner_TX.MinerAddress[:], w.A.key)
	// 10 miniblocks: 6 by M1, 3 by M2, the final one by the integrator
	for i := 0; i < 10; i++ {
		var mb block.MiniBlock
		switch {
		case i < 6:
			s := graviton.Sum(w.M1.key)
			copy(mb.KeyHash[:16], s[:16])
		case i < 9:
			s := graviton.Sum(w.M2.key)
			copy(mb.KeyHash[:16], s[:16])
		default:
			mb.Final, mb.HighDiff = true, true
		}
		c.bl.MiniBlocks = append(c.bl.MiniBlocks, mb)
	}
	return c
}

func (c *child) get(a acct) *crypto.NonceBalance {
	b, err := c.bt.Get(a.key)
	if err != nil {
		c.w.t.Fatal(err)
	}
	return new(crypto.NonceBalance).Deserialize(b)
}
func (c *child) plus(a acct, v uint64) { // ElGamal.Plus, as the coinbase and SC payouts do
	nb := c.get(a)
	nb.Balance = nb.Balance.Plus(new(big.Int).SetUint64(v))
	c.bt.Put(a.key, nb.Serialize())
}

// transfer adds a NORMAL/SC tx with a random (C, D) ring of two to the block and applies it like consensus does.
func (c *child) transfer(name string, typ transaction.TransactionType, ring []acct, fee, burn uint64, scdata rpc.Arguments) crypto.Hash {
	st := crypto.Statement{RingSize: uint64(len(ring)), D: rndPoint(), Fees: fee, Bytes_per_publickey: 8}
	for i := range ring {
		ks := graviton.Sum(ring[i].key) // r23c: ring members named by key-hash prefix, as on chain
		st.Publickeylist_pointers = append(st.Publickeylist_pointers, ks[:8]...)
		ci := rndPoint()
		st.C = append(st.C, ci)
		nb := c.get(ring[i])
		nb.Balance = nb.Balance.Add(crypto.ConstructElGamal(ci, st.D))
		c.bt.Put(ring[i].key, nb.Serialize())
	}
	tx := &transaction.Transaction{}
	tx.Version, tx.TransactionType, tx.SCDATA = 1, typ, scdata
	tx.Payloads = []transaction.AssetPayload{{BurnValue: burn, Statement: st}}
	h := hashOf(name)
	c.w.f.txs[h] = tx
	c.bl.Tx_hashes = append(c.bl.Tx_hashes, h)
	return h
}

func (c *child) register(a acct, bonus uint64) {
	tx := &transaction.Transaction{}
	tx.Version, tx.TransactionType = 1, transaction.REGISTRATION
	copy(tx.MinerAddress[:], a.key)
	h := hashOf(fmt.Sprintf("reg%x", a.key))
	c.w.f.txs[h] = tx
	c.bl.Tx_hashes = append(c.bl.Tx_hashes, h)
	e := crypto.ConstructElGamal(a.y, crypto.ElGamal_BASE_G).Plus(new(big.Int).SetUint64(bonus))
	c.bt.Put(a.key, (&crypto.NonceBalance{Balance: e}).Serialize())
}

func (c *child) fees() (f uint64) {
	for _, h := range c.bl.Tx_hashes {
		f += c.w.f.txs[h].Fees()
	}
	return
}

// coinbase credits the split exactly as process_miner_transaction does.
func (c *child) coinbase(extraIntegrator uint64) {
	full := blockchain.CalcBlockReward(c.bl.Height) + c.fees()
	share := full / uint64(len(c.bl.MiniBlocks))
	left := full - share*uint64(len(c.bl.MiniBlocks))
	c.plus(c.w.A, share+left+extraIntegrator)
	for _, mb := range c.bl.MiniBlocks {
		if mb.Final {
			continue
		}
		_, k, _, err := c.bt.GetKeyValueFromHash(mb.KeyHash[:16])
		if err != nil {
			c.w.t.Fatal(err)
		}
		nb := new(crypto.NonceBalance)
		b, _ := c.bt.Get(k)
		nb.Deserialize(b)
		nb.Balance = nb.Balance.Plus(new(big.Int).SetUint64(share))
		c.bt.Put(k, nb.Serialize())
	}
}

func (c *child) setSC(v uint64) {
	var z crypto.Hash
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	c.sct.Put(z[:], b[:])
	c.meta.Put(scid[:], []byte(fmt.Sprintf("meta%d", v)))
}

func (c *child) commit(trees ...*graviton.Tree) {
	ver, err := graviton.Commit(append([]*graviton.Tree{c.bt, c.meta}, trees...)...)
	if err != nil {
		c.w.t.Fatal(err)
	}
	c.w.f.versions[c.id] = ver
	c.w.f.blocks[c.id] = c.bl
}

func (c *child) audit(p Params) Report {
	r, err := AuditBlock(c.w.f, c.id, p)
	if err != nil {
		c.w.t.Fatalf("audit error: %v", err)
	}
	return r
}

var mainnet = Params{Mainnet: true}

func wantVerdict(t *testing.T, r Report, v string, alertSub string) {
	t.Helper()
	if r.Verdict != v {
		t.Fatalf("verdict %q, want %q (alerts %v notes %v)", r.Verdict, v, r.Alerts, r.Notes)
	}
	if alertSub != "" && !strings.Contains(strings.Join(r.Alerts, "|"), alertSub) {
		t.Fatalf("alerts %v do not mention %q", r.Alerts, alertSub)
	}
}

func TestFormulaMatchesConsensus(t *testing.T) {
	for _, h := range []uint64{0, 1, 17, 144000, 6999999, 7000000, 7000001, 7504640, 7800000, 13999999, 14000000, 14000001, 99999999} {
		if BlockReward(h) != blockchain.CalcBlockReward(h) {
			t.Fatalf("BlockReward(%d) = %d, consensus %d", h, BlockReward(h), blockchain.CalcBlockReward(h))
		}
		if FormulaSupply(h) != blockchain.CalcSupply(h) {
			t.Fatalf("FormulaSupply(%d) = %d, consensus %d", h, FormulaSupply(h), blockchain.CalcSupply(h))
		}
	}
	if BlockReward(H) != 30750 {
		t.Fatalf("reward at %d = %d, want 30750", H, BlockReward(H))
	}
}

func TestSplitReward(t *testing.T) {
	s := SplitReward(30750, 7, 10, 1)
	if s.Share != 3075 || s.Leftover != 7 || s.Paid != 30757 {
		t.Fatalf("split %+v", s)
	}
	s = SplitReward(30750, 0, 10, 2) // two finals: consensus pays one share less
	if s.Paid != 30750-3075 {
		t.Fatalf("two finals paid %d", s.Paid)
	}
}

func TestEmissionAuditHonestCoinbase(t *testing.T) {
	for i := 0; i < 3; i++ {
		w := newWorld(t)
		c := w.child("b1")
		c.coinbase(0)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOK, "")
		if r.Paid != 30750 || r.Changed != 3 || len(r.Payees) != 3 {
			t.Fatalf("paid %d changed %d payees %d", r.Paid, r.Changed, len(r.Payees))
		}
		for _, p := range r.Payees {
			if !p.Verified {
				t.Fatalf("payee %s not verified", p.Key)
			}
		}
		if r.Payees[1].Amount != 6*3075 || r.Payees[2].Amount != 3*3075 {
			t.Fatalf("payee amounts %+v", r.Payees)
		}
	}
}

func TestEmissionAuditHonestTransfersAndRegistration(t *testing.T) {
	for i := 0; i < 3; i++ {
		w := newWorld(t)
		c := w.child("b2")
		c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 93, 0, nil)   // fees 203: leftover 3 goes to the integrator
		c.transfer("t2", transaction.NORMAL, []acct{w.C, w.M1}, 110, 0, nil) // a miner inside a ring
		c.register(newAcct(), 0)
		c.coinbase(0)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOK, "")
		if r.Fees != 203 || r.Paid != 30953 || r.Inserted != 1 || r.Registrations != 1 {
			t.Fatalf("fees %d paid %d inserted %d regs %d", r.Fees, r.Paid, r.Inserted, r.Registrations)
		}
		if r.Payees[0].Amount != 3095+3 || r.Payees[0].Verified != true || r.Payees[1].Verified != false { // A untouched, M1 was in a ring
			t.Fatalf("payee verification %+v", r.Payees)
		}
	}
}

func TestEmissionAuditPlaintextFlowProxy(t *testing.T) {
	w := newWorld(t)
	c := w.child("flows")
	c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 4000, 0, nil)
	c.transfer("t2", transaction.NORMAL, []acct{w.C, w.M1}, 70, 0, nil)
	c.coinbase(0)
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOK, "")
	if r.MaxTxFee != 4000 || r.MaxPlainFlow != 4000 {
		t.Fatalf("max fee %d max flow %d, want 4000", r.MaxTxFee, r.MaxPlainFlow)
	}
}

func TestEmissionAuditTestnetRegistrationBonus(t *testing.T) {
	w := newWorld(t)
	c := w.child("b3")
	c.register(newAcct(), TestnetRegistration)
	c.coinbase(0)
	c.commit()
	wantVerdict(t, c.audit(Params{Mainnet: false}), VerdictOK, "")
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "Left components") // the same block is over-credited on mainnet
}

func TestEmissionAuditDetectsExtraCoinbase(t *testing.T) {
	for _, extra := range []uint64{1, 30750, 1 << 40} {
		w := newWorld(t)
		c := w.child("bad")
		c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 90, 0, nil)
		c.coinbase(extra)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictAlert, "Left components moved by plaintext value")
		if r.Payees[0].Verified {
			t.Fatalf("over-credited integrator reported verified")
		}
	}
}

func TestEmissionAuditDetectsMissingCoinbase(t *testing.T) {
	w := newWorld(t)
	c := w.child("short")
	c.commit() // no reward credited at all
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "Left components")
}

func TestEmissionAuditDetectsRightTamper(t *testing.T) {
	w := newWorld(t)
	c := w.child("right")
	c.coinbase(0)
	nb := c.get(w.B)
	nb.Balance = crypto.ConstructElGamal(nb.Balance.Left, new(bn256.G1).Add(nb.Balance.Right, rndPoint()))
	c.bt.Put(w.B.key, nb.Serialize())
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "Right components")
}

func TestEmissionAuditDetectsUnregisteredAccount(t *testing.T) {
	w := newWorld(t)
	c := w.child("ghost")
	c.coinbase(0)
	g := newAcct()
	c.bt.Put(g.key, (&crypto.NonceBalance{Balance: crypto.ConstructElGamal(g.y, crypto.ElGamal_BASE_G)}).Serialize())
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "created without a registration")
}

func TestEmissionAuditDetectsDeletedAccount(t *testing.T) {
	w := newWorld(t)
	c := w.child("del")
	c.coinbase(0)
	c.bt.Delete(w.Pay.key)
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "deleted from the balance tree")
}

func scCall() rpc.Arguments {
	return rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid}}
}

func TestEmissionAuditSCPayout(t *testing.T) {
	for _, tc := range []struct {
		deposit, payout uint64
	}{{700, 300}, {0, 1200}, {500, 0}, {700, 5700}} {
		w := newWorld(t)
		c := w.child("sc")
		c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, tc.deposit, scCall())
		c.setSC(5000 + tc.deposit - tc.payout)
		if tc.payout > 0 {
			c.plus(w.Pay, tc.payout)
		}
		c.coinbase(0)
		c.commit(c.sct)
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOKSC, "")
		if r.SCPayout != tc.payout || r.SCDeposits != tc.deposit {
			t.Fatalf("payout %d deposits %d, want %d %d", r.SCPayout, r.SCDeposits, tc.payout, tc.deposit)
		}
	}
}

func TestEmissionAuditSCRevertAndBurn(t *testing.T) {
	// refunded to the signer (counts as a payout of the deposit) and destroyed (anonymous) both explain exactly
	for _, refund := range []bool{true, false} {
		w := newWorld(t)
		c := w.child("rev")
		c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 900, scCall())
		if refund {
			c.plus(w.B, 900)
		}
		c.coinbase(0)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOKSC, "")
		if want := map[bool]uint64{true: 900, false: 0}[refund]; r.SCPayout != want {
			t.Fatalf("refund=%v payout %d", refund, r.SCPayout)
		}
	}
}

func TestEmissionAuditDetectsSCCreation(t *testing.T) {
	w := newWorld(t)
	c := w.child("mint")
	c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 100, scCall())
	c.setSC(5000 + 101) // one atomic unit more than deposited
	c.coinbase(0)
	c.commit(c.sct)
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "SC-held plaintext DERO grew")
}

func TestEmissionAuditDetectsSCChangeWithoutCall(t *testing.T) {
	w := newWorld(t)
	c := w.child("nocall")
	c.setSC(4000)
	c.plus(w.Pay, 1000)
	c.coinbase(0)
	c.commit(c.sct)
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "without an SC call")
}

func TestEmissionAuditSCOverpayIsUnexplained(t *testing.T) {
	// an account credited more than the SC paid out: no candidate matches (reported, kept apart from exact alerts)
	w := newWorld(t)
	c := w.child("over")
	c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 0, scCall())
	c.setSC(4000)
	c.plus(w.Pay, 1001)
	c.coinbase(0)
	c.commit(c.sct)
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictSCUnexplained, "")
}

func TestEmissionAuditSkipsProtocolHeights(t *testing.T) {
	w := newWorld(t)
	c := w.child("skip")
	c.commit()
	r := c.audit(Params{Mainnet: true, SkipHeights: map[uint64]bool{H: true}})
	wantVerdict(t, r, VerdictSkipped, "")
}

func TestMatchPayoutSubsets(t *testing.T) {
	deps := []uint64{3, 50, 700, 9000}
	for mask := 0; mask < 16; mask++ {
		var s uint64
		for i := range deps {
			if mask&(1<<uint(i)) != 0 {
				s += deps[i]
			}
		}
		delta := big.NewInt(-25) // SC paid 25 out of reserves as well
		P := s + 25
		got, ok := matchPayout(mulBaseU(P), deps, delta)
		if !ok || got != P {
			t.Fatalf("mask %d: got %d ok %v want %d", mask, got, ok, P)
		}
	}
	if _, ok := matchPayout(mulBaseU(4), deps, big.NewInt(0)); ok {
		t.Fatalf("4 is no subset sum")
	}
	if _, ok := matchPayout(mulBase(big.NewInt(-1)), deps, big.NewInt(1)); ok { // P must not be negative
		t.Fatalf("negative payout accepted")
	}
}

// r23 merge: re-registering an existing account replaced its balance before HF3 (consensus-legal then): a note, and
// the block still balances; from HF3 on (or with HF3Height unset) it stays an alert.
func TestEmissionAuditPreHF3ReRegistrationIsNote(t *testing.T) {
	mk := func() *child {
		w := newWorld(t)
		c := w.child("rereg")
		c.register(w.B, 0)
		c.coinbase(0)
		c.commit()
		return c
	}
	r := mk().audit(Params{Mainnet: true, HF3Height: H + 1})
	wantVerdict(t, r, VerdictOK, "")
	if len(r.Notes) == 0 {
		t.Fatal("pre-HF3 re-registration left no note")
	}
	wantVerdict(t, mk().audit(Params{Mainnet: true, HF3Height: H}), VerdictAlert, "reset its balance")
	wantVerdict(t, mk().audit(mainnet), VerdictAlert, "reset its balance")
}
