// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package emission

// r23c: KATs for the per-account check, the coinbase-shape rule and SC-call payload burns. Each tampering case
// keeps every aggregate sum exact (so the Round 23 checks pass it) and moves value or randomness between accounts.

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

func (c *child) addTo(a acct, l, r *bn256.G1) {
	nb := c.get(a)
	nb.Balance = nb.Balance.Add(crypto.ConstructElGamal(l, r))
	c.bt.Put(a.key, nb.Serialize())
}

func wantNoAlerts(t *testing.T, r Report) {
	t.Helper()
	if len(r.Alerts) != 0 {
		t.Fatalf("unexpected alerts %v", r.Alerts)
	}
}

func TestR23cPerAccountHonestBlockIsExact(t *testing.T) {
	for i := 0; i < 3; i++ {
		w := newWorld(t)
		c := w.child("pa-honest")
		c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 93, 0, nil)
		c.transfer("t2", transaction.NORMAL, []acct{w.C, w.M1}, 110, 0, nil) // a miner inside a ring
		c.register(newAcct(), 0)
		c.coinbase(0)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOK, "")
		if r.PerAccount != "exact" || r.AccountsExact != r.Changed+r.Inserted {
			t.Fatalf("per_account %q exact %d changed %d inserted %d notes %v", r.PerAccount, r.AccountsExact, r.Changed, r.Inserted, r.Notes)
		}
		for _, p := range r.Payees {
			if !p.Explained {
				t.Fatalf("payee %s not explained: %+v", p.Key, r.Payees)
			}
		}
		if r.Payees[1].Verified { // M1 was in a ring: Verified keeps its Round 23 meaning
			t.Fatalf("ring-member payee reported verified")
		}
	}
}

// a miniblock share credited to the wrong miner: the aggregate Left is exact, the old auditor said ok
func TestR23cPerAccountDetectsMisattributedShare(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-steal")
	c.coinbase(0)
	share := (blockchain_reward(H)) / 10
	c.plus(w.M1, share)                                            // M1 gets one more share ...
	c.addTo(w.M2, new(bn256.G1).Neg(mulBaseU(share)), zeroPoint()) // ... taken from M2
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictAlert, "Left component moved by something other than its own ring commitments")
	for _, a := range r.Alerts {
		if strings.Contains(a, "Left components moved by plaintext value") {
			t.Fatalf("aggregate check fired; the case must keep the sum exact: %v", r.Alerts)
		}
	}
	if r.Payees[1].Explained || r.Payees[2].Explained {
		t.Fatalf("misattributed payees reported explained: %+v", r.Payees)
	}
}

// one ring member's commitment applied to another (C[0] and C[1] swapped): sums exact, accounts wrong
func TestR23cPerAccountDetectsSwappedCommitments(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-swap")
	h := c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 90, 0, nil)
	st := c.w.f.txs[h].Payloads[0].Statement
	diff := new(bn256.G1).Add(st.C[1], new(bn256.G1).Neg(st.C[0]))
	c.addTo(w.B, diff, zeroPoint())                    // B now holds C[1]
	c.addTo(w.C, new(bn256.G1).Neg(diff), zeroPoint()) // C now holds C[0]
	c.coinbase(0)
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "Left component moved by something other than its own ring")
}

// D values of two transactions swapped between their members: sum of Right exact, accounts wrong
func TestR23cPerAccountDetectsSwappedD(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-dswap")
	h1 := c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 90, 0, nil)
	h2 := c.transfer("t2", transaction.NORMAL, []acct{w.Pay, w.M2}, 90, 0, nil)
	d1, d2 := c.w.f.txs[h1].Payloads[0].Statement.D, c.w.f.txs[h2].Payloads[0].Statement.D
	x := new(bn256.G1).Add(d2, new(bn256.G1).Neg(d1))
	c.addTo(w.B, zeroPoint(), x)                      // B got D2
	c.addTo(w.Pay, zeroPoint(), new(bn256.G1).Neg(x)) // Pay got D1
	c.coinbase(0)
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictAlert, "Right component moved by something other than the D values of its own rings")
	if strings.Contains(strings.Join(r.Alerts, "|"), "Right components moved by something other than the published D") {
		t.Fatalf("aggregate Right check fired; the case must keep the sum exact: %v", r.Alerts)
	}
}

// with SC calls only Right is pinned per account; an SC payout is no per-account alert, a Right swap still is
func TestR23cPerAccountSCBlockIsRightOnly(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-sc")
	c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 700, scCall())
	c.setSC(5000 + 700 - 300)
	c.plus(w.Pay, 300)
	c.coinbase(0)
	c.commit(c.sct)
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOKSC, "")
	if r.PerAccount != "right_only" {
		t.Fatalf("per_account %q", r.PerAccount)
	}

	w = newWorld(t)
	c = w.child("pa-sc-dswap")
	h := c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 0, scCall())
	h2 := c.transfer("t2", transaction.NORMAL, []acct{w.Pay, w.M2}, 90, 0, nil)
	x := new(bn256.G1).Add(c.w.f.txs[h2].Payloads[0].Statement.D, new(bn256.G1).Neg(c.w.f.txs[h].Payloads[0].Statement.D))
	c.addTo(w.C, zeroPoint(), x)
	c.addTo(w.M2, zeroPoint(), new(bn256.G1).Neg(x))
	c.coinbase(0)
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "Right component moved by something other than the D values")
}

// a ring pointer that names no key: the per-account check steps aside, the aggregate checks still decide
func TestR23cPerAccountUnresolvedPointerIsNote(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-unres")
	h := c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 90, 0, nil)
	st := &c.w.f.txs[h].Payloads[0].Statement
	for i := range st.Publickeylist_pointers[:8] {
		st.Publickeylist_pointers[i] ^= 0xff
	}
	c.coinbase(0)
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOK, "")
	if r.PerAccount != "unresolved" || r.AccountsExact != 0 {
		t.Fatalf("per_account %q exact %d", r.PerAccount, r.AccountsExact)
	}
}

func TestR23cCoinbaseShape(t *testing.T) {
	// two finals at a post-399000 height: consensus refuses such a block, the auditor names it
	w := newWorld(t)
	c := w.child("shape2")
	c.bl.MiniBlocks[8].Final = true
	c.coinbase(0)
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "coinbase shape")

	// nine miniblocks
	w = newWorld(t)
	c = w.child("shape9")
	c.bl.MiniBlocks = c.bl.MiniBlocks[1:]
	c.coinbase(0)
	c.commit()
	wantVerdict(t, c.audit(mainnet), VerdictAlert, "coinbase shape")

	// below 399000 two finals were legal: a note, no alert
	w = newWorld(t)
	c = w.child("shape-old")
	c.bl.Height = 300000
	c.bl.MiniBlocks[8].Final = true
	c.coinbase(0)
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOK, "")
	wantNoAlerts(t, r)
	if r.Finals != 2 || len(r.Notes) == 0 {
		t.Fatalf("finals %d notes %v", r.Finals, r.Notes)
	}
}

// an SC call with two DERO payloads: the first one's BurnValue reaches no contract (incoming_value keeps the last)
func TestR23cSCCallEarlierDEROPayloadIsBurn(t *testing.T) {
	w := newWorld(t)
	c := w.child("sc2")
	h := c.transfer("call", transaction.SC_TX, []acct{w.B, w.C}, 50, 400, scCall())
	tx := c.w.f.txs[h]
	second := c.transfer("p2", transaction.NORMAL, []acct{w.Pay, w.M2}, 0, 600, nil) // borrow a second applied payload
	tx.Payloads = append(tx.Payloads, c.w.f.txs[second].Payloads[0])
	c.bl.Tx_hashes = c.bl.Tx_hashes[:1]
	delete(c.w.f.txs, second)
	c.setSC(5000 + 600)
	c.coinbase(0)
	c.commit(c.sct)
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOKSC, "")
	if r.Burns != 400 || r.SCDeposits != 600 {
		t.Fatalf("burns %d deposits %d, want 400 600", r.Burns, r.SCDeposits)
	}
}

// Verified keeps its Round 23 meaning (Right untouched and Left moved by exactly the share): a payee whose Right
// moved is never Verified, even when its Left delta is exactly its share
func TestR23cPayeeVerifiedNeedsRight(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-right")
	c.coinbase(0)
	c.addTo(w.M1, zeroPoint(), rndPoint())
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictAlert, "Right component moved")
	if r.Payees[1].Verified || r.Payees[1].Explained {
		t.Fatalf("payee with a moved Right reported verified/explained: %+v", r.Payees[1])
	}
}

// a miner registered in the same block: Explained by the per-account check, never Verified (no pre-state)
func TestR23cRegisteredPayee(t *testing.T) {
	w := newWorld(t)
	c := w.child("pa-newminer")
	n := newAcct()
	c.register(n, 0)
	s := graviton.Sum(n.key)
	copy(c.bl.MiniBlocks[0].KeyHash[:16], s[:16])
	c.coinbase(0)
	c.commit()
	r := c.audit(mainnet)
	wantVerdict(t, r, VerdictOK, "")
	var found bool
	for _, p := range r.Payees {
		if p.Key == fmt.Sprintf("%x", n.key) {
			found = true
			if p.Verified || !p.Explained || p.Amount != 3075 {
				t.Fatalf("new miner payee %+v", p)
			}
		}
	}
	if !found || r.PerAccount != "exact" || r.AccountsExact != r.Changed+r.Inserted {
		t.Fatalf("found %v per_account %q exact %d changed %d inserted %d", found, r.PerAccount, r.AccountsExact, r.Changed, r.Inserted)
	}
}

func blockchain_reward(h uint64) uint64 { return BlockReward(h) }

var _ = big.NewInt
