// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

// Package emission is an independent, read-only auditor of what each block did to the plaintext side of the DERO
// money supply (Round 23). It never takes part in consensus: it reads a block, the balance state its execution
// started from (the snapshot of Tips[0], blockchain.go:964) and the state it produced, and checks that the
// difference is exactly what the block's public data and the emission formula allow.
//
// What is checkable. Every change the protocol makes to an account is a homomorphic addition of a PUBLIC delta:
//   - a transfer payload adds (C[i], D) to ring member i (transaction_execute.go:250);
//   - the coinbase adds share*G (+leftover for the integrator) to the Left component only (ElGamal.Plus);
//   - a registration creates (pubkey, G) (+ a fixed bonus on testnet / before mainnet height 144000);
//   - a smart contract pays plaintext DERO into accounts with Plus (dvm ProcessExternal / ErrorRevert).
//
// So, summed over every account the block changed (a graviton tree diff), the Right components must grow by exactly
// sum(RingSize*D) and the Left components by exactly sum(C[i]) + (coinbase + registration bonus + SC payouts)*G.
// The SC payout total P is pinned by plaintext SC accounting: P = sum(credited deposits) - delta(SC-held DERO), where
// each SC call's deposit is either credited/refunded or destroyed (anonymous revert), so P has 2^m candidates.
//
// What is NOT checkable, by construction: the amounts inside C[i] are encrypted. Value created inside a transfer
// (the disclosed range-proof soundness class) is a valid-looking (C, D) and passes this audit. This package only
// proves that nothing outside the published deltas and the formula moved plaintext value.
package emission

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// Emission constants, written out as numbers (not imported from blockchain/) so that this auditor is an independent
// statement of the schedule; TestFormulaMatchesConsensus pins them to blockchain.CalcBlockReward/CalcSupply.
const (
	BaseRewardAtomic      = 123000  // (41 * 100000 * BLOCK_TIME) / 600 with BLOCK_TIME = 18
	ReductionInterval     = 7000000 // 210000 * 600 / BLOCK_TIME
	ClaimBonusTotalAtomic = 271739600
	ClaimBonusPerAccount  = 200    // mainnet registrations below height 144000
	ClaimBonusEndHeight   = 144000 // 86400/18*30
	TestnetRegistration   = 100000000

	// r23c: the coinbase shape consensus enforces (blockchain/miniblocks_consensus.go Verify_MiniBlocks): every block
	// carries BLOCK_TIME-MINIBLOCK_HIGHDIFF+1 = 10 miniblocks with at least one final; from height 399000 (the "soft
	// HF") the 9 non-final ones must all be present, so exactly one is final.
	MiniblocksPerBlock    = 10
	SingleFinalFromHeight = 399000
)

// BlockReward is the coinbase subsidy of a block at height h.
func BlockReward(h uint64) uint64 {
	return BaseRewardAtomic >> ((h + ReductionInterval) / ReductionInterval)
}

// FormulaSupply is the supply the emission formula allows after the block at height h (what GetInfo reports).
func FormulaSupply(h uint64) uint64 {
	s := config.PREMINE + ClaimBonusTotalAtomic
	for start := uint64(0); start < h; start += ReductionInterval {
		if BlockReward(start) == 0 {
			// r27: every later interval pays 0 as well (the reward halves per interval: 0 from start 112,000,000 on).
			// Without the stop, a caller's FormulaSupply(h-1) at h == 0 (2^64-1) looped ~2.6e12 times, and start
			// wrapped past 2^64 back below h: the archive auditor hung on a genesis report.
			break
		}
		n := uint64(ReductionInterval)
		if h-start < n {
			n = h - start
		}
		s += BlockReward(start) * n
	}
	return s
}

// SupplyBefore is the formula supply before the block at height h (FormulaSupply(h-1)); at h == 0, the genesis, it is
// FormulaSupply(0): no block before it paid a reward, and h-1 must not wrap to 2^64-1.
func SupplyBefore(h uint64) uint64 {
	if h == 0 {
		return FormulaSupply(0)
	}
	return FormulaSupply(h - 1)
}

// Split is the coinbase division of transaction_execute.go:126-160, restated: full = base + fees is divided into
// len(MiniBlocks) equal shares; the integrator gets one share plus the remainder, every non-final miniblock one
// share, so Paid = full - share*(finals-1). From height 399000 consensus enforces exactly one final miniblock
// (blockchain/miniblocks_consensus.go: 10 miniblocks, of which 9 non-final in the collection); finals != 1 is only
// possible in the historical blocks below that height. The general formula is kept for those.
type Split struct {
	Full, Share, Leftover, Paid uint64
	Miniblocks, Finals          int
}

func SplitReward(base, fees uint64, miniblocks, finals int) (s Split) {
	s.Full = base + fees // uint64 wrap, as in consensus
	s.Miniblocks, s.Finals = miniblocks, finals
	if miniblocks <= 0 {
		return
	}
	s.Share = s.Full / uint64(miniblocks)
	s.Leftover = s.Full - s.Share*uint64(miniblocks)
	s.Paid = s.Share + s.Leftover + s.Share*uint64(miniblocks-finals)
	return
}

// Source gives the auditor read access to a chain.
type Source interface {
	Block(blid crypto.Hash) (*block.Block, error)
	Tx(txid crypto.Hash) (*transaction.Transaction, error)
	State(blid crypto.Hash) (*graviton.Snapshot, error) // the state committed by executing blid
}

type Params struct {
	Mainnet, Simulator bool
	SkipHeights        map[uint64]bool // heights with protocol-installed contracts (0 and HF1 on mainnet)
	MaxSCSubset        int             // SC calls with a deposit beyond this make the Left check unverifiable (default 12)
	// HF3Height: below it consensus allowed re-registering an existing account, which replaces its balance
	// (blockchain.go refuses it only from MAJOR_HF3_HEIGHT). 0 = treat every height as post-HF3 (strict).
	HF3Height uint64
}

const (
	VerdictOK            = "ok"             // every plaintext movement explained exactly
	VerdictOKSC          = "ok_sc"          // explained exactly, using the SC payout candidate set
	VerdictSCUnexplained = "sc_unexplained" // block with SC calls whose Left residual matched no candidate (see doc)
	VerdictSkipped       = "skipped"
	VerdictError         = "error"
	VerdictAlert         = "ALERT"
)

type Payee struct {
	Key      string `json:"key"` // compressed public key, hex
	Amount   uint64 `json:"amount"`
	Verified bool   `json:"verified"` // its ciphertext moved by exactly Amount*G and nothing else
	// r23c: its ciphertext moved by exactly Amount*G plus the (C[i], D) of every ring it sat in (per-account check);
	// a miner that also sent or received a transfer in the block is explained, not merely unverified
	Explained bool `json:"explained"`
}

type Report struct {
	BLID          string  `json:"blid"`
	Height        uint64  `json:"height"`
	Txs           int     `json:"txs"`
	Registrations int     `json:"registrations"`
	SCCalls       int     `json:"sc_calls"`
	Miniblocks    int     `json:"miniblocks"`
	Finals        int     `json:"finals"`
	BaseReward    uint64  `json:"base_reward"`
	Fees          uint64  `json:"fees"`
	FeesOverflow  bool    `json:"fees_overflow,omitempty"`
	Paid          uint64  `json:"paid"` // what the coinbase credited in total
	Payees        []Payee `json:"payees,omitempty"`
	Changed       int     `json:"changed_accounts"`
	Inserted      int     `json:"inserted_accounts"`
	SCDeposits    uint64  `json:"sc_deposits"` // plaintext DERO offered to SCs by this block's calls
	SCDelta       string  `json:"sc_delta"`    // change of SC-held DERO (signed, atomic units)
	SCPayout      uint64  `json:"sc_payout"`   // P: plaintext DERO paid from SCs into accounts (when matched)
	BurnTxValue   uint64  `json:"burn_value"`  // largest single plaintext burn (a DERO payload's BurnValue outside an SC call)
	Burns         uint64  `json:"burns"`       // r23b: total plaintext DERO burned by this block's transactions
	MaxTxFee      uint64  `json:"max_tx_fee"`  // largest single fee: a fee is plaintext value handed to miners
	MaxPlainFlow  uint64  `json:"max_plaintext_flow"`
	// r23c per-account check: "exact" (every changed account's Left and Right explained by its own ring deltas,
	// coinbase share and registration), "right_only" (a block with SC calls: SC payouts credit Left by amounts the
	// block does not publish per account, so only Right is pinned per account), "unresolved" (a ring pointer did not
	// resolve to one key: the aggregate checks still apply)
	PerAccount    string   `json:"per_account,omitempty"`
	AccountsExact int      `json:"accounts_exact"`
	Verdict       string   `json:"verdict"`
	Alerts        []string `json:"alerts,omitempty"`
	Notes         []string `json:"notes,omitempty"`
	Micros        int64    `json:"micros"`
}

var valueBase = crypto.NewElGamal().G // the base ElGamal.Plus credits plaintext on

func zeroPoint() *bn256.G1          { return new(bn256.G1).Set(crypto.ElGamal_ZERO) }
func samePoint(a, b *bn256.G1) bool { return bytes.Equal(a.Marshal(), b.Marshal()) }
func mulBase(v *big.Int) *bn256.G1 {
	if v.Sign() >= 0 {
		return new(bn256.G1).ScalarMult(valueBase, v)
	}
	return new(bn256.G1).Neg(new(bn256.G1).ScalarMult(valueBase, new(big.Int).Neg(v)))
}
func mulBaseU(v uint64) *bn256.G1 { return mulBase(new(big.Int).SetUint64(v)) }

// decodeBalance is NonceBalance.Deserialize with its panics turned into errors.
func decodeBalance(b []byte) (e *crypto.ElGamal, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("undecodable balance (%d bytes): %v", len(b), r)
		}
	}()
	nb := new(crypto.NonceBalance).Deserialize(b)
	return nb.Balance, nil
}

func scHeldDERO(ss *graviton.Snapshot, scid []byte) uint64 {
	t, err := ss.GetTree(string(scid))
	if err != nil {
		return 0
	}
	var zero crypto.Hash
	b, err := t.Get(zero[:])
	if err != nil || len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func cp(b []byte) []byte { return append([]byte(nil), b...) }

// acctDelta is a change of one account's ElGamal ciphertext (r23c per-account check).
type acctDelta struct{ L, R *bn256.G1 }

func newAcctDelta() *acctDelta { return &acctDelta{L: zeroPoint(), R: zeroPoint()} }

func (r *Report) alert(f string, a ...interface{}) { r.Alerts = append(r.Alerts, fmt.Sprintf(f, a...)) }
func (r *Report) note(f string, a ...interface{})  { r.Notes = append(r.Notes, fmt.Sprintf(f, a...)) }

// AuditBlock audits one block. An error means it could not be audited (missing data); a detected violation is a
// Report with Verdict ALERT, never an error.
func AuditBlock(src Source, blid crypto.Hash, p Params) (r Report, err error) {
	t0 := time.Now()
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("audit panicked: %v", x)
		}
		if err != nil {
			r.Verdict = VerdictError
		}
		r.Micros = time.Since(t0).Microseconds()
	}()
	r.BLID = blid.String()
	r.SCDelta = "0"
	bl, err := src.Block(blid)
	if err != nil {
		return r, err
	}
	r.Height = bl.Height
	r.Txs = len(bl.Tx_hashes)
	if bl.Height == 0 || p.SkipHeights[bl.Height] || len(bl.Tips) == 0 {
		r.Verdict = VerdictSkipped
		r.note("protocol-installed contracts or genesis at this height")
		return r, nil
	}
	pre, err := src.State(bl.Tips[0])
	if err != nil {
		return r, fmt.Errorf("pre-state %s: %w", bl.Tips[0], err)
	}
	post, err := src.State(blid)
	if err != nil {
		return r, fmt.Errorf("post-state: %w", err)
	}
	preB, err := pre.GetTree(config.BALANCE_TREE)
	if err != nil {
		return r, err
	}
	postB, err := post.GetTree(config.BALANCE_TREE)
	if err != nil {
		return r, err
	}

	// 1. the public deltas of the block's transactions
	sumC, sumD := zeroPoint(), zeroPoint()
	// r23c: the same deltas per account. A ring member is named by a key-hash prefix (Publickeylist_pointers), which
	// consensus resolves on the balance tree it executes on (transaction_execute.go process_transaction) and panics
	// when it cannot. A graviton prefix lookup returns the one leaf the prefix leads to or nothing (vendor graviton
	// special.go GetKeyValue), keys are never deleted, and a registration earlier in the block can only make a prefix
	// lead to an inner node (lookup fails, consensus panics, the block is never committed): so for a committed block
	// the pre-state resolves every pointer to the key consensus credited.
	exp := map[string]*acctDelta{}
	resolved := true
	regs := map[string]bool{}
	scids := map[string]bool{}
	var deposits []uint64
	var depositTotal uint64
	for _, h := range bl.Tx_hashes {
		tx, e := src.Tx(h)
		if e != nil {
			return r, fmt.Errorf("tx %s: %w", h, e)
		}
		switch tx.TransactionType {
		case transaction.REGISTRATION:
			regs[string(tx.MinerAddress[:])] = true
			r.Registrations++
			continue
		case transaction.NORMAL, transaction.BURN_TX, transaction.SC_TX:
		default:
			r.alert("tx %s of type %s in a block (consensus executes only registration/normal/burn/sc)", h, tx.TransactionType)
			continue
		}
		f := tx.Fees()
		if r.Fees+f < r.Fees {
			r.FeesOverflow = true
		}
		r.Fees += f
		if f > r.MaxTxFee {
			r.MaxTxFee = f
		}
		// r23b: plaintext burns are the DERO payloads' BurnValue of a transaction that is not an SC call (a BURN_TX's
		// tx.Value is never serialised: transaction.go writes Value only for PREMINE and SC_TX, so it was always 0 here)
		isCall := tx.TransactionType == transaction.SC_TX && len(tx.SCDATA) > 0 && tx.SCDATA.Has(rpc.SCACTION, rpc.DataUint64)
		if !isCall {
			for t := range tx.Payloads {
				if bv := tx.Payloads[t].BurnValue; tx.Payloads[t].SCID.IsZero() && bv > 0 {
					if r.Burns+bv < r.Burns {
						r.alert("burns overflow uint64")
					}
					r.Burns += bv
					if bv > r.BurnTxValue {
						r.BurnTxValue = bv
					}
				}
			}
		}
		for t := range tx.Payloads {
			if !tx.Payloads[t].SCID.IsZero() { // token payloads change SC token trees, not the balance tree
				continue
			}
			st := &tx.Payloads[t].Statement
			if uint64(len(st.C)) < st.RingSize || st.D == nil {
				return r, fmt.Errorf("tx %s payload %d: %d commitments for ring %d", h, t, len(st.C), st.RingSize)
			}
			for i := uint64(0); i < st.RingSize; i++ {
				sumC.Add(sumC, st.C[i])
			}
			sumD.Add(sumD, new(bn256.G1).ScalarMult(st.D, new(big.Int).SetUint64(st.RingSize)))
			if bpp := uint64(st.Bytes_per_publickey); resolved && bpp > 0 && uint64(len(st.Publickeylist_pointers)) >= st.RingSize*bpp {
				for i := uint64(0); i < st.RingSize; i++ {
					ptr := st.Publickeylist_pointers[i*bpp : (i+1)*bpp]
					_, k, _, e := preB.GetKeyValueFromHash(ptr)
					if e != nil {
						resolved = false
						break
					}
					d := exp[string(k)]
					if d == nil {
						d = newAcctDelta()
						exp[string(k)] = d
					}
					d.L.Add(d.L, st.C[i])
					d.R.Add(d.R, st.D)
				}
			} else {
				resolved = false
			}
		}
		if isCall {
			r.SCCalls++
			var d uint64
			for _, pl := range tx.Payloads { // incoming_value[SCID] = BurnValue: the last DERO payload wins
				if pl.SCID.IsZero() {
					// r23c: an earlier DERO payload's BurnValue is overwritten in incoming_value, so it reaches no SC and
					// is destroyed: a plaintext burn (the aggregate Left check already accounts for it through C)
					if d > 0 {
						if r.Burns+d < r.Burns {
							r.alert("burns overflow uint64")
						}
						r.Burns += d
					}
					d = pl.BurnValue
				}
			}
			scid := h
			if rpc.SC_ACTION(tx.SCDATA.Value(rpc.SCACTION, rpc.DataUint64).(uint64)) == rpc.SC_CALL && tx.SCDATA.Has(rpc.SCID, rpc.DataHash) {
				scid = tx.SCDATA.Value(rpc.SCID, rpc.DataHash).(crypto.Hash)
			}
			scids[string(scid[:])] = true
			if d > 0 {
				deposits = append(deposits, d)
				if depositTotal+d < depositTotal {
					r.alert("SC deposits overflow uint64")
				}
				depositTotal += d
				if d > r.MaxPlainFlow {
					r.MaxPlainFlow = d
				}
			}
		}
	}
	r.SCDeposits = depositTotal
	if r.BurnTxValue > r.MaxPlainFlow {
		r.MaxPlainFlow = r.BurnTxValue
	}
	if r.MaxTxFee > r.MaxPlainFlow { // value created inside encrypted amounts can only surface as plaintext via fees,
		r.MaxPlainFlow = r.MaxTxFee // SC deposits or SC payouts: the notable-flow proxy watches all three
	}
	if r.FeesOverflow {
		r.alert("sum of fees overflows uint64 (consensus wraps it)")
	}

	// 2. the coinbase split
	finals := 0
	for _, mbl := range bl.MiniBlocks {
		if mbl.Final {
			finals++
		}
	}
	r.Miniblocks, r.Finals = len(bl.MiniBlocks), finals
	if bl.Height >= SingleFinalFromHeight && (len(bl.MiniBlocks) != MiniblocksPerBlock || finals != 1) {
		r.alert("coinbase shape %d miniblocks with %d final, consensus allows only %d with exactly 1 from height %d", len(bl.MiniBlocks), finals, MiniblocksPerBlock, SingleFinalFromHeight)
	}
	r.BaseReward = BlockReward(bl.Height)
	sp := SplitReward(r.BaseReward, r.Fees, len(bl.MiniBlocks), finals)
	r.Paid = sp.Paid
	if finals != 1 {
		r.note("%d final miniblocks: coinbase pays %d of %d", finals, sp.Paid, sp.Full)
	}
	payees := map[string]uint64{}
	var order []string
	credit := func(k string, v uint64) {
		if _, ok := payees[k]; !ok {
			order = append(order, k)
		}
		payees[k] += v
	}
	credit(string(bl.Miner_TX.MinerAddress[:]), sp.Share+sp.Leftover)
	for _, mbl := range bl.MiniBlocks {
		if mbl.Final {
			continue
		}
		_, k, _, e := postB.GetKeyValueFromHash(mbl.KeyHash[:16])
		if e != nil {
			r.alert("miniblock miner %x is not a registered account", mbl.KeyHash[:16])
			continue
		}
		credit(string(k), sp.Share)
	}

	// 3. registrations: bonus credited by consensus at creation
	var regBonus uint64
	if !p.Mainnet || p.Simulator {
		regBonus += TestnetRegistration
	}
	if p.Mainnet && bl.Height < ClaimBonusEndHeight {
		regBonus += ClaimBonusPerAccount
	}

	// 4. what the block actually changed
	preVals, postVals := map[string][]byte{}, map[string][]byte{}
	var keys []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if err = graviton.Diff(preB, postB,
		func(k, v []byte) { preVals[string(k)] = cp(v); add(string(k)) },
		func(k, v []byte) { postVals[string(k)] = cp(v); add(string(k)) },
		func(k, v []byte) { postVals[string(k)] = cp(v); add(string(k)) }); err != nil {
		return r, fmt.Errorf("balance diff: %w", err)
	}
	dL, dR := zeroPoint(), zeroPoint()
	var regBonusTotal uint64
	act := map[string]*acctDelta{} // r23c: what the block did to each account (an inserted one: beyond its registration)
	replaced := map[string]bool{}  // pre-HF3 re-registrations: the balance was replaced, not added to
	inserted := map[string]bool{}
	for _, k := range keys {
		pv, inPre := preVals[k]
		nv, inPost := postVals[k]
		if inPost && !inPre { // modified (or a leaf moved by the diff walker): fetch the old value
			if b, e := preB.Get([]byte(k)); e == nil {
				pv, inPre = cp(b), true
			}
		}
		switch {
		case inPre && !inPost:
			if _, e := postB.Get([]byte(k)); e != nil {
				r.alert("account %x deleted from the balance tree", k)
			}
			continue
		case !inPre && inPost:
			r.Inserted++
			if !regs[k] {
				r.alert("account %x created without a registration in this block", k)
				continue
			}
			var y bn256.G1
			if e := y.DecodeCompressed([]byte(k)); e != nil {
				r.alert("registered key %x does not decode", k)
				continue
			}
			nb, e := decodeBalance(nv)
			if e != nil {
				r.alert("account %x: %v", k, e)
				continue
			}
			l := new(bn256.G1).Add(nb.Left, new(bn256.G1).Neg(&y))
			rr := new(bn256.G1).Add(nb.Right, new(bn256.G1).Neg(crypto.ElGamal_BASE_G))
			dL.Add(dL, l)
			dR.Add(dR, rr)
			regBonusTotal += regBonus
			act[k] = &acctDelta{L: new(bn256.G1).Add(l, new(bn256.G1).Neg(mulBaseU(regBonus))), R: rr}
			inserted[k] = true
		default:
			r.Changed++
			a, e1 := decodeBalance(pv)
			b, e2 := decodeBalance(nv)
			if e1 != nil || e2 != nil {
				r.alert("account %x: undecodable balance", k)
				continue
			}
			if regs[k] && p.HF3Height > 0 && bl.Height < p.HF3Height {
				// r23 merge: consensus-legal before HF3: the old balance is replaced (value destroyed, never created),
				// so the account is accounted as a fresh registration and the event is a note, not an alert
				var y bn256.G1
				if e := y.DecodeCompressed([]byte(k)); e != nil {
					r.alert("registered key %x does not decode", k)
					continue
				}
				r.note("pre-HF3 re-registration of account %x replaced its balance (consensus-legal below height %d)", k, p.HF3Height)
				dL.Add(dL, new(bn256.G1).Add(b.Left, new(bn256.G1).Neg(&y)))
				dR.Add(dR, new(bn256.G1).Add(b.Right, new(bn256.G1).Neg(crypto.ElGamal_BASE_G)))
				regBonusTotal += regBonus
				replaced[k] = true
				continue
			}
			l := new(bn256.G1).Add(b.Left, new(bn256.G1).Neg(a.Left))
			rr := new(bn256.G1).Add(b.Right, new(bn256.G1).Neg(a.Right))
			dL.Add(dL, l)
			dR.Add(dR, rr)
			act[k] = &acctDelta{L: l, R: rr}
			if regs[k] {
				r.alert("registration of the already-registered account %x reset its balance", k)
			}
		}
	}

	// 5. plaintext SC accounting
	if preM, e := pre.GetTree(config.SC_META); e == nil {
		if postM, e := post.GetTree(config.SC_META); e == nil {
			h := func(k, v []byte) {
				if len(k) == 32 {
					scids[string(k)] = true
				}
			}
			if e := graviton.Diff(preM, postM, h, h, h); e != nil {
				return r, fmt.Errorf("sc meta diff: %w", e)
			}
		}
	}
	scDelta := new(big.Int)
	for s := range scids {
		scDelta.Add(scDelta, new(big.Int).SetUint64(scHeldDERO(post, []byte(s))))
		scDelta.Sub(scDelta, new(big.Int).SetUint64(scHeldDERO(pre, []byte(s))))
	}
	r.SCDelta = scDelta.String()
	if scDelta.Cmp(new(big.Int).SetUint64(depositTotal)) > 0 {
		r.alert("SC-held plaintext DERO grew by %s, more than the %d deposited in this block", scDelta, depositTotal)
	}

	// 6. the checks
	if !samePoint(dR, sumD) {
		r.alert("Right components moved by something other than the published D values")
	}
	expected := new(bn256.G1).Add(sumC, mulBase(new(big.Int).Add(new(big.Int).SetUint64(sp.Paid), new(big.Int).SetUint64(regBonusTotal))))
	residual := new(bn256.G1).Add(dL, new(bn256.G1).Neg(expected)) // must be P*G
	r.Verdict = VerdictOK
	if r.SCCalls == 0 { // no contract ran: every plaintext movement is pinned exactly
		if scDelta.Sign() != 0 {
			r.alert("SC-held plaintext DERO changed by %s in a block without an SC call", scDelta)
		}
		if !samePoint(residual, zeroPoint()) {
			r.alert("Left components moved by plaintext value not explained by transfers, coinbase (%d) or registrations", sp.Paid)
		}
	} else {
		max := p.MaxSCSubset
		if max <= 0 {
			max = 12
		}
		if len(deposits) > max {
			r.Verdict = VerdictSCUnexplained
			r.note("%d SC deposits: payout candidates not enumerated", len(deposits))
		} else if P, ok := matchPayout(residual, deposits, scDelta); ok {
			r.SCPayout = P
			r.Verdict = VerdictOKSC
			if P > r.MaxPlainFlow {
				r.MaxPlainFlow = P
			}
		} else {
			r.Verdict = VerdictSCUnexplained
			r.note("Left residual matches no SC payout candidate (an SC payout that panicked part-way burns the rest; dvm ProcessExternal)")
		}
	}

	// 6b. r23c per-account check: the aggregate checks above prove the block created no plaintext value; this one
	// proves it moved none between accounts either (e.g. a miniblock share credited to the wrong key, or one ring
	// member's commitment applied to another), which an exact sum cannot see.
	exact := map[string]bool{}
	mulMemo := map[uint64]*bn256.G1{} // v*G per distinct payee amount: most payees get the same share (read-only use)
	mul := func(v uint64) *bn256.G1 {
		if g, ok := mulMemo[v]; ok {
			return g
		}
		g := mulBaseU(v)
		mulMemo[v] = g
		return g
	}
	if !resolved {
		r.PerAccount = "unresolved"
		r.note("per-account check skipped: a ring pointer did not resolve to one key")
	} else {
		r.PerAccount = "exact"
		if r.SCCalls > 0 {
			r.PerAccount = "right_only"
		}
		all := make([]string, 0, len(act)+len(exp)+len(payees))
		for k := range act {
			all = append(all, k)
		}
		for k := range exp {
			if act[k] == nil {
				all = append(all, k)
			}
		}
		for k := range payees {
			if act[k] == nil && exp[k] == nil {
				all = append(all, k)
			}
		}
		sort.Strings(all)
		for _, k := range all {
			if replaced[k] {
				continue
			}
			a, e := act[k], exp[k]
			if a == nil {
				a = newAcctDelta()
			}
			if e == nil {
				e = newAcctDelta()
			}
			wantL := e.L
			if v := payees[k]; v > 0 {
				wantL = new(bn256.G1).Add(e.L, mul(v))
			}
			okR := samePoint(a.R, e.R)
			okL := samePoint(a.L, wantL)
			if !okR {
				r.alert("account %x: Right component moved by something other than the D values of its own rings", k)
			}
			if r.SCCalls == 0 && !okL {
				r.alert("account %x: Left component moved by something other than its own ring commitments, coinbase share and registration", k)
			}
			if okR && okL {
				exact[k] = true
				r.AccountsExact++
			}
		}
	}

	// 7. per-payee: who got exactly their share and nothing else
	for _, k := range order {
		py := Payee{Key: fmt.Sprintf("%x", k), Amount: payees[k], Explained: exact[k]}
		if d := act[k]; d != nil && !inserted[k] { // r23c: the diff loop already decoded this account's change
			if samePoint(d.R, zeroPoint()) && samePoint(d.L, mul(py.Amount)) {
				py.Verified, py.Explained = true, true
			}
			r.Payees = append(r.Payees, py)
			continue
		}
		if !replaced[k] { // unchanged, or created by this block: not Verified, as the Round 23 code found
			r.Payees = append(r.Payees, py)
			continue
		}
		pv, e1 := preB.Get([]byte(k))
		nv, e2 := postB.Get([]byte(k))
		if e1 == nil && e2 == nil {
			a, e1 := decodeBalance(pv)
			b, e2 := decodeBalance(nv)
			if e1 == nil && e2 == nil && samePoint(a.Right, b.Right) &&
				samePoint(new(bn256.G1).Add(b.Left, new(bn256.G1).Neg(a.Left)), mul(py.Amount)) {
				py.Verified = true
				py.Explained = true
			}
		}
		r.Payees = append(r.Payees, py)
	}
	if len(r.Alerts) > 0 {
		r.Verdict = VerdictAlert
	}
	return r, nil
}

// matchPayout finds P = sum(selected deposits) - scDelta >= 0 with residual == P*G, trying every subset of deposits
// (each SC call's deposit is either credited/refunded or destroyed). Point additions only: 2^m adds for m deposits.
func matchPayout(residual *bn256.G1, deposits []uint64, scDelta *big.Int) (uint64, bool) {
	m := len(deposits)
	dp := make([]*bn256.G1, m)
	for i, d := range deposits {
		dp[i] = mulBaseU(d)
	}
	cur := mulBase(new(big.Int).Neg(scDelta)) // subset {} : P = -scDelta
	sum := new(big.Int).Neg(scDelta)
	in := make([]bool, m)
	for g := 0; ; g++ {
		if sum.Sign() >= 0 && sum.IsUint64() && samePoint(cur, residual) {
			return sum.Uint64(), true
		}
		if g+1 >= 1<<uint(m) {
			return 0, false
		}
		// Gray code: flip the lowest set bit of g+1
		i := 0
		for x := g + 1; x&1 == 0; x >>= 1 {
			i++
		}
		in[i] = !in[i]
		if in[i] {
			cur.Add(cur, dp[i])
			sum.Add(sum, new(big.Int).SetUint64(deposits[i]))
		} else {
			cur.Add(cur, new(bn256.G1).Neg(dp[i]))
			sum.Sub(sum, new(big.Int).SetUint64(deposits[i]))
		}
	}
}
