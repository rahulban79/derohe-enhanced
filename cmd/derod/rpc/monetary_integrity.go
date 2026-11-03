// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

// DERO.GetMonetaryIntegrity (Round 23b, rpcws): one read-only answer a third party can check a node's monetary
// claims against, without trusting the operator's word.
//
//   - emission: the cumulative totals of the per-block emission auditor (emission_audit.go), without its block lists
//   - hf3_exemption: facts about the consensus table of 75 historical txids whose proofs are not re-verified
//     (blockchain/hardfork_fixes.go), computed from the table this binary was built with: entry count, height span,
//     parity flags, the height after which no block can carry any of them, and a SHA-256 digest over a canonical
//     line per entry so two parties can tell whether they run the same table
//   - finality: the reorg monitor (reorg_events.go), which checks the r23 final_height rule against every replacement
//   - limits: what none of this can prove
//
// Cost: O(1) after the first call (the table facts are computed once, 75 entries); no store read.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/globals"
)

type HF3Exemption_Entry struct {
	TxID     string `json:"txid"`
	BlTips   string `json:"bl_tips"`
	Height   uint64 `json:"height"`
	TxParity bool   `json:"tx_parity"`
	Parity   bool   `json:"parity"`
}

type HF3Exemption_Facts struct {
	Entries      int    `json:"entries"`
	MinHeight    uint64 `json:"min_height"`
	MaxHeight    uint64 `json:"max_height"`
	HF3Height    int64  `json:"hf3_height"`
	AllBelowHF3  bool   `json:"all_below_hf3"` // every entry's tx.Height < HF3: the TXID cache key applies to none built after it
	TxParityTrue int    `json:"tx_parity_true"`
	ParityTrue   int    `json:"parity_true"` // the field execution swaps in (transaction_execute.go:244); the table never sets it
	// a block at height h may carry a tx only if h - tx.Height < TX_VALIDITY_HEIGHT (blockchain.go:786), so no block
	// at or above max_height + TX_VALIDITY_HEIGHT can include any entry
	LastIncludableHeight uint64               `json:"last_includable_height"`
	WindowClosed         bool                 `json:"window_closed"` // chain height is past last_includable_height
	ChainHeight          int64                `json:"chain_height"`
	CacheKeyRule         string               `json:"cache_key_rule"`
	Digest               string               `json:"digest"` // sha256 over the sorted lines of digest_format, hex
	DigestFormat         string               `json:"digest_format"`
	List                 []HF3Exemption_Entry `json:"list,omitempty"`
}

type MonetaryIntegrity_Emission struct {
	Enabled            bool              `json:"enabled"`
	Status             string            `json:"status"`
	Audited            uint64            `json:"audited"`
	Verdicts           map[string]uint64 `json:"verdicts"`
	Alerts             uint64            `json:"alerts"`
	SegmentFrom        uint64            `json:"segment_from"`
	SegmentTo          uint64            `json:"segment_to"`
	VerifiedHeights    uint64            `json:"verified_heights"`
	UnverifiedHeights  uint64            `json:"unverified_heights"`
	ObservedEmission   uint64            `json:"observed_emission"`
	FormulaEmission    uint64            `json:"formula_emission"`
	EmissionConsistent bool              `json:"emission_consistent"`
	FormulaSupply      uint64            `json:"formula_supply"`
	FeesRedistributed  uint64            `json:"fees_redistributed"`
	SCDeposits         uint64            `json:"sc_deposits"`
	SCPayouts          uint64            `json:"sc_payouts"`
	Gaps               uint64            `json:"gaps"`
	Reorgs             uint64            `json:"reorgs"`
	// r23c: the audited emission proper and the payee/burn totals were in GetEmissionAudit but missing here, so a
	// third party reading only this answer could not compare issued with formula emission or see burns
	IssuedEmission       uint64 `json:"issued_emission"`
	IssuedMatchesFormula bool   `json:"issued_matches_formula"`
	Burns                uint64 `json:"burns"`
	Payees               uint64 `json:"payees"`
	PayeesVerified       uint64 `json:"payees_verified"`
	PayeesExplained      uint64 `json:"payees_explained"`
	DeepRewinds          uint64 `json:"deep_rewinds"`
}

type GetMonetaryIntegrity_Params struct {
	List bool `json:"list"` // include the 75 table entries
}

type GetMonetaryIntegrity_Result struct {
	Emission     MonetaryIntegrity_Emission `json:"emission"`
	HF3Exemption HF3Exemption_Facts         `json:"hf3_exemption"`
	Finality     Reorg_Stats                `json:"finality"`
	Limits       []string                   `json:"limits"`
	Status       string                     `json:"status"`
}

const HF3_DIGEST_FORMAT = "%s %s %d %t %t\n" // txid bl_tips height tx_parity parity; lines sorted by txid

var monetary_limits = []string{
	"emission: proves only that no plaintext value moved outside the published (C, D) deltas, the formula coinbase, registrations and SC accounting; value created inside encrypted transfer amounts (the disclosed range-proof soundness class) is invisible to every node",
	"emission: covers only the segment this node audited since it started (segment_from..segment_to), not the chain from genesis",
	"hf3_exemption: the digest says which table a binary carries, not that its entries were honest; the entries' proofs are not re-verified by any node",
	"finality: a monitor of this node's view; final_violations counts replacements below the announced final height and must stay 0",
}

func hf3_facts(table map[string]*blockchain.HF3_Tx_Data, hf3 int64) HF3Exemption_Facts {
	f := HF3Exemption_Facts{HF3Height: hf3, AllBelowHF3: true, DigestFormat: HF3_DIGEST_FORMAT,
		CacheKeyRule: "proof verdict cached by TXID only when tx.Height < hf3_height, else by Keccak256 of the full serialized tx including proofs (transaction_verify.go)"}
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for i, k := range keys {
		e := table[k]
		if e == nil {
			continue
		}
		f.Entries++
		if i == 0 || e.Height < f.MinHeight {
			f.MinHeight = e.Height
		}
		if e.Height > f.MaxHeight {
			f.MaxHeight = e.Height
		}
		if hf3 <= 0 || e.Height >= uint64(hf3) {
			f.AllBelowHF3 = false
		}
		if e.Tx_Parity {
			f.TxParityTrue++
		}
		if e.Parity {
			f.ParityTrue++
		}
		fmt.Fprintf(h, HF3_DIGEST_FORMAT, k, e.Bl_Tips, e.Height, e.Tx_Parity, e.Parity)
		f.List = append(f.List, HF3Exemption_Entry{TxID: k, BlTips: e.Bl_Tips, Height: e.Height, TxParity: e.Tx_Parity, Parity: e.Parity})
	}
	if f.Entries > 0 {
		f.LastIncludableHeight = f.MaxHeight + blockchain.TX_VALIDITY_HEIGHT - 1
	}
	f.Digest = hex.EncodeToString(h.Sum(nil))
	return f
}

var hf3_facts_once sync.Once
var hf3_facts_cached HF3Exemption_Facts

func emission_summary(r GetEmissionAudit_Result) MonetaryIntegrity_Emission {
	return MonetaryIntegrity_Emission{Enabled: r.Enabled, Status: r.Status, Audited: r.Audited, Verdicts: r.Verdicts,
		Alerts: r.Alerts, SegmentFrom: r.SegmentFrom, SegmentTo: r.SegmentTo, VerifiedHeights: r.VerifiedHeights,
		UnverifiedHeights: r.UnverifiedHeights, ObservedEmission: r.ObservedEmission, FormulaEmission: r.FormulaEmission,
		EmissionConsistent: r.EmissionConsistent, FormulaSupply: r.FormulaSupply, FeesRedistributed: r.FeesRedistributed,
		SCDeposits: r.SCDeposits, SCPayouts: r.SCPayouts, Gaps: r.Gaps, Reorgs: r.Reorgs,
		IssuedEmission: r.IssuedEmission, IssuedMatchesFormula: r.IssuedMatchesFormula, Burns: r.Burns, Payees: r.Payees,
		PayeesVerified: r.PayeesVerified, PayeesExplained: r.PayeesExplained, DeepRewinds: r.DeepRewinds}
}

// monetary_integrity assembles the answer; chain_height is the node's height now (-1 unknown).
func monetary_integrity(p GetMonetaryIntegrity_Params, em GetEmissionAudit_Result, facts HF3Exemption_Facts, fin Reorg_Stats, chain_height int64) GetMonetaryIntegrity_Result {
	return monetary_integrity_of(p, emission_summary(em), facts, fin, chain_height)
}

// monetary_integrity_of takes the emission totals directly (r23c: GetMonetaryIntegrity reads emission_state.summary(),
// which copies no report lists).
func monetary_integrity_of(p GetMonetaryIntegrity_Params, em MonetaryIntegrity_Emission, facts HF3Exemption_Facts, fin Reorg_Stats, chain_height int64) GetMonetaryIntegrity_Result {
	f := facts
	if !p.List {
		f.List = nil
	} else {
		f.List = append([]HF3Exemption_Entry(nil), facts.List...)
	}
	f.ChainHeight = chain_height
	f.WindowClosed = f.Entries > 0 && chain_height > int64(f.LastIncludableHeight)
	res := GetMonetaryIntegrity_Result{Emission: em, HF3Exemption: f, Finality: fin,
		Limits: append([]string(nil), monetary_limits...), Status: "OK"}
	switch {
	case em.Alerts > 0 || fin.Violations > 0:
		res.Status = "ALERT"
	case f.HF3Height > 0 && f.Entries > 0 && !f.AllBelowHF3:
		res.Status = "ALERT" // an entry at or above HF3 would be built after it yet skip proofs: must never ship
	}
	return res
}

func GetMonetaryIntegrity(ctx context.Context, p GetMonetaryIntegrity_Params) (result GetMonetaryIntegrity_Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace r %s", r)
		}
	}()
	hf3_facts_once.Do(func() { hf3_facts_cached = hf3_facts(blockchain.HF3_Affected_Txs, globals.Config.MAJOR_HF3_HEIGHT) })
	return monetary_integrity_of(p, emission_state.summary(), hf3_facts_cached, reorg_state.stats(), chain.Get_Height()), nil
}
