// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package emission

// HF3 forensic report (Round 23b): for each of the 75 transactions blockchain/hardfork_fixes.go exempts, state what
// a node can establish from public data and what it cannot. Read-only and defensive: it reads stored bodies and
// blocks, recomputes the TXID, and reports plaintext fields; it never builds or alters a transaction.
//
// What a node CAN state: the table's own facts (height, the tips the nonce bypass is pinned to, Tx_Parity, and the
// Parity the sync path derives from them, p2p/chain_sync.go:397), and, when a body is in a store: that it hashes to
// its TXID, its type, reference height and BLID, plaintext fees and burns, ring sizes, the proof's parity bit, the
// Keccak256 of the full body (so different bodies of one TXID are told apart), which block(s) carry it and whether
// one of them has the table's tips.
// What it CANNOT: the amounts (ElGamal ciphertexts under the ring members' keys), which ring member sent, and, for
// a duplicate, the body a store overwrote (storefs.go keeps one file per TXID): a node that saw only one body
// cannot know the other.

import (
	"fmt"
	"sort"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// HF3FalseParity are the 8 entries listed under "no duplicates, but false parity" in blockchain/hardfork_fixes.go;
// the other 67 are listed under "duplicates" (TestHF3ClassesMatchTable pins both counts against the table).
var HF3FalseParity = map[string]bool{
	"aa0faf67a2856ee30ed4e275c1079d1572b1bcb03d4a9ca682bd825e11d81a43": true,
	"37df76020e1823aade3b130fe53571b93d6c5c34e35d1d522c7c5cd449e84370": true,
	"09d0260ea572349c4869b58cb59638348e1ed4bc57c511619d36fd1fd484211f": true,
	"6d882984bad971d4becb9ac15ecd8cb3e3e0ee783d6d6c1d1ce95df12625732f": true,
	"0511f2b2a8ee9408b216cb1db6129937119fb76e99a1dcd1544f49462da58a38": true,
	"414f79b8ff3c862eaa5727c6591542218881c751ba4fe052c9aaeeec0cfedfcd": true,
	"0045a6d4c51a8578b6c97f2b376415653583505f21032eb6a808cd1643a300a7": true,
	"60bfbd73a60060d6502b13871f55a47ebfb732bcb8f5685602688f7eae36fa3e": true,
}

type HF3Entry struct {
	TXID     string
	BlTips   string
	Height   uint64
	TxParity bool
}

// Body is one stored copy of a transaction, with where it was read.
type Body struct {
	Source string
	Bytes  []byte
}

type BlockRef struct {
	Source    string   `json:"source"`
	Topo      int64    `json:"topo"`
	Height    uint64   `json:"height"`
	BLID      string   `json:"blid"`
	Tips      []string `json:"tips"`
	TableTips bool     `json:"has_table_tips"` // this block's tips are the entry's Bl_Tips (the one the bypass is pinned to)
}

type HF3BodyFacts struct {
	Sources      []string `json:"sources"`
	BodyKeccak   string   `json:"body_keccak256"`
	Size         int      `json:"size"`
	Canonical    bool     `json:"canonical"` // Serialize(Deserialize(body)) == body
	Type         string   `json:"type"`
	TxHeight     uint64   `json:"tx_height"`
	BLID         string   `json:"blid"`
	Fees         uint64   `json:"fees"`
	Burn         uint64   `json:"burn"` // plaintext BurnValue of the DERO payloads (deposit when an SC call)
	SCCall       bool     `json:"sc_call"`
	Payloads     int      `json:"payloads"`
	TokenPayload int      `json:"token_payloads"`
	RingSizes    []uint64 `json:"ring_sizes"`
	ProofParity  []bool   `json:"proof_parity"` // per payload, Proof.Parity() of this body
}

type HF3Record struct {
	TXID            string `json:"txid"`
	Class           string `json:"class"` // duplicate | false_parity
	TableHeight     uint64 `json:"table_height"`
	TableBlTips     string `json:"table_bl_tips"`
	TxParity        bool   `json:"tx_parity"`
	ParityAbove     bool   `json:"parity_for_blocks_above_table_height"` // chain_sync.go:397: (bl.Height > Height) == Tx_Parity
	ParityAtOrBelow bool   `json:"parity_for_blocks_at_or_below_table_height"`

	InStore        bool           `json:"in_store"`
	BodiesSeen     int            `json:"bodies_seen"`
	DistinctBodies int            `json:"distinct_bodies"`
	BodiesDiffer   bool           `json:"bodies_differ"`
	ForeignBodies  int            `json:"foreign_bodies"` // stored under this TXID but hashing to another (or undecodable)
	Bodies         []HF3BodyFacts `json:"bodies,omitempty"`

	TxHeightMatchesTable bool `json:"tx_height_matches_table"`

	Blocks     []BlockRef `json:"blocks,omitempty"`
	TableBlock string     `json:"table_block,omitempty"` // the block whose tips are Bl_Tips, when found
	// at the table block, the Parity execution swaps in (transaction_execute.go:244 with chain_sync.go:397), and
	// whether it equals the held body's own Proof.Parity() for every payload (nil: no table block or no body)
	ExecParity             *bool  `json:"exec_parity_at_table_block,omitempty"`
	ExecParityMatchesProof *bool  `json:"exec_parity_matches_proof,omitempty"`
	BlocksSearched         string `json:"blocks_searched"`

	Cannot []string `json:"cannot"`
}

var hf3Cannot = []string{
	"amounts: each payload's C[i] and D are ElGamal ciphertexts under the ring members' keys",
	"the sender: any ring member could have signed",
	"the overwritten body of a duplicate: a store keeps one file per TXID (blockchain/storefs.go)",
	"the value effect of executing a TXID twice: it is the encrypted delta applied again",
}

// HF3Forensic builds the record of one entry from the bodies and blocks the caller found. Bodies that are not
// this TXID (undecodable, or hashing elsewhere) are counted as foreign and never described.
func HF3Forensic(e HF3Entry, bodies []Body, blocks []BlockRef, searched string) HF3Record {
	r := HF3Record{TXID: e.TXID, Class: "duplicate", TableHeight: e.Height, TableBlTips: e.BlTips, TxParity: e.TxParity,
		ParityAbove: e.TxParity, ParityAtOrBelow: !e.TxParity, BlocksSearched: searched}
	if HF3FalseParity[e.TXID] {
		r.Class = "false_parity"
	}
	byHash := map[string]int{}
	for _, b := range bodies {
		tx, err := DecodeTx(b.Bytes)
		if err != nil || tx.GetHash().String() != e.TXID {
			r.ForeignBodies++
			continue
		}
		r.BodiesSeen++
		k := crypto.Keccak256(b.Bytes).String()
		if i, ok := byHash[k]; ok {
			r.Bodies[i].Sources = append(r.Bodies[i].Sources, b.Source)
			continue
		}
		byHash[k] = len(r.Bodies)
		r.Bodies = append(r.Bodies, bodyFacts(b, k, tx))
	}
	r.InStore = r.BodiesSeen > 0
	r.DistinctBodies = len(r.Bodies)
	r.BodiesDiffer = r.DistinctBodies > 1
	if len(r.Bodies) > 0 {
		r.TxHeightMatchesTable = r.Bodies[0].TxHeight == e.Height
	}
	for _, b := range blocks {
		b.TableTips = len(b.Tips) > 0 && joinTips(b.Tips) == e.BlTips
		if b.TableTips {
			r.TableBlock = b.BLID
			p := (b.Height > e.Height) == e.TxParity
			r.ExecParity = &p
			if len(r.Bodies) > 0 && len(r.Bodies[0].ProofParity) > 0 {
				m := true
				for _, pp := range r.Bodies[0].ProofParity {
					m = m && pp == p
				}
				r.ExecParityMatchesProof = &m
			}
		}
		r.Blocks = append(r.Blocks, b)
	}
	sort.Slice(r.Blocks, func(i, j int) bool { return r.Blocks[i].Topo < r.Blocks[j].Topo })
	r.Cannot = hf3Cannot
	return r
}

// joinTips renders tips the way transaction_verify.go:236 builds the bypass key (fmt %s of the tips string).
func joinTips(t []string) string {
	s := ""
	for _, x := range t {
		s += x
	}
	return s
}

func bodyFacts(b Body, k string, tx *transaction.Transaction) HF3BodyFacts {
	f := HF3BodyFacts{Sources: []string{b.Source}, BodyKeccak: k, Size: len(b.Bytes), Type: tx.TransactionType.String(),
		TxHeight: tx.Height, BLID: fmt.Sprintf("%x", tx.BLID[:]), Fees: tx.Fees(), Payloads: len(tx.Payloads)}
	f.Canonical = string(tx.Serialize()) == string(b.Bytes)
	f.SCCall = tx.TransactionType == transaction.SC_TX
	for _, p := range tx.Payloads {
		if !p.SCID.IsZero() {
			f.TokenPayload++
		} else {
			f.Burn = sat(f.Burn, p.BurnValue)
		}
		f.RingSizes = append(f.RingSizes, p.Statement.RingSize)
		if p.Proof != nil {
			f.ProofParity = append(f.ProofParity, p.Proof.Parity())
		}
	}
	return f
}

type HF3Summary struct {
	Entries          int    `json:"entries"`
	Duplicates       int    `json:"duplicates"`
	FalseParity      int    `json:"false_parity"`
	HeightFrom       uint64 `json:"height_from"`
	HeightTo         uint64 `json:"height_to"`
	InStore          int    `json:"in_store"`
	BodiesDiffer     int    `json:"bodies_differ"`
	ForeignBodies    int    `json:"foreign_bodies"`
	BlocksFound      int    `json:"blocks_found"`
	TableBlocksFound int    `json:"table_blocks_found"`
	MultiBlockTxids  int    `json:"txids_in_more_than_one_block"`
	FeesKnown        uint64 `json:"fees_known"` // gross plaintext of the bodies we hold
	BurnKnown        uint64 `json:"burn_known"`
	Limit            string `json:"limit"`
}

func SummarizeHF3(rs []HF3Record) (s HF3Summary) {
	s.Entries = len(rs)
	for i, r := range rs {
		if r.Class == "false_parity" {
			s.FalseParity++
		} else {
			s.Duplicates++
		}
		if i == 0 || r.TableHeight < s.HeightFrom {
			s.HeightFrom = r.TableHeight
		}
		if r.TableHeight > s.HeightTo {
			s.HeightTo = r.TableHeight
		}
		if r.InStore {
			s.InStore++
			s.FeesKnown = sat(s.FeesKnown, r.Bodies[0].Fees)
			s.BurnKnown = sat(s.BurnKnown, r.Bodies[0].Burn)
		}
		if r.BodiesDiffer {
			s.BodiesDiffer++
		}
		s.ForeignBodies += r.ForeignBodies
		s.BlocksFound += len(r.Blocks)
		if r.TableBlock != "" {
			s.TableBlocksFound++
		}
		if len(r.Blocks) > 1 {
			s.MultiBlockTxids++
		}
	}
	s.Limit = fmt.Sprintf("plaintext only: fees and burns of the %d bodies held; amounts are encrypted, so neither the gross value moved by these transactions nor the net value a double execution created is computable by any node", s.InStore)
	return s
}
