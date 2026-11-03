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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// r23b: plaintext burns are payload BurnValues outside SC calls; an SC deposit is not a burn.
func TestEmissionAuditCountsPayloadBurns(t *testing.T) {
	for i := 0; i < 3; i++ {
		w := newWorld(t)
		c := w.child("burns")
		c.transfer("t1", transaction.NORMAL, []acct{w.B, w.C}, 50, 777, nil)
		c.transfer("t2", transaction.NORMAL, []acct{w.C, w.M1}, 50, 23, nil)
		c.transfer("t3", transaction.SC_TX, []acct{w.B, w.M2}, 50, 400, scCall()) // a deposit, not a burn
		c.coinbase(0)
		c.setSC(5400)
		c.commit(c.sct)
		r := c.audit(mainnet)
		if r.Burns != 800 || r.BurnTxValue != 777 || r.SCDeposits != 400 {
			t.Fatalf("burns %d largest %d deposits %d, want 800/777/400 (verdict %s alerts %v)", r.Burns, r.BurnTxValue, r.SCDeposits, r.Verdict, r.Alerts)
		}
		if r.MaxPlainFlow < 777 {
			t.Fatalf("max plaintext flow %d does not see the 777 burn", r.MaxPlainFlow)
		}
	}
}

func okReport(h uint64) Report {
	return Report{Height: h, BaseReward: BlockReward(h), Paid: BlockReward(h) + 5, Fees: 5, Burns: 1, Verdict: VerdictOK}
}

func TestCumulativeContiguityAndConsistency(t *testing.T) {
	var c Cumulative
	for h := uint64(7600000); h < 7600010; h++ {
		c.Add(okReport(h), nil)
	}
	if !c.Consistent || !c.IssuedMatchesFormula || c.Verified != 10 || c.Observed != c.Formula || c.Issued != 10*BlockReward(7600000) || c.Burns != 10 || c.Fees != 50 {
		t.Fatalf("honest run: %+v", c)
	}
	u := okReport(7600010)
	u.Verdict = VerdictSCUnexplained
	c.Add(u, nil)
	if !c.Consistent || c.Unverified != 1 || c.Excused != BlockReward(7600010) {
		t.Fatalf("an unverified height is excused at its formula reward: %+v", c)
	}
	c.Add(okReport(7600013), nil) // two heights missing
	if c.Consistent || c.Gaps != 2 {
		t.Fatalf("a gap must break consistency: %+v", c)
	}
	var g Cumulative
	two := okReport(40)
	two.Paid -= 3075 // a historical block with two finals pays one share less
	g.Add(two, nil)
	if g.IssuedMatchesFormula || g.Issued != BlockReward(40)-3075 {
		t.Fatalf("issued must follow what was credited: %+v", g)
	}
	var d Cumulative
	d.Add(okReport(10), nil)
	d.Add(okReport(10), nil)
	if d.Consistent || d.RepeatedHeights != 1 {
		t.Fatalf("a repeated height must break consistency: %+v", d)
	}
	var e Cumulative
	a := okReport(20)
	a.Verdict = VerdictAlert
	e.Add(a, nil)
	if e.Consistent || e.Alerts != 1 || e.Verified != 0 {
		t.Fatalf("an alert must break consistency: %+v", e)
	}
	var f Cumulative
	f.Add(okReport(30), errors.New("missing tx"))
	if f.Verified != 0 || f.Unverified != 1 || f.Fees != 0 {
		t.Fatalf("an errored audit is unverified and contributes no flows: %+v", f)
	}
}

type fakeTopo []crypto.Hash

func (f fakeTopo) Record(i int64) (crypto.Hash, uint64, int64, error) {
	if i < 0 || i >= int64(len(f)) || f[i].IsZero() {
		return crypto.Hash{}, 0, 0, ErrUnavailable
	}
	return f[i], 1, i, nil
}

// prunedSource reports some blocks as not held, the way DirSource does for a fastsynced store.
type prunedSource struct {
	Source
	pruned map[crypto.Hash]bool
}

func (p prunedSource) Block(h crypto.Hash) (*block.Block, error) {
	if p.pruned[h] {
		return nil, ErrUnavailable
	}
	return p.Source.Block(h)
}

// A pruned block inside the range is `unavailable`, never an audit error, and splits the range into segments.
func TestArchiveRangePrunedIsUnavailable(t *testing.T) {
	w := newWorld(t)
	var topo fakeTopo
	var ids []crypto.Hash
	for i := 0; i < 5; i++ {
		c := w.child(fmt.Sprintf("arch%d", i))
		c.bl.Height = H + uint64(i)
		c.coinbase(0)
		c.commit()
		ids = append(ids, c.id)
		topo = append(topo, c.id)
	}
	topo = append(fakeTopo{{}}, topo...) // topo 0 unwritten, blocks at topo 1..5
	src := prunedSource{Source: w.f, pruned: map[crypto.Hash]bool{ids[2]: true}}
	s := ArchiveRange(src, topo, 0, 5, mainnet, nil)
	if s.Requested != 6 || s.Audited != 4 || s.Unavailable != 2 || s.Errors != 0 {
		t.Fatalf("requested %d audited %d unavailable %d errors %d (%s)", s.Requested, s.Audited, s.Unavailable, s.Errors, s.FirstError)
	}
	if len(s.Segments) != 2 || s.Available[0] != [2]int64{1, 2} || s.Available[1] != [2]int64{4, 5} {
		t.Fatalf("segments %v", s.Available)
	}
	for _, g := range s.Segments {
		if !g.Consistent || g.Verified != 2 {
			t.Fatalf("segment %+v", g)
		}
	}
	if s.Cumulative.Consistent || s.Cumulative.Gaps != 1 {
		t.Fatalf("the whole range has a gap: %+v", s.Cumulative)
	}
}

func writeTopo(t *testing.T, recs [][3]uint64) string {
	var b bytes.Buffer
	for _, r := range recs {
		var x [48]byte
		if r[0] != 0 {
			binary.BigEndian.PutUint64(x[:8], r[0])
		}
		binary.LittleEndian.PutUint64(x[32:], r[1])
		binary.LittleEndian.PutUint64(x[40:], r[2])
		b.Write(x[:])
	}
	p := filepath.Join(t.TempDir(), "topo.map")
	if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A fastsynced topo.map: unwritten slots below the bootstrap and at the end.
func TestTopoMapSkipsUnwrittenSlots(t *testing.T) {
	var recs [][3]uint64
	for i := uint64(0); i < 20; i++ {
		switch {
		case i < 7 || i >= 17:
			recs = append(recs, [3]uint64{0, 4225, 0})
		default:
			recs = append(recs, [3]uint64{i + 1, i, 100 + i})
		}
	}
	tm, err := OpenTopo(writeTopo(t, recs))
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	if tm.FirstWritten() != 7 || tm.LastWritten() != 16 {
		t.Fatalf("written %d..%d, want 7..16", tm.FirstWritten(), tm.LastWritten())
	}
	for h, want := range map[int64]int64{0: 7, 107: 7, 110: 10, 116: 16, 117: 17} {
		if got := tm.FindHeight(h); got != want {
			t.Fatalf("FindHeight(%d) = %d, want %d", h, got, want)
		}
	}
	if _, _, _, err := tm.Record(3); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unwritten slot must be unavailable, got %v", err)
	}
}

func TestSeriesTornTailAndChecksum(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	for i := 0; i < 3; i++ {
		if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: uint64(100 * (i + 1)), Observed: uint64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, b[:len(b)-20], 0600); err != nil { // a crash mid-append: torn last record
		t.Fatal(err)
	}
	recs, bad, err := ReadSeriesTail(p, SeriesMaxBytes)
	if err != nil || len(recs) != 2 || bad != 1 {
		t.Fatalf("torn tail: %d records, %d bad, %v", len(recs), bad, err)
	}
	if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: 400}); err != nil {
		t.Fatal(err)
	}
	recs, bad, _ = ReadSeriesTail(p, SeriesMaxBytes)
	if len(recs) != 3 || bad != 1 || recs[2].Height != 400 {
		t.Fatalf("append after a torn tail must survive: %d records %d bad %+v", len(recs), bad, recs)
	}
	b, _ = os.ReadFile(p)
	i := bytes.Index(b, []byte(`"height":200`))
	b[i+10] = '9' // a corrupted digit, the json still parses
	os.WriteFile(p, b, 0600)
	recs, bad, _ = ReadSeriesTail(p, SeriesMaxBytes)
	if len(recs) != 2 || bad != 2 {
		t.Fatalf("checksum: %d records %d bad", len(recs), bad)
	}
	for _, r := range recs {
		if r.Height == 900 || r.Height == 290 {
			t.Fatalf("a record with a bad checksum was returned: %+v", r)
		}
	}
	// a window that starts mid-line drops only that partial line
	recs, bad, _ = ReadSeriesTail(p, int64(len(EncodeSeriesLine(SeriesRecord{Kind: SeriesCheckpoint, Height: 400})))+5)
	if len(recs) != 1 || recs[0].Height != 400 || bad != 0 {
		t.Fatalf("tail window: %+v bad %d", recs, bad)
	}
}

func loadHF3Fixture(t *testing.T) []byte {
	h, err := os.ReadFile("testdata/hf3_414f79b8.tx.hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The fixture is the mainnet body of HF3 entry 414f79b8 (false parity, block 7,467,498), read from this project's
// archived pre-HF3 datadir. Defensive: the second body below differs in one proof byte and is only described.
func TestHF3ForensicOnRealBody(t *testing.T) {
	raw := loadHF3Fixture(t)
	const id = "414f79b8ff3c862eaa5727c6591542218881c751ba4fe052c9aaeeec0cfedfcd"
	te := blockchain.HF3_Affected_Txs[id]
	if te == nil {
		t.Fatal("fixture txid is not in the HF3 table")
	}
	e := HF3Entry{TXID: id, BlTips: te.Bl_Tips, Height: te.Height, TxParity: te.Tx_Parity}
	blk := BlockRef{Topo: 7467498, Height: 7467498, BLID: "6837704e", Tips: []string{te.Bl_Tips}}
	other := BlockRef{Topo: 7467499, Height: 7467499, BLID: "x", Tips: []string{"y"}}
	r := HF3Forensic(e, []Body{{Source: "a", Bytes: raw}, {Source: "b", Bytes: raw}}, []BlockRef{other, blk}, "test")
	if !r.InStore || r.BodiesSeen != 2 || r.DistinctBodies != 1 || r.BodiesDiffer || r.Class != "false_parity" {
		t.Fatalf("record %+v", r)
	}
	f := r.Bodies[0]
	if !f.Canonical || f.Type != "NORMAL" || f.Fees != 121 || f.TxHeight != 7467492 || len(f.RingSizes) != 1 || f.RingSizes[0] != 2 || len(f.Sources) != 2 {
		t.Fatalf("body facts %+v", f)
	}
	if r.TableBlock != "6837704e" || r.ExecParity == nil || *r.ExecParity != false || r.ExecParityMatchesProof == nil || !*r.ExecParityMatchesProof {
		t.Fatalf("table block %q exec parity %v matches %v", r.TableBlock, r.ExecParity, r.ExecParityMatchesProof)
	}
	if r.TxHeightMatchesTable {
		t.Fatal("the table height is the executing block's height, not tx.Height")
	}

	// a second body with the same TXID (one proof byte changed) is told apart by its full-body hash
	var alt []byte
	for off := len(raw) - 1; off > len(raw)-200 && alt == nil; off-- {
		b := append([]byte(nil), raw...)
		b[off] ^= 0x01
		if tx, err := DecodeTx(b); err == nil && tx.GetHash().String() == id {
			alt = b
		}
	}
	if alt == nil {
		t.Fatal("no decodable same-TXID variant")
	}
	r = HF3Forensic(e, []Body{{Source: "a", Bytes: raw}, {Source: "b", Bytes: alt}}, nil, "test")
	if !r.BodiesDiffer || r.DistinctBodies != 2 || r.Bodies[0].BodyKeccak == r.Bodies[1].BodyKeccak {
		t.Fatalf("two bodies of one TXID must be told apart: %+v", r)
	}

	// a body that is not this TXID is foreign and never described
	tx, _ := DecodeTx(raw)
	tx.Height++ // the TXID commits to the reference height
	foreign := tx.Serialize()
	r = HF3Forensic(e, []Body{{Source: "x", Bytes: foreign}, {Source: "y", Bytes: []byte{1, 2, 3}}}, nil, "test")
	if r.InStore || r.ForeignBodies != 2 || len(r.Bodies) != 0 {
		t.Fatalf("foreign bodies must not be described: %+v", r)
	}
	s := SummarizeHF3([]HF3Record{HF3Forensic(e, []Body{{Bytes: raw}}, []BlockRef{blk}, "")})
	if s.InStore != 1 || s.FeesKnown != 121 || s.FalseParity != 1 || s.TableBlocksFound != 1 || !strings.Contains(s.Limit, "encrypted") {
		t.Fatalf("summary %+v", s)
	}
}

// HF3FalseParity must be exactly the entries under the "false parity" comment of blockchain/hardfork_fixes.go.
func TestHF3ClassesMatchTable(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "blockchain", "hardfork_fixes.go"))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(src, []byte("// no duplicates, but false parity"))
	if i < 0 {
		t.Fatal("false-parity section not found")
	}
	ids := regexp.MustCompile(`"([0-9a-f]{64})": \{`).FindAllSubmatch(src[i:], -1)
	if len(ids) != 8 || len(HF3FalseParity) != 8 {
		t.Fatalf("%d false-parity ids in the source, %d in HF3FalseParity", len(ids), len(HF3FalseParity))
	}
	for _, m := range ids {
		if !HF3FalseParity[string(m[1])] {
			t.Fatalf("source false-parity id %s missing", m[1])
		}
	}
	dups := 0
	for k := range blockchain.HF3_Affected_Txs {
		if !HF3FalseParity[k] {
			dups++
		}
	}
	if dups != 67 {
		t.Fatalf("%d duplicates, want 67", dups)
	}
}
