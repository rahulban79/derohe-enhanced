// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package emission

// r27 (glue-global): the archive reader (DirSource, 0.0% covered), the series file (tail window, CountSeries, payee
// census) and the genesis edge of the cumulative account.

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

func within_deadline(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return within 10 s (FormulaSupply(h-1) wrapped at h == 0)", what)
	}
}

func TestR27FormulaSupplyBoundedAndGenesis(t *testing.T) {
	var top uint64
	within_deadline(t, "FormulaSupply(2^64-1)", func() { top = FormulaSupply(math.MaxUint64) })
	if top != FormulaSupply(200000000) || FormulaSupply(200000000) != FormulaSupply(112000000) {
		t.Fatalf("supply must stop growing once the reward is 0: %d %d %d", top, FormulaSupply(200000000), FormulaSupply(112000000))
	}
	if BlockReward(111999999) != 1 || FormulaSupply(112000000)-FormulaSupply(111999999) != 1 { // the last paying interval
		t.Fatalf("the last paying interval was cut off: reward %d", BlockReward(111999999))
	}
	if SupplyBefore(0) != FormulaSupply(0) || SupplyBefore(5) != FormulaSupply(4) {
		t.Fatalf("SupplyBefore")
	}
	var c Cumulative
	within_deadline(t, "Cumulative.Add(genesis)", func() {
		c.Add(Report{Height: 0, Verdict: VerdictSkipped}, nil) // the genesis on a full archive node
		for h := uint64(1); h <= 3; h++ {
			c.Add(okReport(h), nil)
		}
	})
	if c.From != 0 || c.To != 3 || c.Excused != 0 || c.Formula != FormulaSupply(3)-FormulaSupply(0) || !c.Consistent {
		t.Fatalf("genesis segment: %+v", c)
	}
}

func TestR27CumulativeCountsPayeesSkipsErrors(t *testing.T) {
	var c Cumulative
	r := okReport(7600000)
	r.Payees = []Payee{{Verified: true, Explained: true}, {Explained: true}, {}}
	c.Add(r, nil)
	c.Add(okReport(7600001), nil)
	e := okReport(7600002)
	e.Payees = []Payee{{Verified: true}}
	c.Add(e, errors.New("missing tx")) // an errored audit contributes no flows and no payees
	if c.Payees != 3 || c.PayeesVerified != 1 || c.PayeesExplained != 2 {
		t.Fatalf("payees %d verified %d explained %d", c.Payees, c.PayeesVerified, c.PayeesExplained)
	}
}

func TestR27SeriesPayeesRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: 7, Payees: 3141, PayeesVerified: 3000, PayeesExplained: 3141}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, k := range []string{`"payees":3141`, `"payees_verified":3000`, `"payees_explained":3141`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Fatalf("line %s lacks %s", b, k)
		}
	}
	old := []byte(`{"kind":"checkpoint","height":9}`) // a pre-r27 record: no payee keys
	line := []byte(fmt.Sprintf("%s %08x", old, crc32.ChecksumIEEE(old)))
	if r, ok := ParseSeriesLine(line); !ok || r.Height != 9 || r.Payees != 0 {
		t.Fatalf("old record: %+v %v", r, ok)
	}
	recs, bad, err := ReadSeriesTail(p, SeriesMaxBytes)
	if err != nil || bad != 0 || len(recs) != 1 || recs[0].Payees != 3141 || recs[0].PayeesVerified != 3000 || recs[0].PayeesExplained != 3141 {
		t.Fatalf("read back %+v bad %d %v", recs, bad, err)
	}
}

func TestR27SeriesTailWindowOnLineBoundary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	var lines [][]byte
	for i := 1; i <= 4; i++ {
		r := SeriesRecord{Kind: SeriesCheckpoint, Height: uint64(100 * i)}
		lines = append(lines, EncodeSeriesLine(r))
		if err := AppendSeries(p, r); err != nil {
			t.Fatal(err)
		}
	}
	for keep := 1; keep <= 3; keep++ { // a window of exactly the last `keep` lines holds `keep` intact records
		n := 0
		for _, l := range lines[len(lines)-keep:] {
			n += len(l)
		}
		recs, bad, err := ReadSeriesTail(p, int64(n))
		if err != nil || bad != 0 || len(recs) != keep || recs[0].Height != uint64(100*(5-keep)) {
			t.Fatalf("window of %d whole lines: %d records (bad %d, %v), first %+v", keep, len(recs), bad, err, recs)
		}
		recs, _, _ = ReadSeriesTail(p, int64(n-1)) // one byte short: the first of them is partial and dropped
		if len(recs) != keep-1 {
			t.Fatalf("window one byte short of %d lines: %d records", keep, len(recs))
		}
	}
}

func TestR27CountSeries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	for i := 0; i < 5; i++ {
		AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: uint64(i)})
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("garbage line\n\n{\"kind\":\"x\"} 00000000\n")
	f.Close()
	if in, bad, err := CountSeries(p); err != nil || in != 5 || bad != 2 {
		t.Fatalf("CountSeries %d intact %d bad %v", in, bad, err)
	}
	if _, _, err := CountSeries(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatalf("a missing file must be an error")
	}
}

// a datadir laid out like blockchain/storefs.go: bltx_store/xx/yy/<hash>.block_<difficulty>_<version>_<height>
func TestR27DirSourceReadsStorefsLayout(t *testing.T) {
	root := t.TempDir()
	mem, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := mem.LoadSnapshot(0)
	tree, _ := ss.GetTree("t")
	tree.Put([]byte("k"), []byte("v"))
	if _, err := graviton.Commit(tree); err != nil { // version 1
		t.Fatal(err)
	}
	src := &DirSource{BLTX: root, Store: mem}

	bl := block.Block{Major_Version: 1, Height: 42, Timestamp: 1}
	bl.Miner_TX.Version, bl.Miner_TX.TransactionType = 1, transaction.PREMINE
	h := bl.GetHash()
	d := src.dir(h[0], h[1])
	os.MkdirAll(d, 0700)
	body := bl.Serialize()
	for _, v := range []int{0, 1} { // two state versions of the same block: the newest wins
		os.WriteFile(filepath.Join(d, fmt.Sprintf("%x.block_1000_%d_42", h[:], v)), body, 0600)
	}
	os.WriteFile(filepath.Join(d, "unrelated.block_1_9_1"), []byte("x"), 0600)
	name, v, err := src.BlockFile(h)
	if err != nil || v != 1 || filepath.Base(name) != fmt.Sprintf("%x.block_1000_1_42", h[:]) {
		t.Fatalf("BlockFile %s v%d %v", name, v, err)
	}
	got, err := src.Block(h)
	if err != nil || got.Height != 42 || got.GetHash() != h {
		t.Fatalf("Block %+v %v", got, err)
	}
	st, err := src.State(h)
	if err != nil || st.GetVersion() != 1 {
		t.Fatalf("State %v", err)
	}

	var missing crypto.Hash
	missing[0], missing[1] = h[0]^0xff, 7
	if _, err := src.Block(missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a block in a missing directory: %v", err)
	}
	missing[0], missing[1] = h[0], h[1] // same directory, no such file
	if _, _, err := src.BlockFile(missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a block missing from its directory: %v", err)
	}
	if _, err := (&DirSource{BLTX: root}).State(h); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no store: %v", err)
	}
	bl0 := block.Block{Major_Version: 1, Height: 43}
	bl0.Miner_TX.Version, bl0.Miner_TX.TransactionType = 1, transaction.PREMINE
	h0 := bl0.GetHash()
	os.MkdirAll(src.dir(h0[0], h0[1]), 0700)
	os.WriteFile(filepath.Join(src.dir(h0[0], h0[1]), fmt.Sprintf("%x.block_1000_0_43", h0[:])), bl0.Serialize(), 0600)
	if _, err := src.State(h0); !errors.Is(err, ErrUnavailable) { // version 0: no state was ever committed for it
		t.Fatalf("version-0 state: %v", err)
	}

	var txid crypto.Hash
	for i := range txid {
		txid[i] = byte(i + 1)
	}
	if _, err := src.TxBytes(txid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent tx: %v", err)
	}
	alt := src.dir(txid[16], txid[17]) // storefs keeps a tx at either of two directories
	os.MkdirAll(alt, 0700)
	os.WriteFile(filepath.Join(alt, fmt.Sprintf("%x.tx", txid[:])), []byte{0xff, 0xff}, 0600)
	if b, err := src.TxBytes(txid); err != nil || len(b) != 2 {
		t.Fatalf("tx at the second directory: %v", err)
	}
	if tx, err := src.Tx(txid); err == nil || tx != nil {
		t.Fatalf("a body that does not decode must be an error, not a transaction")
	}
}

func TestR27TopoMapLen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "topo.map")
	os.WriteFile(p, make([]byte, 48*3+7), 0600) // a torn trailing partial record is not counted
	tm, err := OpenTopo(p)
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	if tm.Len() != 3 || tm.LastWritten() != -1 || tm.FirstWritten() != -1 || tm.FindHeight(5) != 0 {
		t.Fatalf("len %d last %d first %d", tm.Len(), tm.LastWritten(), tm.FirstWritten())
	}
	if _, err := OpenTopo(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatalf("missing topo.map must be an error")
	}
}
