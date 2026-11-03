// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package rpc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
)

// r23b: the auditor appends a checkpoint each time its segment top crosses a multiple of EMISSION_SERIES_EVERY,
// the records match the RPC segment, survive a restart (read back) and a failed write is counted, not fatal.
func TestEmissionSeriesCheckpointsPersist(t *testing.T) {
	for i := 0; i < 3; i++ {
		path := filepath.Join(t.TempDir(), EMISSION_SERIES_FILE)
		f, a := install_emission_fake(t, 1090)
		a.open_series(path)
		a.step() // 1075..1090: first checkpoint of the segment
		for f.topo < 1310 {
			f.topo += 7
			a.step()
		}
		r := a.snapshot()
		if r.Series.Written != 4 || r.Series.Errors != 0 || len(r.Series.Last) != 4 { // segment start (1076), 1100, 1200, 1300
			t.Fatalf("series %+v", r.Series)
		}
		recs, bad, err := emission.ReadSeriesTail(path, emission.SeriesMaxBytes)
		if err != nil || bad != 0 || len(recs) != 4 {
			t.Fatalf("file: %d records %d bad %v", len(recs), bad, err)
		}
		for _, x := range recs {
			if x.Kind != emission.SeriesCheckpoint || !x.Consistent || x.SegmentFrom != 1075 || x.Verified != x.SegmentTo-x.SegmentFrom+1 ||
				x.Observed != x.Formula || x.Formula != emission.FormulaSupply(x.SegmentTo)-emission.FormulaSupply(1074) || x.SegStart == 0 {
				t.Fatalf("checkpoint %+v", x)
			}
		}
		if recs[0].SegmentTo != 1076 || recs[1].SegmentTo != 1100 || recs[2].SegmentTo != 1200 || recs[3].SegmentTo != 1300 {
			t.Fatalf("checkpoints at %d %d %d %d: not the segment start and the interval crossings", recs[0].SegmentTo, recs[1].SegmentTo, recs[2].SegmentTo, recs[3].SegmentTo)
		}

		b := new_emission_auditor() // a restart reads back what the file holds
		b.open_series(path)
		if s := b.snapshot().Series; s.Records != 4 || s.Dropped != 0 || len(s.Last) != 4 || s.Last[3].SegmentTo != 1300 {
			t.Fatalf("read back %+v", s)
		}

		old := emission_series_append
		emission_series_append = func(string, emission.SeriesRecord) error { return errors.New("disk full") }
		for f.topo < 1410 {
			f.topo += 7
			a.step()
		}
		emission_series_append = old
		if s := a.snapshot().Series; s.Errors != 1 || s.LastError != "disk full" || s.Written != 4 {
			t.Fatalf("failed write %+v", s)
		}
	}
}

// A notable flow is also persisted; burns are summed into the RPC totals.
func TestEmissionSeriesNotableAndBurns(t *testing.T) {
	path := filepath.Join(t.TempDir(), EMISSION_SERIES_FILE)
	_, a := install_emission_fake(t, 1000)
	a.open_series(path)
	a.step()
	big := emission.Report{Height: 1001, Verdict: emission.VerdictOK, BaseReward: emission.BlockReward(1001), MaxPlainFlow: emission.FormulaSupply(1001), Burns: 70}
	a.record(1001, crypto.Hash{1}, big, nil, false)
	a.record(1002, crypto.Hash{2}, emission.Report{Height: 1002, Verdict: emission.VerdictOK, BaseReward: emission.BlockReward(1002), Burns: 5}, nil, false)
	a.step()
	recs, _, _ := emission.ReadSeriesTail(path, emission.SeriesMaxBytes)
	var notable int
	for _, x := range recs {
		if x.Kind == emission.SeriesNotable {
			notable++
			if x.Height != 1001 || x.Flow != emission.FormulaSupply(1001) {
				t.Fatalf("notable record %+v", x)
			}
		}
	}
	if notable != 1 {
		t.Fatalf("%d notable records in %+v", notable, recs)
	}
	if r := a.snapshot(); r.Burns != 75 {
		t.Fatalf("burns %d, want 75", r.Burns)
	}
}

func TestEmissionSeriesSwitch(t *testing.T) {
	if !emission_series_enabled(func(string) string { return "" }) || emission_series_enabled(func(string) string { return "0" }) {
		t.Fatal("DERO_EMISSION_SERIES switch")
	}
	_, a := install_emission_fake(t, 1000)
	a.step() // no open_series: nothing is written, nothing breaks
	if s := a.snapshot().Series; s.Enabled || s.Written != 0 {
		t.Fatalf("series without a file %+v", s)
	}
}

// issued_emission is the proven coinbase issuance (Paid - Fees); a replaced block's contribution is taken back.
func TestEmissionIssuedFollowsReorg(t *testing.T) {
	a := new_emission_auditor()
	a.res.Enabled = true
	for h := uint64(2000); h < 2004; h++ {
		b := emission.BlockReward(h)
		a.record(int64(h), crypto.Hash{byte(h)}, emission.Report{Height: h, Verdict: emission.VerdictOK, BaseReward: b, Fees: 9, Paid: b + 9}, nil, false)
	}
	r := a.snapshot()
	if r.IssuedEmission != 4*emission.BlockReward(2000) || !r.IssuedMatchesFormula || !r.EmissionConsistent {
		t.Fatalf("issued %d observed %d matches %v", r.IssuedEmission, r.ObservedEmission, r.IssuedMatchesFormula)
	}
	// height 2003 replaced by a block whose coinbase credited one share less (two finals): issued follows it
	b := emission.BlockReward(2003)
	a.record(2003, crypto.Hash{0xff}, emission.Report{Height: 2003, Verdict: emission.VerdictOK, BaseReward: b, Fees: 9, Paid: b + 9 - b/10}, nil, true)
	r = a.snapshot()
	if r.IssuedEmission != 4*b-b/10 || r.IssuedMatchesFormula || r.VerifiedHeights != 4 {
		t.Fatalf("after reorg: issued %d observed %d matches %v verified %d", r.IssuedEmission, r.ObservedEmission, r.IssuedMatchesFormula, r.VerifiedHeights)
	}
}

// r23b merge (SND-3 fix): the restart count is the whole file's, not the 1 MiB tail's
func TestR23bOpenSeriesCountsWholeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), EMISSION_SERIES_FILE)
	var b bytes.Buffer
	n := 0
	for b.Len() < 2*EMISSION_SERIES_TAIL {
		b.Write(emission.EncodeSeriesLine(emission.SeriesRecord{Kind: emission.SeriesCheckpoint, Height: uint64(100 * (n + 1))}))
		b.WriteByte('\n')
		n++
	}
	b.WriteString("torn line\n")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	tail, _, _ := emission.ReadSeriesTail(path, EMISSION_SERIES_TAIL)
	a := new_emission_auditor()
	a.open_series(path)
	s := a.snapshot().Series
	if s.Records != uint64(n) || s.Dropped != 1 || len(tail) >= n {
		t.Fatalf("records %d dropped %d, want %d and 1 (the tail alone holds %d)", s.Records, s.Dropped, n, len(tail))
	}
	if len(s.Last) != EMISSION_SERIES_SHOWN || s.Last[EMISSION_SERIES_SHOWN-1].Height != uint64(100*n) {
		t.Fatalf("last records %+v", s.Last)
	}
}
