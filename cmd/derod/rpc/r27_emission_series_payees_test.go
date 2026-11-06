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
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/glue/emission"
)

// r27 (B36): every checkpoint the live auditor appends carries the segment's payee totals as GetEmissionAudit shows
// them at that moment (the fake audit reports 2 payees per block, 1 verified), so the file alone answers the payee
// part of a 24 h emission read after the process stopped.
func TestR27EmissionSeriesCheckpointsCarryPayees(t *testing.T) {
	path := filepath.Join(t.TempDir(), EMISSION_SERIES_FILE)
	f, a := install_emission_fake(t, 1090)
	a.open_series(path)
	a.step()
	for f.topo < 1310 {
		f.topo += 7
		a.step()
	}
	recs, bad, err := emission.ReadSeriesTail(path, emission.SeriesMaxBytes)
	if err != nil || bad != 0 || len(recs) != 4 {
		t.Fatalf("file: %d records %d bad %v", len(recs), bad, err)
	}
	for _, x := range recs {
		n := x.Verified // every fake height verifies, so payees = 2 per height
		if !x.PayeesKnown() || x.Payees != 2*n || x.PayeesVerified != n {
			t.Fatalf("checkpoint at %d: v %d payees %d verified %d, want %d %d", x.SegmentTo, x.V, x.Payees, x.PayeesVerified, 2*n, n)
		}
	}
	last := recs[len(recs)-1]
	if r := a.snapshot(); last.SegmentTo == r.SegmentTo && last.Payees != r.Payees {
		t.Fatalf("checkpoint payees %d != GetEmissionAudit payees %d at the same top", last.Payees, r.Payees)
	}
}

// r27 (glue-global): a series checkpoint carries the auditor's payee census (it carried none before).
func TestR27SeriesRecordCarriesPayees(t *testing.T) {
	a := new_emission_auditor()
	a.res.Payees, a.res.PayeesVerified, a.res.PayeesExplained = 3141, 3100, 3141
	r := a.series_record(emission.SeriesCheckpoint, 7, emission.Report{Height: 7})
	if r.Payees != 3141 || r.PayeesVerified != 3100 || r.PayeesExplained != 3141 {
		t.Fatalf("checkpoint payees %d verified %d explained %d", r.Payees, r.PayeesVerified, r.PayeesExplained)
	}
}
