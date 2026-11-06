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
	"path/filepath"
	"testing"
)

// r27 (B36): an archive segment counts its coinbase payees like the live auditor (cmd/derod/rpc flows_of), and a
// series checkpoint carries them with V = SeriesV2, so a stopped process's payee totals survive in the file.
func TestR27CumulativeCountsPayees(t *testing.T) {
	var c Cumulative
	py := []Payee{{Amount: 1, Verified: true, Explained: true}, {Amount: 2, Explained: true}, {Amount: 3}}
	for h := uint64(1000); h < 1004; h++ {
		c.Add(Report{Height: h, Verdict: VerdictOK, BaseReward: BlockReward(h), Payees: py}, nil)
	}
	if c.Payees != 12 || c.PayeesVerified != 4 || c.PayeesExplained != 8 {
		t.Fatalf("payees %d verified %d explained %d, want 12 4 8", c.Payees, c.PayeesVerified, c.PayeesExplained)
	}
	c.Add(Report{Height: 1004, Payees: py}, ErrUnavailable) // an audit error: no flows counted
	if c.Payees != 12 {
		t.Fatalf("an errored height added payees: %d", c.Payees)
	}
}

func TestR27SeriesCarriesPayees(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: 100}); err != nil { // a pre-r27 shape
		t.Fatal(err)
	}
	if err := AppendSeries(p, SeriesRecord{Kind: SeriesCheckpoint, Height: 200, V: SeriesV2, Payees: 3141, PayeesVerified: 3000, PayeesExplained: 3141}); err != nil {
		t.Fatal(err)
	}
	recs, bad, err := ReadSeriesTail(p, SeriesMaxBytes)
	if err != nil || bad != 0 || len(recs) != 2 {
		t.Fatalf("%d records %d bad %v", len(recs), bad, err)
	}
	if recs[0].PayeesKnown() || recs[0].Payees != 0 {
		t.Fatalf("a pre-r27 record claims payee counts: %+v", recs[0])
	}
	if !recs[1].PayeesKnown() || recs[1].Payees != 3141 || recs[1].PayeesVerified != 3000 || recs[1].PayeesExplained != 3141 {
		t.Fatalf("payees lost in the round trip: %+v", recs[1])
	}
}
