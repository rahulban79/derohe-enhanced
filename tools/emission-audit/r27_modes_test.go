// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package main

// r27 (tools-kats): tools/emission-audit had 4 Go sources and 0 tests (R27 Part A census) although it produced the
// B36 24 h read. These cover the payee tally both modes print (-archive printed none), the archive callback
// (segments reset at an unavailable height, series checkpoints at the interval), the series reader and the -hf3
// invocation check, on forged inputs only.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/glue/emission"
)

func r27Report(h uint64, payees ...emission.Payee) emission.Report {
	return emission.Report{Height: h, BaseReward: emission.BlockReward(h), Paid: emission.BlockReward(h), Verdict: emission.VerdictOK,
		Payees: payees}
}

func TestR27PayeeTallyCountsVerifiedAndExplained(t *testing.T) {
	var p payeeTally
	p.add(r27Report(1, emission.Payee{Verified: true}, emission.Payee{Explained: true}, emission.Payee{}))
	p.add(r27Report(2, emission.Payee{Verified: true, Explained: true}))
	p.add(r27Report(3))
	if p.payees != 4 || p.verified != 2 || p.explained != 2 {
		t.Fatalf("tally %+v, want 4 payees, 2 verified, 2 explained", p)
	}
	if s := p.String(); s != "payees 4 verified 2 explained 2" {
		t.Fatalf("String() = %q", s)
	}
}

// The -archive callback counts the payees of every audited report (an audit error still names its payees), skips
// unavailable heights for both the tally and the segment (which restarts), and writes a checkpoint each time the
// segment's top crosses a multiple of the interval.
func TestR27ArchiveEachPayeesSegmentsAndCheckpoints(t *testing.T) {
	series := filepath.Join(t.TempDir(), "series.jsonl")
	clock := int64(1000)
	a := &archiveRun{segStart: clock, seriesOut: series, every: 10, now: func() int64 { clock++; return clock }}
	for h := uint64(7600005); h <= 7600025; h++ {
		a.each(int64(h), r27Report(h, emission.Payee{Verified: true}, emission.Payee{}), nil)
	}
	a.each(0, emission.Report{}, fmt.Errorf("pruned: %w", emission.ErrUnavailable))
	if a.seg.Blocks != 0 {
		t.Fatalf("an unavailable height left the segment open (%d blocks)", a.seg.Blocks)
	}
	a.each(7600031, r27Report(7600031, emission.Payee{Explained: true}), errors.New("tx does not decode"))
	if a.payees.payees != 21*2+1 || a.payees.verified != 21 || a.payees.explained != 1 {
		t.Fatalf("payee tally %v, want 43 payees, 21 verified, 1 explained", a.payees)
	}
	intact, bad, err := emission.CountSeries(series)
	if err != nil || intact != 2 || bad != 0 || a.written != 2 || a.werr != 0 {
		t.Fatalf("checkpoints: file %d intact %d bad %v; written %d errors %d, want 2 (tops 7600010, 7600020)", intact, bad, err,
			a.written, a.werr)
	}
	recs, _, _ := emission.ReadSeriesTail(series, emission.SeriesMaxBytes)
	if len(recs) != 2 || recs[0].SegmentTo != 7600010 || recs[1].SegmentTo != 7600020 || recs[0].SegStart != 1000 {
		t.Fatalf("checkpoint records %+v", recs)
	}
}

func TestR27SeriesMainAndHF3Invocation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := emission.AppendSeries(p, emission.SeriesRecord{Kind: emission.SeriesCheckpoint, SegStart: 1, SegmentFrom: 1, SegmentTo: 9,
		Verified: 9, Consistent: true}); err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	devnull, _ := os.Open(os.DevNull)
	os.Stdout = devnull
	rc1, rc2, rc3 := seriesMain(p), seriesMain(p+".absent"), hf3Main(",,", "")
	os.Stdout = stdout
	if rc1 != 0 || rc2 != 1 || rc3 != 2 {
		t.Fatalf("seriesMain ok %d (want 0), missing %d (want 1); hf3Main without datadirs %d (want 2)", rc1, rc2, rc3)
	}
}
