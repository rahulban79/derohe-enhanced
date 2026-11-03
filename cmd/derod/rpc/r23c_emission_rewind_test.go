// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"testing"

	"github.com/deroproject/derohe/glue/emission"
)

// r23c: a local rewind (console pop / Rewind_Chain) deeper than the topoheights the auditor's window remembers
// (4*EMISSION_REORG_WINDOW) re-audits the regrown heights as new: before the fix their old contributions were never
// taken back, so verified_heights and the flow totals counted those heights twice and emission_consistent went
// false for an honest chain.
func TestR23cEmissionDeepRewindNotDoubleCounted(t *testing.T) {
	for _, depth := range []int64{10, 4*EMISSION_REORG_WINDOW + 1, 50, 200} {
		f, a := install_emission_fake(t, 1000)
		a.step()
		for f.topo = 1001; f.topo <= 1100; f.topo++ { // follow block by block
			a.step()
		}
		f.topo = 1100
		before := a.snapshot()
		if before.VerifiedHeights != 116 || !before.EmissionConsistent {
			t.Fatalf("depth %d: before rewind %+v", depth, before)
		}
		f.topo = 1100 - depth // rewind
		for t2 := f.topo + 1; t2 <= 1100; t2++ {
			f.set(t2, "b") // the regrown chain has other blocks
		}
		a.step()
		for f.topo = 1100 - depth + 1; f.topo <= 1100; f.topo++ {
			a.step()
		}
		f.topo = 1100
		r := a.snapshot()
		span := r.SegmentTo - r.SegmentFrom + 1
		// within EMISSION_WINDOW_KEEP the history is kept: the segment still starts at the first backfilled height,
		// or lower when the first regrowth pass re-read below it (from = rewind target + 1 - EMISSION_REORG_WINDOW)
		wantFrom := uint64(985)
		if low := uint64(1100 - depth + 1 - EMISSION_REORG_WINDOW); low < wantFrom {
			wantFrom = low
		}
		if r.SegmentFrom != wantFrom || r.DeepRewinds != 0 || r.Gaps != 0 {
			t.Fatalf("depth %d: segment restarted: from %d deep_rewinds %d gaps %d", depth, r.SegmentFrom, r.DeepRewinds, r.Gaps)
		}
		if r.VerifiedHeights != span || !r.EmissionConsistent || r.Payees != 2*span || r.PayeesVerified != span || r.FeesRedistributed != 10*span {
			t.Fatalf("depth %d: after regrowth segment %d..%d verified %d payees %d verified_payees %d fees %d consistent %v",
				depth, r.SegmentFrom, r.SegmentTo, r.VerifiedHeights, r.Payees, r.PayeesVerified, r.FeesRedistributed, r.EmissionConsistent)
		}
	}
}

// r23c: deeper than EMISSION_WINDOW_KEEP the dropped contributions cannot be taken back: the segment and the flow
// totals restart (one deep_rewinds), and nothing is counted twice.
func TestR23cEmissionRewindBeyondKeepRestartsSegment(t *testing.T) {
	f, a := install_emission_fake(t, 100)
	a.step()
	for f.topo = 101; f.topo <= 4900; f.topo++ {
		a.step()
	}
	f.topo = 4900
	f.topo = 4900 - EMISSION_WINDOW_KEEP - 100
	for t2 := f.topo + 1; t2 <= 4900; t2++ {
		f.set(t2, "b")
	}
	a.step()
	for f.topo = 4900 - EMISSION_WINDOW_KEEP - 100 + 1; f.topo <= 4900; f.topo++ {
		a.step()
	}
	f.topo = 4900
	r := a.snapshot()
	span := r.SegmentTo - r.SegmentFrom + 1
	if r.DeepRewinds != 1 || r.Gaps != 1 || !r.EmissionConsistent || r.VerifiedHeights != span || r.Payees != 2*span || r.FeesRedistributed != 10*span {
		t.Fatalf("segment %d..%d deep %d gaps %d verified %d payees %d fees %d consistent %v", r.SegmentFrom, r.SegmentTo, r.DeepRewinds, r.Gaps, r.VerifiedHeights, r.Payees, r.FeesRedistributed, r.EmissionConsistent)
	}
}

// r23c: GetMonetaryIntegrity carries the audited emission and the payee/burn totals of GetEmissionAudit
func TestR23cMonetaryIntegrityCarriesIssuedAndPayees(t *testing.T) {
	em := GetEmissionAudit_Result{Enabled: true, Status: "OK", IssuedEmission: 307500, IssuedMatchesFormula: true, ObservedEmission: 307500,
		Burns: 7, Payees: 30, PayeesVerified: 27, PayeesExplained: 30, DeepRewinds: 1}
	r := monetary_integrity(GetMonetaryIntegrity_Params{}, em, HF3Exemption_Facts{}, Reorg_Stats{}, 10)
	e := r.Emission
	if e.IssuedEmission != 307500 || !e.IssuedMatchesFormula || e.Burns != 7 || e.Payees != 30 || e.PayeesVerified != 27 || e.PayeesExplained != 30 || e.DeepRewinds != 1 {
		t.Fatalf("summary %+v", e)
	}
}

// r23c: explained payees are counted into the flow totals and taken back with the block on a reorg
func TestR23cFlowsCountExplained(t *testing.T) {
	f := flows_of(emission.Report{Payees: []emission.Payee{{Explained: true, Verified: true}, {Explained: true}, {}}})
	if f.payees != 3 || f.payees_verified != 1 || f.payees_explained != 2 {
		t.Fatalf("flows %+v", f)
	}
	var res GetEmissionAudit_Result
	res.add_flows(f, +1)
	if res.PayeesExplained != 2 || res.flows_total() != f {
		t.Fatalf("totals %+v", res)
	}
	res.add_flows(f, -1)
	if res.PayeesExplained != 0 || res.Payees != 0 {
		t.Fatalf("taken back %+v", res)
	}
}
