// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
)

type emission_fake struct {
	topo    int64
	blids   map[int64]crypto.Hash
	heights map[crypto.Hash]uint64
	verdict map[crypto.Hash]string
	fail    map[crypto.Hash]bool
	calls   int
}

func (f *emission_fake) set(t int64, tag string) crypto.Hash {
	h := crypto.Keccak256([]byte(fmt.Sprintf("%d/%s", t, tag)))
	f.blids[t], f.heights[h] = h, uint64(t)
	return h
}

func install_emission_fake(t *testing.T, topo int64) (*emission_fake, *emission_auditor) {
	f := &emission_fake{topo: topo, blids: map[int64]crypto.Hash{}, heights: map[crypto.Hash]uint64{}, verdict: map[crypto.Hash]string{}, fail: map[crypto.Hash]bool{}}
	for i := int64(1); i <= 5000; i++ {
		f.set(i, "a")
	}
	ot, ob, oa := emission_topo, emission_topo_blid, emission_audit_block
	emission_topo = func() int64 { return f.topo }
	emission_topo_blid = func(t int64) (crypto.Hash, error) {
		if h, ok := f.blids[t]; ok {
			return h, nil
		}
		return crypto.Hash{}, errors.New("no topo")
	}
	emission_audit_block = func(blid crypto.Hash) (emission.Report, error) {
		f.calls++
		if f.fail[blid] {
			return emission.Report{BLID: blid.String()}, errors.New("missing block")
		}
		h := f.heights[blid]
		v := emission.VerdictOK
		if f.verdict[blid] != "" {
			v = f.verdict[blid]
		}
		return emission.Report{BLID: blid.String(), Height: h, BaseReward: emission.BlockReward(h), Fees: 10, Verdict: v, Micros: 1000,
			Payees: []emission.Payee{{Amount: 1, Verified: true}, {Amount: 2}}}, nil
	}
	t.Cleanup(func() { emission_topo, emission_topo_blid, emission_audit_block = ot, ob, oa })
	a := new_emission_auditor()
	a.res.Enabled = true
	return f, a
}

func TestEmissionAuditStepBackfillAndFollow(t *testing.T) {
	for i := 0; i < 3; i++ {
		f, a := install_emission_fake(t, 1000)
		if n := a.step(); n != EMISSION_BACKFILL {
			t.Fatalf("first pass audited %d, want %d", n, EMISSION_BACKFILL)
		}
		f.topo = 1001
		if n := a.step(); n != 1 {
			t.Fatalf("follow pass audited %d, want 1", n)
		}
		if n := a.step(); n != 0 {
			t.Fatalf("idle pass audited %d", n)
		}
		r := a.snapshot()
		if r.Status != "OK" || r.SegmentFrom != 985 || r.SegmentTo != 1001 || r.VerifiedHeights != 17 || !r.EmissionConsistent {
			t.Fatalf("segment %+v", r)
		}
		if r.ObservedEmission != r.FormulaEmission || r.FormulaEmission != 17*emission.BlockReward(1000) {
			t.Fatalf("observed %d formula %d", r.ObservedEmission, r.FormulaEmission)
		}
		if r.Payees != 34 || r.PayeesVerified != 17 || r.FeesRedistributed != 170 || r.MeanMicros != 1000 {
			t.Fatalf("totals %+v", r)
		}
	}
}

func TestEmissionAuditReorgReaudits(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	a.step()
	nb := f.set(998, "b") // the block at topoheight 998 was replaced
	f.verdict[nb] = emission.VerdictSCUnexplained
	if n := a.step(); n != 1 {
		t.Fatalf("reorg pass audited %d, want 1", n)
	}
	r := a.snapshot()
	// r23 merge: an unexplained SC block is outside the verified set, not a break of the segment
	if r.Reorgs != 1 || r.VerifiedHeights != 15 || r.UnverifiedHeights != 1 || !r.EmissionConsistent {
		t.Fatalf("after reorg to an unverified block: %+v", r)
	}
	f.set(998, "c")
	a.step()
	if r = a.snapshot(); r.VerifiedHeights != 16 || r.UnverifiedHeights != 0 || !r.EmissionConsistent || r.Reorgs != 2 {
		t.Fatalf("after reorg back to a verified block: %+v", r)
	}
	if r.Payees != 32 { // a re-audited height is not counted twice
		t.Fatalf("payees %d", r.Payees)
	}
}

func TestEmissionAuditSkipsAheadWhenFarBehind(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	a.step()
	f.topo = 1000 + EMISSION_CATCHUP_MAX + 1
	f.calls = 0
	a.step()
	r := a.snapshot()
	if f.calls != EMISSION_BACKFILL || r.Gaps != 1 || r.SegmentFrom != uint64(f.topo-EMISSION_BACKFILL+1) || !r.EmissionConsistent {
		t.Fatalf("calls %d result %+v", f.calls, r)
	}
}

func TestEmissionAuditAlertAndError(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	f.verdict[f.blids[999]] = emission.VerdictAlert
	f.fail[f.blids[1000]] = true
	before := emission_alerts_total.Get()
	a.step()
	r := a.snapshot()
	if r.Status != "ALERT" || r.Alerts != 1 || len(r.LastAlerts) != 1 || r.Verdicts[emission.VerdictError] != 1 || r.LastError == "" {
		t.Fatalf("result %+v", r)
	}
	if emission_alerts_total.Get() != before+1 {
		t.Fatalf("alert counter not incremented")
	}
	if r.EmissionConsistent { // an alerted and an unaudited height break the segment
		t.Fatalf("segment consistent despite alert/error")
	}
}

func TestEmissionAuditNotableFlow(t *testing.T) {
	_, a := install_emission_fake(t, 1000)
	a.step()
	big := emission.Report{Height: 1001, Verdict: emission.VerdictOKSC, MaxPlainFlow: emission.FormulaSupply(1001)}
	a.record(1001, crypto.Hash{1}, big, nil, false)
	small := emission.Report{Height: 1002, Verdict: emission.VerdictOK, MaxPlainFlow: 5}
	a.record(1002, crypto.Hash{2}, small, nil, false)
	if r := a.snapshot(); len(r.Notable) != 1 || r.Notable[0].Height != 1001 {
		t.Fatalf("notable %+v", r.Notable)
	}
}

func TestEmissionAuditEnabledSwitch(t *testing.T) {
	if !emission_audit_enabled(func(string) string { return "" }) || emission_audit_enabled(func(string) string { return "0" }) {
		t.Fatalf("DERO_EMISSION_AUDIT switch")
	}
	a := new_emission_auditor()
	if a.snapshot().Status != "disabled" {
		t.Fatalf("status of a disabled auditor")
	}
}

// r23 merge: one benign sc_unexplained block (consensus quirk) or one transient audit error must not leave
// emission_consistent false for good: the first is excused, the second is retried.
func TestEmissionAuditUnexplainedAndErrorDoNotStick(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	f.verdict[f.blids[995]] = emission.VerdictSCUnexplained
	f.fail[f.blids[997]] = true // inside the segment, and the failed audit reports no height
	a.step()
	r := a.snapshot()
	if r.EmissionConsistent || r.UnverifiedHeights != 1 {
		t.Fatalf("an errored height (no report) must leave the segment open until it is retried: %+v", r)
	}
	delete(f.fail, f.blids[997]) // the error was transient
	f.calls = 0
	a.step()
	if r = a.snapshot(); f.calls != 1 || !r.EmissionConsistent || r.VerifiedHeights != 15 || r.UnverifiedHeights != 1 || r.Alerts != 0 {
		t.Fatalf("errored height not retried, or unexplained block not excused: calls %d %+v", f.calls, r)
	}
}

// r23 merge: a persistently failing topoheight is retried at most EMISSION_ERROR_RETRIES times in all.
func TestEmissionAuditErrorRetryCapped(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	f.fail[f.blids[1000]] = true
	a.step()
	f.calls = 0
	for i := 0; i < 10; i++ {
		a.step()
	}
	if f.calls != EMISSION_ERROR_RETRIES-1 {
		t.Fatalf("persistent error audited %d more times, want %d", f.calls, EMISSION_ERROR_RETRIES-1)
	}
}
