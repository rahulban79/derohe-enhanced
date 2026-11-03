// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
)

// r23b forensics: when a topoheight is re-audited because its block was replaced (a reorg), the flow totals
// (fees_redistributed, sc_deposits, sc_payouts, payees, payees_verified) must describe the replacing block, not the
// first-seen one. Every fake block carries Fees 10 and 2 payees (1 verified); the replacing block below carries other
// flows, so the totals move by exactly the difference.
func TestR23bEmissionReorgReplacesFlows(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	a.step() // 16 heights 985..1000
	r := a.snapshot()
	if r.FeesRedistributed != 160 || r.Payees != 32 || r.PayeesVerified != 16 || r.SCPayouts != 0 || r.SCDeposits != 0 {
		t.Fatalf("before the reorg: %+v", r)
	}

	nb := f.set(998, "b")
	fake := emission_audit_block
	emission_audit_block = func(blid crypto.Hash) (emission.Report, error) {
		rep, err := fake(blid)
		if blid == nb {
			rep.Fees, rep.SCDeposits, rep.SCPayout, rep.Burns = 0, 700, 500, 4321
			rep.Payees = []emission.Payee{{Amount: 1, Verified: true}, {Amount: 2, Verified: true}, {Amount: 3, Verified: true}}
			rep.Verdict = emission.VerdictOKSC
		}
		return rep, err
	}
	t.Cleanup(func() { emission_audit_block = fake })
	if n := a.step(); n != 1 {
		t.Fatalf("reorg pass audited %d, want 1", n)
	}
	r = a.snapshot()
	if r.Reorgs != 1 || !r.EmissionConsistent || r.VerifiedHeights != 16 {
		t.Fatalf("segment after reorg: %+v", r)
	}
	if r.Burns != 4321 { // r23b merge: the soundness burns follow the reorg like the other flows
		t.Fatalf("burns after reorg %d, want 4321", r.Burns)
	}
	if r.FeesRedistributed != 150 || r.SCDeposits != 700 || r.SCPayouts != 500 || r.Payees != 33 || r.PayeesVerified != 18 {
		t.Fatalf("flows after reorg describe the replaced block: fees %d sc_deposits %d sc_payouts %d payees %d verified %d",
			r.FeesRedistributed, r.SCDeposits, r.SCPayouts, r.Payees, r.PayeesVerified)
	}

	// reorg back to a plain block: the SC flows are taken back again
	f.set(998, "c")
	a.step()
	if r = a.snapshot(); r.Reorgs != 2 || r.Burns != 0 || r.FeesRedistributed != 160 || r.SCDeposits != 0 || r.SCPayouts != 0 || r.Payees != 32 || r.PayeesVerified != 16 {
		t.Fatalf("flows after reorg back: %+v", r)
	}
}

// an errored audit adds no flows (even partial ones), and its successful retry (same block id) adds them once
func TestR23bEmissionErroredRetryCountsFlowsOnce(t *testing.T) {
	f, a := install_emission_fake(t, 1000)
	a.step()
	nb := f.set(1001, "a")
	f.fail[nb] = true
	fake := emission_audit_block
	emission_audit_block = func(blid crypto.Hash) (emission.Report, error) { // a failed audit may carry partial flows
		rep, err := fake(blid)
		if err != nil {
			rep.Fees, rep.Payees = 10, []emission.Payee{{Amount: 1, Verified: true}}
		}
		return rep, err
	}
	t.Cleanup(func() { emission_audit_block = fake })
	f.topo = 1001
	a.step()
	r := a.snapshot()
	if r.FeesRedistributed != 160 || r.Payees != 32 {
		t.Fatalf("an errored audit added flows: %+v", r)
	}
	delete(f.fail, nb)
	a.step()
	if r = a.snapshot(); r.FeesRedistributed != 170 || r.Payees != 34 || r.PayeesVerified != 17 || r.Reorgs != 0 {
		t.Fatalf("retry after error: fees %d payees %d verified %d reorgs %d", r.FeesRedistributed, r.Payees, r.PayeesVerified, r.Reorgs)
	}
	a.step()
	if r = a.snapshot(); r.FeesRedistributed != 170 || r.Payees != 34 {
		t.Fatalf("an audited block was counted twice: %+v", r)
	}
}
