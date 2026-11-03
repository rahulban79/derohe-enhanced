package rpc

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/emission"
)

func paid_fake(t *testing.T, topo int64) (*emission_fake, *emission_auditor) {
	f, a := install_emission_fake(t, topo)
	inner := emission_audit_block
	emission_audit_block = func(b crypto.Hash) (emission.Report, error) {
		r, e := inner(b)
		r.Paid = r.BaseReward + r.Fees
		return r, e
	}
	return f, a
}

// r23c (verifier): after a segment restart (catch-up gap or deep rewind), issued_emission must restart with observed_emission
func TestR23cIssuedRestartsAfterDeepRewind(t *testing.T) {
	f, a := paid_fake(t, 100)
	a.step()
	for f.topo = 101; f.topo <= 4900; f.topo++ {
		a.step()
	}
	f.topo = 4900 - EMISSION_WINDOW_KEEP - 100
	for t2 := f.topo + 1; t2 <= 4900; t2++ {
		f.set(t2, "b")
	}
	a.step()
	for f.topo = 4900 - EMISSION_WINDOW_KEEP - 100 + 1; f.topo <= 4900; f.topo++ {
		a.step()
	}
	r := a.snapshot()
	t.Logf("deep: observed %d issued %d issued_matches %v consistent %v deep %d", r.ObservedEmission, r.IssuedEmission, r.IssuedMatchesFormula, r.EmissionConsistent, r.DeepRewinds)
	if !r.IssuedMatchesFormula {
		t.Errorf("issued_matches_formula false on an honest chain after a deep rewind")
	}
}

func TestR23cIssuedRestartsAfterCatchupGap(t *testing.T) {
	f, a := paid_fake(t, 100)
	a.step()
	if r := a.snapshot(); !r.IssuedMatchesFormula {
		t.Fatalf("fake broken: %d %d", r.ObservedEmission, r.IssuedEmission)
	}
	for f.topo = 101; f.topo <= 200; f.topo++ {
		a.step()
	}
	f.topo = 200 + EMISSION_CATCHUP_MAX + 50
	a.step()
	r := a.snapshot()
	t.Logf("gap: observed %d issued %d issued_matches %v consistent %v gaps %d", r.ObservedEmission, r.IssuedEmission, r.IssuedMatchesFormula, r.EmissionConsistent, r.Gaps)
	if !r.IssuedMatchesFormula {
		t.Errorf("issued_matches_formula false on an honest chain after a catch-up gap")
	}
}
