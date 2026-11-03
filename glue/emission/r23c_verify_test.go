package emission

// r23c (verifier): counter-tests of the per-account check

import (
	"testing"

	"github.com/deroproject/derohe/transaction"
)

// an account in two rings of one block that is also a payee: must be exact, no alert
func TestR23cPerAccountAccountInTwoRingsAndPayee(t *testing.T) {
	for i := 0; i < 5; i++ {
		w := newWorld(t)
		c := w.child("v-two")
		c.transfer("t1", transaction.NORMAL, []acct{w.B, w.M1}, 90, 0, nil)
		c.transfer("t2", transaction.NORMAL, []acct{w.M1, w.C}, 70, 0, nil)
		c.transfer("t3", transaction.NORMAL, []acct{w.B, w.M2}, 50, 0, nil)
		c.coinbase(0)
		c.commit()
		r := c.audit(mainnet)
		wantVerdict(t, r, VerdictOK, "")
		wantNoAlerts(t, r)
		if r.PerAccount != "exact" || r.AccountsExact != r.Changed+r.Inserted {
			t.Fatalf("per_account %q exact %d changed %d inserted %d", r.PerAccount, r.AccountsExact, r.Changed, r.Inserted)
		}
		for _, p := range r.Payees {
			if !p.Explained {
				t.Fatalf("payee not explained %+v", p)
			}
		}
	}
}
