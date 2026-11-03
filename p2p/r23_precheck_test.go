// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

import (
	"errors"
	"testing"

	"github.com/deroproject/derohe/glue/txprecheck"
	"github.com/deroproject/derohe/transaction"
)

// relay_admit must refuse a transfer whose structure consensus refuses before the pool (or txcanon) sees it (r23)
func TestRelayAdmitPrechecksStructure(t *testing.T) {
	for i := 0; i < 3; i++ {
		var tx transaction.Transaction
		tx.Version, tx.TransactionType = 1, transaction.NORMAL // no payload: transaction_verify.go:273 refuses it
		added := 0
		err := relay_admit([]byte{1}, func(*transaction.Transaction) error { added++; return nil })(&tx)
		if !errors.Is(err, txprecheck.ErrStructure) || added != 0 {
			t.Fatalf("structurally invalid relayed tx: err %v, added %d", err, added)
		}
	}
}

// r23 merge: a relayed precheck refusal is scored against the peer like the verification failure it replaces (before
// txprecheck these txs failed Verify_Transaction_NonCoinbase and were penalised as invalid_tx).
func TestRelayPrecheckRefusalIsScored(t *testing.T) {
	var tx transaction.Transaction
	tx.Version, tx.TransactionType = 1, transaction.NORMAL
	err := relay_admit([]byte{1}, func(*transaction.Transaction) error { return nil })(&tx)
	if !errors.Is(err, txprecheck.ErrStructure) {
		t.Fatalf("premise: precheck refusal expected, got %v", err)
	}
	if !is_tx_verification_failure(err) {
		t.Fatalf("relayed precheck refusal is not scored: %v", err)
	}
	if is_tx_verification_failure(errors.New("tx already in pool")) {
		t.Fatal("a timing-dependent rejection must stay unscored")
	}
}
