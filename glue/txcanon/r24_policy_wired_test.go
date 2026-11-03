// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txcanon

// r24: Admit (the single admission entry point of SendRawTransaction and the p2p relay) runs glue/txpolicy.

import (
	"errors"
	"testing"

	"github.com/deroproject/derohe/blockchain/mempool"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/glue/txpolicy"
	"github.com/deroproject/derohe/transaction"
)

type r24_empty_pool struct{}

func (r24_empty_pool) Mempool_List_TX_SortedInfo() []mempool.TX_Sorting_struct { return nil }
func (r24_empty_pool) Mempool_Get_TX(crypto.Hash) *transaction.Transaction     { return nil }
func (r24_empty_pool) Mempool_Delete_TX(crypto.Hash) *transaction.Transaction  { return nil }

func TestR24AdmitRunsTxpolicy(t *testing.T) {
	raw := (&synth{}).bytes()
	tx := decoded(t, raw)
	if tx.IsRegistration() {
		t.Fatalf("synthetic tx must be a transfer for this test")
	}
	txpolicy.Attach(r24_empty_pool{}, 0)
	defer txpolicy.Detach()
	calls := 0
	bad := errors.New("Incoming TX ab could not be verified, err transaction statement 0 verification failed")
	for i := 0; i < 3; i++ {
		if err := Admit(raw, tx, func(*transaction.Transaction) error { calls++; return bad }); err == nil {
			t.Fatalf("invalid tx admitted")
		}
	}
	if calls != 1 {
		t.Fatalf("txcanon.Admit verified known-invalid bytes %d times: the r24 policy is not wired", calls)
	}
}
