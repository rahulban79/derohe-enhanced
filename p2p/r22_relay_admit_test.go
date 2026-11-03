// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package p2p

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/glue/txcanon"
	"github.com/deroproject/derohe/transaction"
)

// relay_admit must run the txcanon round-trip policy before the pool sees the tx (r22)
func TestRelayAdmitRefusesUnserializable(t *testing.T) {
	var tx transaction.Transaction
	tx.Version = 1
	tx.TransactionType = transaction.TransactionType(99) // Serialize panics on it
	added := 0
	err := relay_admit([]byte{1}, func(*transaction.Transaction) error { added++; return nil })(&tx)
	if !errors.Is(err, txcanon.ErrNotRoundTrip) || added != 0 {
		t.Fatalf("err=%v added=%d: the pool was reached without the round-trip check", err, added)
	}
	if score := (&Connection{}).score_pool_rejection(err); score {
		t.Fatal("a round-trip refusal must not be scored against the peer")
	}
}

// the relayed-tx admission in chain_sync.go must go through relay_admit
func TestRelayAdmitWired(t *testing.T) {
	src, err := os.ReadFile("chain_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "admit_relayed_tx(response.Txs[i], &tx, relay_admit(response.Txs[i], chain.Add_TX_To_Pool))") {
		t.Fatal("relayed transactions must be admitted through relay_admit")
	}
}
