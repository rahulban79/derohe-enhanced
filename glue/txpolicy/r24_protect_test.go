// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package txpolicy

// r24 (verify-txpool): txs of templates handed to miners are never evicted (SetProtectedSource).

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

func TestR24ProtectedTxsNeverEvicted(t *testing.T) {
	f := new_fake_pool()
	hs := fill(f, 10, 3000, func(i int) uint64 { return 80 + uint64(i) }) // rates 80..89 per 3000 B, cap full
	attach_test(t, f, 30_000)
	prot := map[crypto.Hash]bool{hs[0]: true, hs[1]: true} // the two lowest payers are in a mining job
	SetProtectedSource(func() map[crypto.Hash]bool { return prot })
	t.Cleanup(func() { SetProtectedSource(nil) })

	// entry fee skips the protected: the lowest evictable pays 82, so 83 per 3000 B is the threshold
	if need := FeeToEnter(3000); need != 83 {
		t.Fatalf("FeeToEnter(3000) = %d, want 83 (the protected 80 and 81 are not victims)", need)
	}
	tx, raw := forged(82, 1, 3000) // beats the protected 80/81 but ties the lowest evictable: refused
	if err := Admit(raw, tx, func(*transaction.Transaction) error { return nil }); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("fee 82: %v, want ErrPoolFull", err)
	}
	tx, raw = forged(200, 2, 3000)
	if err := Admit(raw, tx, func(tx *transaction.Transaction) error { f.put(forged_txid(tx), tx, 3000); return nil }); err != nil {
		t.Fatalf("better tx refused: %v", err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != hs[2] {
		t.Fatalf("evicted %v, want only the lowest unprotected %v", f.deleted, hs[2])
	}
	for _, h := range hs[:2] {
		if f.Mempool_Get_TX(h) == nil {
			t.Fatalf("a template tx was evicted")
		}
	}
	// everything lower is protected: nothing can be evicted, so even a high fee is refused before verification
	all := map[crypto.Hash]bool{}
	for _, h := range f.Mempool_List_TX_SortedInfo() {
		all[h.Hash] = true
	}
	prot = all
	p.Lock()
	p.sum_at = p.sum_at.Add(-SUMMARY_TTL * 2)
	p.Unlock()
	tx, raw = forged(10_000, 3, 3000)
	if err := Admit(raw, tx, func(*transaction.Transaction) error { t.Fatalf("verified"); return nil }); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("all protected: %v, want ErrPoolFull", err)
	}
}

func TestR24DerodSetsProtectedSource(t *testing.T) {
	src, err := os.ReadFile("../../cmd/derod/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\ttxpolicy.SetProtectedSource(derodrpc.TemplateTxs)\n") {
		t.Fatalf("cmd/derod/main.go no longer protects the txs of mining templates from eviction")
	}
}
